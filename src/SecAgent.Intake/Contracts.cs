using SecAgent.Core;

namespace SecAgent.Intake;

/// <summary>Payload formats the intake accepts. The format is part of the URL (POST /api/intake/{format}) and of the signed string.</summary>
public static class IntakeFormats
{
    public const string Sarif = "sarif";                       // SARIF 2.1.0 (any producer; Black Duck SCA / Polaris SARIF tested)
    public const string BlackDuckRapid = "blackduck-rapid";    // Black Duck Detect rapid / stateless scan JSON (*_BlackDuck_DeveloperMode_Result.json)
    public static readonly string[] All = [Sarif, BlackDuckRapid];
}

/// <summary>Who/what the scan result is about. Comes from signed request headers (webhook) or blob metadata (Blob drop).</summary>
public sealed record IntakeMetadata
{
    public required string Format { get; init; }
    public required string Repo { get; init; }             // owner/name
    public int? PrNumber { get; init; }                    // null = backlog / branch scan (e.g. nightly on main)
    public string? Ref { get; init; }                      // branch the scan ran on (PR head ref or main)
    public required string HeadSha { get; init; }          // the exact commit that was scanned
    public required string Scanner { get; init; }          // canonical source_scanner, e.g. "blackduck"
    public required string RunId { get; init; }            // producer run id, e.g. GitHub "<run_id>-<run_attempt>"
    public string Mode => PrNumber is null ? "backlog" : "pr";
    public string Branch => Ref is { Length: > 0 } r ? r : PrNumber is { } n ? $"pr/{n}" : "unknown";

    /// <summary>Idempotency key: repo + head SHA + scanner + producer run (+ format, so SARIF and rapid JSON of one run can both be sent).</summary>
    public string IdempotencyKey => Hashing.Sha256($"intake|{Repo.ToLowerInvariant()}|{HeadSha.ToLowerInvariant()}|{Scanner}|{RunId}|{Format}");
}

public sealed record ParseOutcome(List<Finding> Findings, string ToolName, string ToolVersion, List<string> Notes);

/// <summary>Maps one scanner payload format to canonical findings. Implementations validate structure and throw <see cref="IntakeRejectedException"/> on bad input.</summary>
public interface IFindingParser
{
    string Format { get; }
    ParseOutcome Parse(ReadOnlyMemory<byte> payload, IntakeMetadata meta);
    /// <summary>Returns the payload as it may be stored at rest (secret values removed). Default implementations mask known secret patterns.</summary>
    byte[] Redact(ReadOnlyMemory<byte> payload, ParseOutcome parsed);
}

public sealed record RawRef(string Uri, string Hash);

/// <summary>Write-once store for the raw scanner payloads (local folder now; Azure Blob container "raw" in the cloud).</summary>
public interface IRawFindingStore
{
    RawRef Put(string path, byte[] content);
    byte[] Get(string uri);
}

/// <summary>One accepted intake (one producer run, one payload).</summary>
public sealed class IntakeRecord
{
    public string IntakeId { get; set; } = Guid.NewGuid().ToString("N");
    public string Key { get; set; } = "";
    public string BodySha256 { get; set; } = "";
    public string Status { get; set; } = IntakeStatus.Claimed;
    public IntakeMetadata? Meta { get; set; }
    public string? RawUri { get; set; }
    public string? RawHash { get; set; }
    public string? CanonicalUri { get; set; }
    public int Findings { get; set; }
    public string? ScannerVersion { get; set; }
    public string? RunTicket { get; set; }
    public Guid? RunId { get; set; }
    public string? Detail { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

public static class IntakeStatus
{
    public const string Claimed = "claimed", Queued = "queued", RunStarted = "run_started", BacklogPending = "backlog_pending", StartFailed = "start_failed";
}

/// <summary>Idempotency ledger (local JSON files now; a SQL table or Table Storage in the cloud). TryClaim is atomic per key.</summary>
public interface IIntakeLedger
{
    bool TryClaim(IntakeRecord record, out IntakeRecord existing);
    void Update(IntakeRecord record);
    IntakeRecord? Get(string key);
    IEnumerable<IntakeRecord> All();
}

/// <summary>What the intake asks the pipeline to do after a payload is accepted.</summary>
public sealed record IntakeRunRequest(string IntakeId, string IdempotencyKey, string Repo, int? PrNumber, string? Ref, string HeadSha, string Scanner, string Mode, int Findings);

public sealed record RunTicket(string Ticket, bool Enqueued);

/// <summary>Starts (or queues) a pipeline run for an accepted intake. Local: in-process queue + dispatcher → RunService.StartAsync (same path as POST /api/runs).
/// Cloud: an IMessageQueue backed by Azure Service Bus (MessageId = idempotency key gives broker-side duplicate detection).</summary>
public interface IRunStarter
{
    Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct);
}

/// <summary>Authenticates a webhook request before anything is parsed or stored.</summary>
public interface IIntakeAuthenticator
{
    /// <summary>Runs before metadata validation, on the raw header values exactly as sent, so unauthenticated callers only ever see 401.</summary>
    IntakeAuthResult Authenticate(string format, IReadOnlyDictionary<string, string> headers, ReadOnlySpan<byte> body, DateTimeOffset now);
}

public sealed record IntakeAuthResult(bool Ok, string? Error = null)
{
    public static readonly IntakeAuthResult Success = new(true);
    public static IntakeAuthResult Fail(string error) => new(false, error);
}

/// <summary>Input rejected (bad schema, oversize, unknown format …). StatusCode is what the HTTP endpoint returns.</summary>
public sealed class IntakeRejectedException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}
