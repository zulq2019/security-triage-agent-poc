using SecAgent.Core;

namespace SecAgent.Abstractions.Intake;

/// <summary>Payload formats shipped with the intake. The format is part of the URL (POST /api/intake/{format}) and of the signed string.
/// New formats do not need a constant here: register another <see cref="IFindingParser"/>.</summary>
public static class IntakeFormats
{
    public const string Sarif = "sarif";                       // SARIF 2.1.0 (any producer; Black Duck SCA / Polaris SARIF tested)
    public const string BlackDuckRapid = "blackduck-rapid";    // Black Duck Detect rapid / stateless scan JSON (*_BlackDuck_DeveloperMode_Result.json)
}

/// <summary>Adapter keys for Intake:Adapters:* (which implementation of a port is used). Local adapters ship in SecAgent.Intake,
/// Azure adapters in SecAgent.Intake.Azure.</summary>
public static class IntakeAdapterKeys
{
    public const string Local = "local";
    public const string AzureBlob = "azure-blob";
    public const string AzureServiceBus = "azure-servicebus";
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

/// <summary>What the intake asks the pipeline to do after a payload is accepted.</summary>
public sealed record IntakeRunRequest(string IntakeId, string IdempotencyKey, string Repo, int? PrNumber, string? Ref, string HeadSha, string Scanner, string Mode, int Findings);

public sealed record RunTicket(string Ticket, bool Enqueued);

/// <summary>Input rejected (bad schema, oversize, unknown format …). StatusCode is what the HTTP endpoint returns.</summary>
public sealed class IntakeRejectedException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}
