using SecAgent.Core;

namespace SecAgent.Abstractions.Intake;

// Ports of the intake (hexagonal architecture): the application core in SecAgent.Intake depends only on these; adapters implement them
// (local folder / file ledger / in-process queue in SecAgent.Intake, Azure Blob / Service Bus in SecAgent.Intake.Azure).

public sealed record ParseOutcome(List<Finding> Findings, string ToolName, string ToolVersion, List<string> Notes);

/// <summary>Strategy + Adapter: maps one scanner payload format to canonical findings. Implementations validate structure and throw
/// <see cref="IntakeRejectedException"/> on bad input. Add a format by registering another implementation (no existing code changes).</summary>
public interface IFindingParser
{
    /// <summary>URL segment / blob metadata value that selects this parser (lower case).</summary>
    string Format { get; }
    /// <summary>File-name suffix for the raw copy at rest, e.g. "sarif.json".</summary>
    string RawFileExtension { get; }
    ParseOutcome Parse(ReadOnlyMemory<byte> payload, IntakeMetadata meta);
    /// <summary>Returns the payload as it may be stored at rest (secret values removed).</summary>
    byte[] Redact(ReadOnlyMemory<byte> payload, ParseOutcome parsed);
}

/// <summary>Optional, for parsers whose files are recognisable by name (used when a dropped blob has no "format" metadata).</summary>
public interface IFileNameFormatHint
{
    bool Recognises(string fileName);
}

public sealed record RawRef(string Uri, string Hash);

/// <summary>Write-once store for raw scanner payloads and their canonical findings (local folder, or an Azure Blob container).
/// URIs are blob://raw/… in both, so evidence references do not depend on the adapter.</summary>
public interface IRawFindingStore
{
    RawRef Put(string path, byte[] content);
    byte[] Get(string uri);
}

/// <summary>Outcome of a fenced ledger write (<see cref="IIntakeLedger.TryUpdate"/>).</summary>
public enum LedgerWriteResult
{
    /// <summary>The stored record still carried the expected claim token; it was replaced.</summary>
    Updated,
    /// <summary>The stored record carries another claim token: another delivery took the claim over (or it was terminalized). Nothing was
    /// written; the caller no longer owns the record and must stop without further side effects.</summary>
    LostOwnership,
    /// <summary>No record under that key. Nothing was written.</summary>
    NotFound,
}

/// <summary>Idempotency ledger writes (local JSON files; a SQL table or Table Storage in the cloud). TryClaim is atomic per key.
/// <para>Fencing: after the claim, every write is a compare-and-set on the claim token (<see cref="TryUpdate"/>), so a delivery whose
/// claim was taken over after the lease cannot overwrite the new owner's state. There is deliberately no unconditional update.</para></summary>
public interface IIntakeLedger
{
    bool TryClaim(IntakeRecord record, out IntakeRecord existing);
    /// <summary>Compare-and-set: replaces the stored record with <paramref name="record"/> only if the stored record still carries
    /// <paramref name="expectedClaimToken"/> (an ETag / rowversion check in a cloud adapter), atomically with <see cref="TryClaim"/> and
    /// other TryUpdate calls. A takeover passes the old token and a record with a new one; the claim holder passes its own token.</summary>
    LedgerWriteResult TryUpdate(IntakeRecord record, string expectedClaimToken);
    IntakeRecord? Get(string key);
}

/// <summary>Read side of the ledger (listing endpoint, external-finding lookup). Segregated from the write side.</summary>
public interface IIntakeRecordQuery
{
    IEnumerable<IntakeRecord> All();
}

/// <summary>Shared naming convention for the run queue, used by every adapter and mirrored by the infrastructure (infra/agents.bicep
/// creates <c>runs</c> with sessions on; deploy/agents.json lists it for the intake, agent-api and orchestrator).
/// <para>Session = the run target (repository + PR, or repository + ref), so requests for one PR are handed out in order, one at a
/// time. The same key is used whether or not the broker enforces sessions (sessionless deployments simply ignore it).</para></summary>
public static class RunQueueConvention
{
    /// <summary>Queue name for run requests, locally and in Service Bus.</summary>
    public const string QueueName = "runs";
    /// <summary>Service Bus limit for SessionId.</summary>
    public const int MaxSessionIdLength = 128;

    /// <summary>"owner/repo#12" for a PR, "owner/repo@refs/heads/main" for a ref; hashed when longer than the broker allows.</summary>
    public static string SessionId(IntakeRunRequest request)
    {
        var key = request.PrNumber is int pr ? $"{request.Repo}#{pr}" : $"{request.Repo}@{request.Ref ?? request.HeadSha}";
        return key.Length <= MaxSessionIdLength ? key : "sha256:" + Hashing.Sha256(key)[..32];
    }
}

/// <summary>Producer side of the run queue: asks for a pipeline run for an accepted intake.</summary>
public interface IRunStarter
{
    Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct);
}

/// <summary>One received run request plus the adapter's own message handle (needed to complete / abandon it).</summary>
public sealed record IntakeRunDelivery(IntakeRunRequest Request, object Handle);

/// <summary>Consumer side of the run queue (in-process queue locally, Service Bus in Azure).</summary>
public interface IIntakeRunSource
{
    /// <summary>The next run request, or null when none is available right now.</summary>
    Task<IntakeRunDelivery?> ReceiveAsync(CancellationToken ct);
    Task CompleteAsync(IntakeRunDelivery delivery, CancellationToken ct);
    /// <summary>Puts the message back for redelivery (dead-lettered after the adapter's max deliveries).</summary>
    Task AbandonAsync(IntakeRunDelivery delivery, string error, CancellationToken ct);
}

/// <summary>Authenticates a webhook request before anything is parsed or stored.</summary>
public interface IIntakeAuthenticator
{
    /// <summary>Runs before metadata validation, on the raw header values exactly as sent, so unauthenticated callers only ever see 401.</summary>
    IntakeAuthResult Authenticate(string format, IReadOnlyDictionary<string, string> headers, ReadOnlySpan<byte> body);
}

public sealed record IntakeAuthResult(bool Ok, string? Error = null)
{
    public static readonly IntakeAuthResult Success = new(true);
    public static IntakeAuthResult Fail(string error) => new(false, error);
}

/// <summary>A read request on the intake's own API (GET /api/intake): the request headers and whether the caller is on this machine
/// without a proxy in between (only used when a loopback exemption is explicitly configured).</summary>
public sealed record IntakeReadRequest(IReadOnlyDictionary<string, string> Headers, bool IsDirectLoopback);

/// <summary>Strategy: one way to authorise a read of intake records (admin token, HMAC-signed request, explicit loopback exemption).
/// The read authoriser asks every configured credential; any grant wins.</summary>
public interface IIntakeReadCredential
{
    /// <summary>Human-readable name for errors and logs, e.g. "admin token".</summary>
    string Name { get; }
    /// <summary>False when this credential is not set up on the server (e.g. no admin token configured); it is then ignored.</summary>
    bool IsConfigured { get; }
    /// <summary>Null when the request does not present this credential; otherwise the check result.</summary>
    IntakeAuthResult? Check(IntakeReadRequest request);
}

/// <summary>Where the shared HMAC secret comes from (environment variable locally; Key Vault reference / SecretClient in Azure).</summary>
public interface IIntakeSecretProvider
{
    /// <summary>The secret, or null when it is not configured (the endpoint then refuses every request).</summary>
    string? GetSecret();
}

/// <summary>A "blob created" notification, shaped like the Event Grid Microsoft.Storage.BlobCreated event data we need:
/// url, name, contentLength. Metadata comes from the blob's own metadata (repo, pr, ref, head_sha, scanner, run_id, format)
/// or, for the local drop folder, a sidecar "&lt;file&gt;.meta.json".</summary>
public sealed record BlobCreatedEvent(string Url, string Name, long ContentLength, IReadOnlyDictionary<string, string> Metadata);

/// <summary>Reads blob content (local drop folder, or Azure Blob with the app's managed identity).</summary>
public interface IBlobReader
{
    Task<byte[]> ReadAsync(BlobCreatedEvent evt, long maxBytes, CancellationToken ct);
}
