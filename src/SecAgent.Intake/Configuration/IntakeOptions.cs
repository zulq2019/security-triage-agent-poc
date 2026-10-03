using SecAgent.Abstractions.Intake;

namespace SecAgent.Intake.Configuration;

/// <summary>Intake configuration, bound from the "Intake" configuration section (Options pattern: inject <c>IOptions&lt;IntakeOptions&gt;</c>).
/// Validated on start by <see cref="IntakeOptionsValidator"/>. The HMAC secret itself is never configuration: only the NAME of the
/// environment variable that holds it (in Azure: an App Service Key Vault reference), read through <see cref="IIntakeSecretProvider"/>.</summary>
public sealed class IntakeOptions
{
    public const string SectionName = "Intake";

    public bool Enabled { get; set; } = true;
    /// <summary>Env var holding the shared HMAC secret (same value as the GitHub secret INTAKE_HMAC_SECRET). Unset = every request gets 503.</summary>
    public string HmacSecretEnv { get; set; } = "SECAGENT_INTAKE_HMAC_SECRET";
    /// <summary>Signed timestamp must be within this many seconds of server time (replay window; the idempotency key covers replays inside it).</summary>
    public int TimestampToleranceSeconds { get; set; } = 300;
    public long MaxBodyBytes { get; set; } = 25L * 1024 * 1024;
    public int MaxResults { get; set; } = 20000;
    public int MaxJsonDepth { get; set; } = 64;
    /// <summary>A claimed-but-unfinished idempotency key older than this is resumed by the next delivery (crash recovery).</summary>
    public int ClaimLeaseSeconds { get; set; } = 120;
    /// <summary>Accepted source_scanner values (must also be in rules/schema/finding.schema.json).</summary>
    public List<string> AllowedScanners { get; set; } = ["blackduck"];
    /// <summary>Repos allowed to push (owner/name, "*" suffix wildcard: "my-org/*"). Empty = any repo.</summary>
    public List<string> AllowedRepos { get; set; } = [];
    /// <summary>Format used for a dropped blob that has no "format" metadata and whose name no parser recognises.</summary>
    public string DefaultBlobFormat { get; set; } = IntakeFormats.Sarif;

    /// <summary>Data root for the local adapters (the host sets it; the dashboard uses .data). Folders below default from it.</summary>
    public string StorageRoot { get; set; } = "";
    /// <summary>Local write-once blob root (default {StorageRoot}/blob, the same root the pipeline uses, so blob:// URIs resolve the same).</summary>
    public string RawStoreRoot { get; set; } = "";
    /// <summary>Local idempotency ledger folder (default {StorageRoot}/intake/ledger).</summary>
    public string LedgerFolder { get; set; } = "";
    /// <summary>Local Blob-drop watcher for dev (stands in for Blob created → Event Grid → handler).</summary>
    public bool DropWatcherEnabled { get; set; }
    /// <summary>Default {StorageRoot}/intake/drop.</summary>
    public string DropFolder { get; set; } = "";
    /// <summary>Run the queue → pipeline dispatcher in this process (off for a host that only accepts and enqueues).</summary>
    public bool DispatcherEnabled { get; set; } = true;

    /// <summary>Which adapter implements each port (see <see cref="IntakeAdapterKeys"/>).</summary>
    public IntakeAdapterOptions Adapters { get; set; } = new();

    public bool RepoAllowed(string repo) => AllowedRepos.Count == 0 || AllowedRepos.Any(p =>
        p.EndsWith('*') ? repo.StartsWith(p[..^1], StringComparison.OrdinalIgnoreCase) : string.Equals(p, repo, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Adapter selection by configuration. "local" adapters ship with SecAgent.Intake; "azure-blob" / "azure-servicebus" are registered
/// by services.AddSecAgentIntakeAzure(...) from SecAgent.Intake.Azure.</summary>
public sealed class IntakeAdapterOptions
{
    public string RawStore { get; set; } = IntakeAdapterKeys.Local;
    public string Ledger { get; set; } = IntakeAdapterKeys.Local;
    public string RunQueue { get; set; } = IntakeAdapterKeys.Local;
    public string BlobReader { get; set; } = IntakeAdapterKeys.Local;
}
