using System.Text.Json;

namespace SecAgent.Intake;

/// <summary>Intake configuration ("Intake" section of src/SecAgent.Dashboard/appsettings.json, overridable in appsettings.Local.json and by env vars).
/// The HMAC secret itself is never in a file: only the NAME of the environment variable that holds it (in Azure: an App Service Key Vault reference).</summary>
public sealed class IntakeOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Env var holding the shared HMAC secret (same value as the GitHub secret INTAKE_HMAC_SECRET). Unset = intake refuses every request (503).</summary>
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
    /// <summary>Local Blob-drop watcher for dev (stands in for Blob created → Event Grid → handler).</summary>
    public bool DropWatcherEnabled { get; set; }
    public string DropFolder { get; set; } = "";
    public string Source { get; set; } = "built-in defaults";

    public string? HmacSecret => Environment.GetEnvironmentVariable(HmacSecretEnv) is { Length: > 0 } s ? s : null;

    public bool RepoAllowed(string repo) => AllowedRepos.Count == 0 || AllowedRepos.Any(p =>
        p.EndsWith('*') ? repo.StartsWith(p[..^1], StringComparison.OrdinalIgnoreCase) : string.Equals(p, repo, StringComparison.OrdinalIgnoreCase));

    static readonly JsonSerializerOptions Opts = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>appsettings.json → appsettings.Local.json → env (SECAGENT_INTAKE_ENABLED, SECAGENT_INTAKE_DROP_WATCHER).</summary>
    public static IntakeOptions Load(string repoRoot, string dataRoot)
    {
        var o = new IntakeOptions();
        var sources = new List<string>();
        foreach (var name in new[] { "appsettings.json", "appsettings.Local.json" })
        {
            var file = Path.Combine(repoRoot, "src", "SecAgent.Dashboard", name);
            if (!File.Exists(file)) continue;
            using var doc = JsonDocument.Parse(File.ReadAllText(file), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!doc.RootElement.TryGetProperty("Intake", out var sec)) continue;
            sources.Add(name);
            foreach (var p in sec.EnumerateObject())
            {
                var prop = typeof(IntakeOptions).GetProperties().FirstOrDefault(x => x.Name.Equals(p.Name, StringComparison.OrdinalIgnoreCase) && x.CanWrite && x.Name != nameof(Source));
                if (prop != null) prop.SetValue(o, p.Value.Deserialize(prop.PropertyType, Opts));
            }
        }
        string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } x ? x : null;
        if (Env("SECAGENT_INTAKE_ENABLED") is { } en) { o.Enabled = en is "1" or "true"; sources.Add("SECAGENT_INTAKE_ENABLED"); }
        if (Env("SECAGENT_INTAKE_DROP_WATCHER") is { } dw) { o.DropWatcherEnabled = dw is "1" or "true"; sources.Add("SECAGENT_INTAKE_DROP_WATCHER"); }
        if (string.IsNullOrEmpty(o.DropFolder)) o.DropFolder = Path.Combine(dataRoot, "intake", "drop");
        o.Source = sources.Count > 0 ? string.Join(" + ", sources) : "built-in defaults";
        return o;
    }
}
