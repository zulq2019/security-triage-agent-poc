namespace SecAgent.Connectors.Configuration;

public enum DeploymentModel
{
    /// <summary>Customer-hosted: one constant tenant owns every connection (SDD 9.7).</summary>
    SingleTenant,
    /// <summary>Wipro-hosted: one entry per customer tenant; repositories map to exactly one tenant; no cross-tenant fallback.</summary>
    MultiTenant,
}

/// <summary>The "Connectors" configuration section. Holds provider ids, URLs and secret <em>references</em> only.</summary>
public sealed class ConnectorOptions
{
    public const string SectionName = "Connectors";

    public DeploymentModel DeploymentModel { get; set; } = DeploymentModel.SingleTenant;
    /// <summary>Single-tenant: the constant tenant id. Multi-tenant: unused by the resolver (every tenant is explicit).</summary>
    public string DefaultTenant { get; set; } = "default";
    public Dictionary<string, TenantConnectionsOptions> Tenants { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Connections shared by every tenant unless a tenant overrides them. Multi-tenant: only the model provider may be shared
    /// (the Wipro model gateway); a shared GitHub / Jira / Black Duck / Teams connection would cross tenant boundaries and is rejected.</summary>
    public TenantConnectionsOptions Defaults { get; set; } = new();
    /// <summary>Multi-tenant: secret reference schemes that are tenant-scoped (Key Vault per tenant). "env" / "gh-cli" are process-wide.</summary>
    public List<string> MultiTenantSecretSchemes { get; set; } = ["kv", "memory"];
    public ConnectorResilienceOptions Resilience { get; set; } = new();
}

public sealed class TenantConnectionsOptions
{
    /// <summary>Multi-tenant: repositories owned by this tenant ("org/*", "org/repo" or "*").</summary>
    public List<string> Repositories { get; set; } = [];
    public ConnectionOptions? SourceControl { get; set; }
    public ConnectionOptions? IssueTracker { get; set; }
    public ConnectionOptions? ScannerSource { get; set; }
    public ConnectionOptions? ModelProvider { get; set; }
    public ConnectionOptions? Notifier { get; set; }

    public ConnectionOptions? For(ConnectorKind kind) => kind switch
    {
        ConnectorKind.SourceControl => SourceControl,
        ConnectorKind.IssueTracker => IssueTracker,
        ConnectorKind.ScannerSource => ScannerSource,
        ConnectorKind.ModelProvider => ModelProvider,
        ConnectorKind.Notifier => Notifier,
        _ => null,
    };

    public void Set(ConnectorKind kind, ConnectionOptions? value)
    {
        switch (kind)
        {
            case ConnectorKind.SourceControl: SourceControl = value; break;
            case ConnectorKind.IssueTracker: IssueTracker = value; break;
            case ConnectorKind.ScannerSource: ScannerSource = value; break;
            case ConnectorKind.ModelProvider: ModelProvider = value; break;
            case ConnectorKind.Notifier: Notifier = value; break;
        }
    }
}

public sealed class ConnectionOptions
{
    /// <summary>Plug-in id ("github", "jira", "blackduck", "openai-compatible", "teams", "fake") or "none".</summary>
    public string Provider { get; set; } = "";
    public string? BaseUrl { get; set; }
    /// <summary>Secret reference ("env:NAME", "kv:name", "kv:https://vault/secrets/name"). Never the secret value.</summary>
    public string? Secret { get; set; }
    public Dictionary<string, string> Settings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Retry / backoff, rate limiting, circuit breaker and timeouts. Applied per tenant and connector, either by the HTTP resilience
/// handler (REST connectors) or by the call-level decorator (SDK / process / in-memory connectors), never both.</summary>
public sealed class ConnectorResilienceOptions
{
    /// <summary>Retries apply to idempotent operations only (reads; HTTP GET/HEAD). Creating a PR or an issue is never retried blindly.</summary>
    public int MaxRetryAttempts { get; set; } = 3;
    public TimeSpan BaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);
    public bool UseJitter { get; set; } = true;
    public TimeSpan AttemptTimeout { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan TotalTimeout { get; set; } = TimeSpan.FromSeconds(120);
    /// <summary>Attempt timeout for model completions (SDK transport): local models can take minutes per call.</summary>
    public TimeSpan ModelAttemptTimeout { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>Token bucket per tenant + connector.</summary>
    public int PermitsPerSecond { get; set; } = 10;
    public int QueueLimit { get; set; } = 50;
    public double CircuitBreakerFailureRatio { get; set; } = 0.5;
    public int CircuitBreakerMinimumThroughput { get; set; } = 5;
    public TimeSpan CircuitBreakerSamplingDuration { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan CircuitBreakerBreakDuration { get; set; } = TimeSpan.FromSeconds(30);
}
