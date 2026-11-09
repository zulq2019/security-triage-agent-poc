namespace SecAgent.Connectors;

/// <summary>Reference to a secret, never the secret itself: "scheme:name", e.g. "env:GITHUB_TOKEN" (local),
/// "kv:github-token" or "kv:https://kv-secagent-tenant-a.vault.azure.net/secrets/github-token" (Key Vault).</summary>
public readonly record struct SecretRef(string Value)
{
    public string Scheme => Value.IndexOf(':') is var i and > 0 ? Value[..i].ToLowerInvariant() : "";
    public string Name => Value.IndexOf(':') is var i and > 0 ? Value[(i + 1)..] : Value;
    public bool IsValid => Scheme.Length > 0 && Name.Length > 0;
    public override string ToString() => Value;   // safe to log: it is a reference
}

/// <summary>A resolved connection of one tenant to one system: which plug-in, where, and which secret reference to use.
/// Holds no secret values (configuration validation rejects secret-looking settings).</summary>
public sealed record ConnectionSettings(string TenantId, ConnectorKind Kind, string Provider, string? BaseUrl, SecretRef? Secret,
    IReadOnlyDictionary<string, string> Settings)
{
    public string? Get(string key) => Settings.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;
    public string Require(string key) => Get(key) ?? throw new ConnectorConfigurationException($"{Kind} connection '{Provider}' for tenant '{TenantId}' needs setting '{key}'");
    public Uri RequireBaseUrl() => Uri.TryCreate(BaseUrl, UriKind.Absolute, out var u) ? u
        : throw new ConnectorConfigurationException($"{Kind} connection '{Provider}' for tenant '{TenantId}' needs an absolute BaseUrl");
    public SecretRef RequireSecret() => Secret is { IsValid: true } s ? s
        : throw new ConnectorConfigurationException($"{Kind} connection '{Provider}' for tenant '{TenantId}' needs a Secret reference (e.g. env:NAME or kv:name)");
}

/// <summary>Per-tenant connection lookup. Multi-tenant (Wipro-hosted): each tenant has its own connections and secrets, and an unknown
/// tenant never falls back to another tenant's connection. Single-tenant (customer-hosted): one constant tenant.</summary>
public interface ITenantConnectionResolver
{
    /// <summary>The tenant's connection of this kind, or null when none is configured (provider "none" or missing).</summary>
    ConnectionSettings? Resolve(string tenantId, ConnectorKind kind);
}

/// <summary>Which tenant a repository belongs to (the pipeline asks this once per run).</summary>
public interface ITenantResolver
{
    string ForRepository(string repo);
}

public interface ISecretProvider
{
    /// <summary>The secret value. Throws <see cref="ConnectorConfigurationException"/> when it cannot be resolved. Callers must never log it.</summary>
    ValueTask<string> GetSecretAsync(SecretRef secret, CancellationToken ct);
}
