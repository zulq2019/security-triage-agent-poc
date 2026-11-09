namespace SecAgent.Connectors.Secrets;

/// <summary>One secret store, addressed by the scheme of a <see cref="SecretRef"/> ("env", "kv", "gh-cli", "memory").</summary>
public interface ISecretSource
{
    string Scheme { get; }
    /// <summary>The value, or null when the store has no such secret.</summary>
    ValueTask<string?> TryGetAsync(string name, CancellationToken ct);
}

/// <summary>Local development: the secret lives in an environment variable ("env:GITHUB_TOKEN").</summary>
public sealed class EnvironmentSecretSource : ISecretSource
{
    public string Scheme => "env";
    public ValueTask<string?> TryGetAsync(string name, CancellationToken ct) =>
        ValueTask.FromResult(Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null);
}

/// <summary>Routes a secret reference to the store named by its scheme. Connectors get this through DI and ask for a secret at call time;
/// nothing above the connector (agents, pipeline, UI) ever sees the value. Errors name the reference, never the value.</summary>
public sealed class CompositeSecretProvider(IEnumerable<ISecretSource> sources) : ISecretProvider
{
    readonly Dictionary<string, ISecretSource> _sources = sources.GroupBy(s => s.Scheme, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.Last(), StringComparer.OrdinalIgnoreCase);

    public async ValueTask<string> GetSecretAsync(SecretRef secret, CancellationToken ct)
    {
        if (!secret.IsValid) throw new ConnectorConfigurationException($"Invalid secret reference '{secret}' (expected scheme:name)");
        if (!_sources.TryGetValue(secret.Scheme, out var source)) throw new ConnectorConfigurationException($"No secret source for scheme '{secret.Scheme}' (reference '{secret}')");
        return await source.TryGetAsync(secret.Name, ct) ?? throw new ConnectorConfigurationException($"Secret '{secret}' is not set");
    }
}
