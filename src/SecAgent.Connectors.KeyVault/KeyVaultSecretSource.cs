using System.Collections.Concurrent;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Connectors.Secrets;

namespace SecAgent.Connectors.KeyVault;

public sealed class KeyVaultSecretOptions
{
    /// <summary>Vault used by short references ("kv:github-token"). Multi-tenant deployments use full URLs per tenant instead.</summary>
    public string? DefaultVaultUri { get; set; }
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>"kv" secret scheme. "kv:https://kv-secagent-tenant-a.vault.azure.net/secrets/github-token" (per-tenant vault) or "kv:github-token"
/// (default vault). Values are cached briefly in memory and never logged; the managed identity needs "Key Vault Secrets User" only.</summary>
public sealed class KeyVaultSecretSource(IOptions<KeyVaultSecretOptions> options, TimeProvider time, TokenCredential? credential = null) : ISecretSource
{
    readonly TokenCredential _credential = credential ?? new DefaultAzureCredential();
    readonly ConcurrentDictionary<string, SecretClient> _clients = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, (string Value, DateTimeOffset Until)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public string Scheme => "kv";

    public async ValueTask<string?> TryGetAsync(string name, CancellationToken ct)
    {
        if (_cache.TryGetValue(name, out var hit) && hit.Until > time.GetUtcNow()) return hit.Value;
        var (vault, secretName) = Parse(name);
        var client = _clients.GetOrAdd(vault.ToString(), _ => new SecretClient(vault, _credential));
        try
        {
            var value = (await client.GetSecretAsync(secretName, cancellationToken: ct)).Value.Value;
            _cache[name] = (value, time.GetUtcNow() + options.Value.CacheDuration);
            return value;
        }
        catch (RequestFailedException e) when (e.Status == 404) { return null; }
        catch (RequestFailedException e) { throw new ConnectorException($"Key Vault {vault.Host}: reading secret '{secretName}' failed ({e.Status})", e.Status is 429 or >= 500, null, null, e); }
    }

    (Uri Vault, string Name) Parse(string reference)
    {
        if (Uri.TryCreate(reference, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps)
        {
            var parts = u.AbsolutePath.Trim('/').Split('/');
            if (parts.Length >= 2 && parts[0] == "secrets") return (new Uri($"https://{u.Host}/"), parts[1]);
            throw new ConnectorConfigurationException($"Key Vault reference '{reference}' must look like https://<vault>.vault.azure.net/secrets/<name>");
        }
        var vault = options.Value.DefaultVaultUri ?? throw new ConnectorConfigurationException($"Secret 'kv:{reference}' needs Connectors:KeyVault:DefaultVaultUri or a full vault URL");
        return (new Uri(vault), reference);
    }
}

public static class KeyVaultSecretRegistration
{
    public static ConnectorsBuilder AddKeyVaultSecrets(this ConnectorsBuilder builder, IConfiguration configuration)
    {
        builder.Services.Configure<KeyVaultSecretOptions>(configuration.GetSection("Connectors:KeyVault"));
        builder.Services.AddSingleton<KeyVaultSecretSource>(sp => new KeyVaultSecretSource(sp.GetRequiredService<IOptions<KeyVaultSecretOptions>>(), sp.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<ISecretSource>(sp => sp.GetRequiredService<KeyVaultSecretSource>());
        return builder;
    }
}
