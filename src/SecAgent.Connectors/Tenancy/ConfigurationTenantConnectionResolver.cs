using Microsoft.Extensions.Options;
using SecAgent.Connectors.Configuration;

namespace SecAgent.Connectors.Tenancy;

/// <summary>Resolves tenants and their connections from <see cref="ConnectorOptions"/>. Single-tenant: every request maps to the one
/// constant tenant. Multi-tenant: a repository must belong to exactly one tenant, and an unknown tenant is an error (never a fallback).</summary>
public sealed class ConfigurationTenantConnectionResolver(IOptionsMonitor<ConnectorOptions> options) : ITenantConnectionResolver, ITenantResolver
{
    public string ForRepository(string repo)
    {
        var o = options.CurrentValue;
        if (o.DeploymentModel == DeploymentModel.SingleTenant) return o.DefaultTenant;
        var matches = o.Tenants.Where(t => t.Value.Repositories.Any(p => RepositoryPattern.Matches(p, repo))).Select(t => t.Key).ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new UnknownTenantException($"No tenant owns repository '{repo}'"),
            _ => throw new UnknownTenantException($"Repository '{repo}' matches more than one tenant ({string.Join(", ", matches)})"),
        };
    }

    public ConnectionSettings? Resolve(string tenantId, ConnectorKind kind)
    {
        var o = options.CurrentValue;
        string tenant;
        TenantConnectionsOptions? t;
        if (o.DeploymentModel == DeploymentModel.SingleTenant)
        {
            tenant = o.DefaultTenant;
            t = o.Tenants.GetValueOrDefault(tenant);
        }
        else
        {
            if (string.IsNullOrWhiteSpace(tenantId) || !o.Tenants.TryGetValue(tenantId, out t)) throw new UnknownTenantException($"Unknown tenant '{tenantId}'");
            tenant = o.Tenants.Keys.First(k => k.Equals(tenantId, StringComparison.OrdinalIgnoreCase));
        }
        var c = t?.For(kind) ?? o.Defaults.For(kind);
        if (c == null || string.IsNullOrWhiteSpace(c.Provider) || c.Provider.Trim().Equals("none", StringComparison.OrdinalIgnoreCase)) return null;
        return new ConnectionSettings(tenant, kind, c.Provider.Trim().ToLowerInvariant(), string.IsNullOrWhiteSpace(c.BaseUrl) ? null : c.BaseUrl.Trim(),
            string.IsNullOrWhiteSpace(c.Secret) ? null : new SecretRef(c.Secret.Trim()),
            new Dictionary<string, string>(c.Settings, StringComparer.OrdinalIgnoreCase));
    }
}

public static class RepositoryPattern
{
    /// <summary>"org/*" matches every repo of org; "org/repo" matches exactly; "*" matches all. Case-insensitive (GitHub names are).</summary>
    public static bool Matches(string pattern, string repo)
    {
        pattern = pattern.Trim();
        if (pattern == "*") return true;
        if (pattern.EndsWith("/*", StringComparison.Ordinal)) return repo.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase);
        return string.Equals(pattern, repo, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when some repository could match both patterns.</summary>
    public static bool Overlaps(string a, string b)
    {
        static string? Org(string p) => p.EndsWith("/*", StringComparison.Ordinal) ? p[..^2] : null;
        if (a == "*" || b == "*" || string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
        var (oa, ob) = (Org(a), Org(b));
        if (oa != null && ob != null) return string.Equals(oa, ob, StringComparison.OrdinalIgnoreCase);
        return oa != null ? Matches(a, b) : ob != null && Matches(b, a);
    }
}
