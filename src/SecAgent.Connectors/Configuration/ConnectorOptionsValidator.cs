using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecAgent.Connectors.Secrets;

namespace SecAgent.Connectors.Configuration;

/// <summary>Fails start-up on a connection that could not work or would be unsafe: unknown provider, missing / unknown secret scheme,
/// a secret value pasted into Settings, cross-tenant sharing in multi-tenant mode, overlapping repository ownership.</summary>
public sealed partial class ConnectorOptionsValidator(IConnectorCatalog catalog, IEnumerable<ISecretSource> secretSources) : IValidateOptions<ConnectorOptions>
{
    [GeneratedRegex("(token|password|passwd|secret|apikey|api_key|privatekey|private_key|webhook)", RegexOptions.IgnoreCase)]
    private static partial Regex SecretLikeKey();

    public ValidateOptionsResult Validate(string? name, ConnectorOptions o)
    {
        var errors = new List<string>();
        var schemes = secretSources.Select(s => s.Scheme).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (o.DeploymentModel == DeploymentModel.SingleTenant)
        {
            if (string.IsNullOrWhiteSpace(o.DefaultTenant)) errors.Add("Connectors:DefaultTenant is required in SingleTenant mode");
            if (o.Tenants.Count > 1) errors.Add($"Connectors: SingleTenant mode has exactly one tenant, found {o.Tenants.Count} ({string.Join(", ", o.Tenants.Keys)})");
            if (o.Tenants.Count == 1 && !o.Tenants.ContainsKey(o.DefaultTenant)) errors.Add($"Connectors: the single tenant must be named '{o.DefaultTenant}' (Connectors:DefaultTenant)");
        }
        else
        {
            if (o.Tenants.Count == 0) errors.Add("Connectors: MultiTenant mode needs at least one entry under Connectors:Tenants");
            foreach (var kind in Enum.GetValues<ConnectorKind>().Where(k => k != ConnectorKind.ModelProvider))
                if (o.Defaults.For(kind) is { Provider.Length: > 0 } d && !d.Provider.Equals("none", StringComparison.OrdinalIgnoreCase))
                    errors.Add($"Connectors:Defaults:{kind}: MultiTenant mode cannot share a {kind} connection across tenants; configure it per tenant");
            var owners = new List<(string Pattern, string Tenant)>();
            foreach (var (tenant, t) in o.Tenants)
            {
                if (t.Repositories.Count == 0) errors.Add($"Connectors:Tenants:{tenant}:Repositories is required in MultiTenant mode");
                foreach (var p in t.Repositories.Select(x => x.Trim()))
                {
                    if (p == "*") { errors.Add($"Connectors:Tenants:{tenant}:Repositories: '*' is not allowed in MultiTenant mode"); continue; }
                    // "org/*" and "org/repo" overlap too: a repository must map to exactly one tenant.
                    foreach (var (q, other) in owners.Where(x => !x.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase) && Tenancy.RepositoryPattern.Overlaps(x.Pattern, p)))
                        errors.Add($"Connectors: repositories matching '{p}' ({tenant}) and '{q}' ({other}) would belong to more than one tenant");
                    owners.Add((p, tenant));
                }
            }
        }
        void Check(string path, ConnectorKind kind, ConnectionOptions? c)
        {
            if (c == null || string.IsNullOrWhiteSpace(c.Provider) || c.Provider.Equals("none", StringComparison.OrdinalIgnoreCase)) return;
            if (!catalog.TryGet(kind, c.Provider.Trim(), out var connector))
            {
                var known = catalog.Descriptors.Where(d => d.Kind == kind).Select(d => d.Id).ToList();
                errors.Add($"{path}:Provider '{c.Provider}' has no registered {kind} connector (registered: {(known.Count == 0 ? "none" : string.Join(", ", known))})");
                return;
            }
            if (c.BaseUrl is { Length: > 0 } u && !Uri.TryCreate(u, UriKind.Absolute, out _)) errors.Add($"{path}:BaseUrl '{u}' is not an absolute URL");
            if (c.Secret is { Length: > 0 } s)
            {
                var r = new SecretRef(s);
                if (!r.IsValid) errors.Add($"{path}:Secret must be a reference like env:NAME or kv:name");
                else if (!schemes.Contains(r.Scheme)) errors.Add($"{path}:Secret scheme '{r.Scheme}' has no registered secret source (registered: {string.Join(", ", schemes)})");
                else if (o.DeploymentModel == DeploymentModel.MultiTenant && !o.MultiTenantSecretSchemes.Contains(r.Scheme, StringComparer.OrdinalIgnoreCase))
                    errors.Add($"{path}:Secret scheme '{r.Scheme}' is process-wide; MultiTenant mode needs a tenant-scoped store ({string.Join(", ", o.MultiTenantSecretSchemes)})");
            }
            foreach (var key in c.Settings.Keys.Where(k => SecretLikeKey().IsMatch(k)))
                errors.Add($"{path}:Settings:{key} looks like a secret; put a reference in {path}:Secret instead");
            foreach (var f in connector.Describe().SetupFields.Where(f => f.Required))
            {
                var present = f.Name switch
                {
                    "BaseUrl" => !string.IsNullOrWhiteSpace(c.BaseUrl),
                    "Secret" => !string.IsNullOrWhiteSpace(c.Secret),
                    _ => c.Settings.TryGetValue(f.Name, out var v) && !string.IsNullOrWhiteSpace(v),
                };
                if (!present) errors.Add($"{path}: {connector.Describe().Id} needs {(f.Name is "BaseUrl" or "Secret" ? f.Name : "Settings:" + f.Name)} ({f.Label})");
            }
        }
        foreach (var kind in Enum.GetValues<ConnectorKind>())
        {
            Check($"Connectors:Defaults:{kind}", kind, o.Defaults.For(kind));
            foreach (var (tenant, t) in o.Tenants) Check($"Connectors:Tenants:{tenant}:{kind}", kind, t.For(kind));
        }
        var r = o.Resilience;
        if (r.MaxRetryAttempts is < 0 or > 10) errors.Add("Connectors:Resilience:MaxRetryAttempts must be 0-10");
        if (r.PermitsPerSecond < 1) errors.Add("Connectors:Resilience:PermitsPerSecond must be at least 1");
        if (r.CircuitBreakerMinimumThroughput < 2) errors.Add("Connectors:Resilience:CircuitBreakerMinimumThroughput must be at least 2");
        if (r.CircuitBreakerFailureRatio is <= 0 or > 1) errors.Add("Connectors:Resilience:CircuitBreakerFailureRatio must be in (0, 1]");
        if (r.CircuitBreakerBreakDuration < TimeSpan.FromMilliseconds(500) || r.CircuitBreakerSamplingDuration < TimeSpan.FromMilliseconds(500))
            errors.Add("Connectors:Resilience: circuit breaker durations must be at least 500 ms");
        if (r.AttemptTimeout < TimeSpan.FromMilliseconds(10) || r.TotalTimeout < r.AttemptTimeout) errors.Add("Connectors:Resilience: AttemptTimeout must be >= 10 ms and <= TotalTimeout");
        if (r.ModelAttemptTimeout < TimeSpan.FromSeconds(1)) errors.Add("Connectors:Resilience: ModelAttemptTimeout must be >= 1 s");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
