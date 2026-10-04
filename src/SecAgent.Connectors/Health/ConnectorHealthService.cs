namespace SecAgent.Connectors.Health;

/// <summary>One row of the Connections page for a tenant: which plug-in is configured for a kind, its descriptor and (optionally) health.</summary>
public sealed record ConnectorStatus(ConnectorKind Kind, bool Configured, string? Provider, string? BaseUrl, string? SecretRef, ConnectorDescriptor? Descriptor, HealthResult? Health);

public interface IConnectorHealthService
{
    Task<IReadOnlyList<ConnectorStatus>> GetStatusAsync(string tenantId, bool probe, CancellationToken ct);
}

/// <summary>Health runs before a run and from the page (SDD 9.7). A probe never throws: an exception is reported as Failing.</summary>
public sealed class ConnectorHealthService(ITenantConnectionResolver resolver, IConnectorCatalog catalog, TimeProvider time) : IConnectorHealthService
{
    public async Task<IReadOnlyList<ConnectorStatus>> GetStatusAsync(string tenantId, bool probe, CancellationToken ct)
    {
        var rows = new List<ConnectorStatus>();
        foreach (var kind in Enum.GetValues<ConnectorKind>())
        {
            var s = resolver.Resolve(tenantId, kind);
            if (s == null) { rows.Add(new(kind, false, null, null, null, null, null)); continue; }
            catalog.TryGet(kind, s.Provider, out var connector);
            HealthResult? health = null;
            if (probe && connector != null)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                try { health = await connector.CheckHealthAsync(s, timeout.Token); }
                catch (Exception e) { health = HealthResult.Failing($"{e.GetType().Name}: {e.Message}", time.GetUtcNow()); }
            }
            rows.Add(new(kind, true, s.Provider, s.BaseUrl, s.Secret?.Value, connector?.Describe(), health));
        }
        return rows;
    }
}
