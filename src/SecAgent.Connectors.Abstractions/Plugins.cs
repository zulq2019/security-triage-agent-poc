namespace SecAgent.Connectors;

/// <summary>Connector plug-in (SDD 9.8): describes itself and checks its health for one connection. One class + one registration
/// line per connector; the core, the pipeline and the Connections page do not change when one is added.</summary>
public interface IConnector
{
    ConnectorDescriptor Describe();
    /// <summary>One cheap real read call (or, for fakes, an in-memory check). Never throws for an unhealthy system: returns Failing.</summary>
    Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct);
}

/// <summary>Plug-in factory: builds the typed client for one resolved connection. Called by the runtime's client factory, never by agents.</summary>
public interface IConnectorClientProvider<out TClient> : IConnector where TClient : class
{
    TClient CreateClient(ConnectionSettings connection);
}

/// <summary>What workers use: a typed client for one tenant (SDD 9.8 "IConnectorClientFactory"). Workers never see a token or a
/// connection string; the client is already wrapped with the auditing and resilience decorators.</summary>
public interface IConnectorClientFactory<TClient> where TClient : class
{
    /// <summary>The tenant's client. Throws <see cref="ConnectorNotConfiguredException"/> when the tenant has no connection of this kind.</summary>
    TClient ForTenant(string tenantId);
    /// <summary>For optional connectors (issue tracker, notifier): false when the tenant has none configured.</summary>
    bool TryForTenant(string tenantId, out TClient client);
}

/// <summary>Catalogue of registered connector plug-ins (for the Connections page and for configuration validation).</summary>
public interface IConnectorCatalog
{
    IReadOnlyList<ConnectorDescriptor> Descriptors { get; }
    bool TryGet(ConnectorKind kind, string providerId, out IConnector connector);
}
