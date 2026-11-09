using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using SecAgent.Connectors.Calls;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.Decorators;

namespace SecAgent.Connectors;

/// <summary>Abstract factory selected by configuration: resolves the tenant's connection, picks the plug-in named by its Provider from the
/// catalogue, builds the client and wraps it with the decorators. Clients are cached per tenant and dropped when configuration changes.</summary>
public sealed class ConnectorClientFactory<TClient> : IConnectorClientFactory<TClient>, IDisposable where TClient : class
{
    readonly ConnectorKind _kind = ConnectorKinds.KindOf(typeof(TClient));
    readonly ITenantConnectionResolver _resolver;
    readonly IConnectorCatalog _catalog;
    readonly IConnectorClientDecorator<TClient> _decorator;
    readonly ConnectorInvokerFactory _invokers;
    readonly ConcurrentDictionary<string, (ConnectionSettings Settings, TClient Client)> _cache = new(StringComparer.OrdinalIgnoreCase);
    readonly IDisposable? _onChange;

    public ConnectorClientFactory(ITenantConnectionResolver resolver, IConnectorCatalog catalog, IConnectorClientDecorator<TClient> decorator,
        ConnectorInvokerFactory invokers, IOptionsMonitor<ConnectorOptions> options)
    {
        _resolver = resolver; _catalog = catalog; _decorator = decorator; _invokers = invokers;
        _ = options.CurrentValue;   // validates the configuration on first use outside a host (OptionsValidationException)
        _onChange = options.OnChange(_ => _cache.Clear());
    }

    public TClient ForTenant(string tenantId) => TryForTenant(tenantId, out var c) ? c : throw new ConnectorNotConfiguredException(tenantId, _kind);

    public bool TryForTenant(string tenantId, out TClient client)
    {
        var settings = _resolver.Resolve(tenantId, _kind);
        if (settings == null) { client = null!; return false; }
        client = _cache.AddOrUpdate(settings.TenantId, _ => (settings, Create(settings)),
            (_, existing) => SameConnection(existing.Settings, settings) ? existing : (settings, Create(settings))).Client;
        return true;
    }

    TClient Create(ConnectionSettings s)
    {
        if (!_catalog.TryGet(_kind, s.Provider, out var connector) || connector is not IConnectorClientProvider<TClient> provider)
            throw new ConnectorConfigurationException($"No {_kind} connector named '{s.Provider}' is registered");
        var inner = provider.CreateClient(s);
        return _decorator.Decorate(inner, _invokers.Create(s, provider.Describe()));
    }

    static bool SameConnection(ConnectionSettings a, ConnectionSettings b) =>
        a.Provider == b.Provider && a.BaseUrl == b.BaseUrl && a.Secret == b.Secret && a.Settings.Count == b.Settings.Count
        && a.Settings.All(kv => b.Settings.TryGetValue(kv.Key, out var v) && v == kv.Value);

    public void Dispose() => _onChange?.Dispose();
}
