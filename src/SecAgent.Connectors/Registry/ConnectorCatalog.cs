namespace SecAgent.Connectors.Registry;

/// <summary>Plug-in registry keyed by (kind, provider id), like the fixer registry. Two plug-ins with the same key stop start-up.</summary>
public sealed class ConnectorCatalog : IConnectorCatalog
{
    readonly Dictionary<(ConnectorKind, string), IConnector> _byKey = new();

    public ConnectorCatalog(IEnumerable<IConnector> connectors)
    {
        foreach (var c in connectors)
        {
            var d = c.Describe();
            var key = (d.Kind, d.Id.ToLowerInvariant());
            if (_byKey.TryGetValue(key, out var existing))
            {
                if (ReferenceEquals(existing, c)) continue;
                throw new InvalidOperationException($"Two {d.Kind} connectors are registered with id '{d.Id}' ({existing.GetType().Name}, {c.GetType().Name})");
            }
            _byKey[key] = c;
        }
        Descriptors = _byKey.Values.Select(c => c.Describe()).OrderBy(d => d.Kind).ThenBy(d => d.IsSimulated).ThenBy(d => d.Id).ToList();
    }

    public IReadOnlyList<ConnectorDescriptor> Descriptors { get; }

    public bool TryGet(ConnectorKind kind, string providerId, out IConnector connector) =>
        _byKey.TryGetValue((kind, providerId.Trim().ToLowerInvariant()), out connector!);
}
