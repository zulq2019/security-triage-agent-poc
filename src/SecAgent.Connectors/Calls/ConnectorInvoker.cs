namespace SecAgent.Connectors.Calls;

/// <summary>One logical connector operation. <paramref name="Target"/> is an id (repo#12, PROJ-7), never a payload.</summary>
/// <param name="Idempotent">Safe to retry (reads, upserts). Creates are not: they are never retried blindly.</param>
public sealed record ConnectorCall(string Operation, string? Target, bool Idempotent);

public sealed record ConnectorCallContext(ConnectionSettings Connection, ConnectorDescriptor Descriptor);

/// <summary>Cross-cutting behaviour around every connector call (Decorator / chain of responsibility). Registered in DI; the runtime
/// wraps every client it hands out, so a plug-in never implements auditing or resilience itself.</summary>
public interface IConnectorCallInterceptor
{
    /// <summary>Lower runs first (outermost).</summary>
    int Order { get; }
    bool AppliesTo(ConnectorDescriptor descriptor);
    Task<T> InterceptAsync<T>(ConnectorCallContext context, ConnectorCall call, Func<CancellationToken, Task<T>> next, CancellationToken ct);
}

/// <summary>Runs an operation through the interceptor chain of one connection.</summary>
public sealed class ConnectorInvoker(ConnectorCallContext context, IReadOnlyList<IConnectorCallInterceptor> chain)
{
    public ConnectorCallContext Context => context;
    public IReadOnlyList<IConnectorCallInterceptor> Chain => chain;

    public Task<T> InvokeAsync<T>(ConnectorCall call, Func<CancellationToken, Task<T>> operation, CancellationToken ct)
    {
        var next = operation;
        for (var i = chain.Count - 1; i >= 0; i--)
        {
            var interceptor = chain[i];
            var inner = next;
            next = c => interceptor.InterceptAsync(context, call, inner, c);
        }
        return next(ct);
    }

    public Task InvokeAsync(ConnectorCall call, Func<CancellationToken, Task> operation, CancellationToken ct) =>
        InvokeAsync(call, async c => { await operation(c); return true; }, ct);
}

public sealed class ConnectorInvokerFactory(IEnumerable<IConnectorCallInterceptor> interceptors)
{
    readonly IReadOnlyList<IConnectorCallInterceptor> _all = interceptors.OrderBy(i => i.Order).ToList();

    public ConnectorInvoker Create(ConnectionSettings connection, ConnectorDescriptor descriptor) =>
        new(new ConnectorCallContext(connection, descriptor), _all.Where(i => i.AppliesTo(descriptor)).ToList());
}
