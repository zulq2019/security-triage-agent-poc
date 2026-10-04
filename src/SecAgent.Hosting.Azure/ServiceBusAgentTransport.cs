using System.Collections.Concurrent;
using Azure.Core;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SecAgent.Hosting.Azure;

/// <summary>Section Agent:ServiceBus.</summary>
public sealed class ServiceBusTransportOptions
{
    /// <summary>Fully qualified namespace (SECAGENT_SERVICEBUS_NAMESPACE from the Bicep), e.g. sb-secagent-dev-uks-xxxxx.servicebus.windows.net.</summary>
    public string Namespace { get; set; } = "";
    /// <summary>Queues created without sessions (mirror of the Bicep parameter sessionlessQueues). Every other queue is session-enabled:
    /// SessionId = run id, so one run's messages are processed in order. Topic subscriptions are sessionless.</summary>
    public List<string> SessionlessQueues { get; set; } = [];
}

/// <summary>Entities the readiness probe may touch without side effects: <see cref="SendEntities"/> get an AMQP sender link opened
/// (authorised with the role's Data Sender), <see cref="PeekEntities"/> (topic subscriptions and sessionless queues the role consumes)
/// get a peek (Data Receiver; no lock, nothing consumed). Session-enabled queues are never probed: accepting a session would take it.</summary>
public sealed record ServiceBusProbeTargets(IReadOnlyList<string> SendEntities, IReadOnlyList<string> PeekEntities)
{
    public static ServiceBusProbeTargets For(AgentRoleContext context, ServiceBusTransportOptions options) => new(
        [.. context.AllowedSends.Order(StringComparer.Ordinal), .. context.Spec.PublishesEvents ? [context.Catalog.RunEventsTopic] : Array.Empty<string>()],
        [.. context.ConsumedEntities.Where(e => ServiceBusAgentTransport.SplitSubscription(e).Topic != null || options.SessionlessQueues.Contains(e))]);
}

/// <summary>Adapter: the worker's queue ports over Azure Service Bus. Sends set MessageId (duplicate detection) and SessionId (run id).
/// Receives accept the next session with a message (session-enabled queues) or use a plain receiver (sessionless queues, subscriptions).
/// Abandon → redelivery, then the broker dead-letters after the queue's MaxDeliveryCount.</summary>
/// <para>Readiness (<see cref="CheckAsync"/>) is not just "client not closed": the most recent receive must not have failed, and an
/// authenticated broker operation (open a sender link / peek, see <see cref="ServiceBusProbeTargets"/>) must succeed. Probe results are
/// cached briefly so frequent /readyz calls do not load the broker. A bad namespace, missing RBAC or a broker outage reports not ready.</para>
/// <para>Locks: <see cref="IAgentDelivery.RenewLockAsync"/> renews the session lock (session-enabled queues) or the message lock, and
/// the consumer calls it while the handler runs, so long scans keep their lock.</para></summary>
public sealed class ServiceBusAgentTransport(ServiceBusClient client, ServiceBusTransportOptions options, ServiceBusProbeTargets probeTargets, TimeProvider time)
    : IAgentQueueTransport, IAsyncDisposable
{
    static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(10), HealthyProbeCache = TimeSpan.FromSeconds(30), FailedProbeCache = TimeSpan.FromSeconds(5);
    readonly ConcurrentDictionary<string, ServiceBusSender> _senders = new();
    readonly SemaphoreSlim _probeGate = new(1, 1);
    (DateTimeOffset At, bool Ok, string Detail)? _probe;
    (DateTimeOffset At, string Entity, string Error)? _lastReceiveFailure;
    DateTimeOffset _lastReceiveOk = DateTimeOffset.MinValue;

    ServiceBusSender Sender(string entity) => _senders.GetOrAdd(entity, client.CreateSender);

    static ServiceBusMessage ToMessage(AgentMessage m) => new(BinaryData.FromString(m.Body))
    {
        MessageId = m.MessageId, SessionId = m.RunId, Subject = m.Type, ContentType = "application/json",
    };

    public Task PublishAsync(string queue, AgentMessage message, CancellationToken ct) => Sender(queue).SendMessageAsync(ToMessage(message), ct);

    public Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct) =>
        Sender(topic).SendMessageAsync(ToMessage(message), ct);   // the broker copies to every subscription

    public async Task<IAgentDelivery?> ReceiveAsync(string entity, TimeSpan wait, CancellationToken ct)
    {
        try
        {
            var d = await ReceiveCoreAsync(entity, wait, ct);
            _lastReceiveOk = time.GetUtcNow();
            return d;
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            _lastReceiveFailure = (time.GetUtcNow(), entity, Describe(e));
            throw;
        }
    }

    async Task<IAgentDelivery?> ReceiveCoreAsync(string entity, TimeSpan wait, CancellationToken ct)
    {
        var (topic, subscription) = SplitSubscription(entity);
        if (topic != null)
        {
            var r = client.CreateReceiver(topic, subscription);
            var m = await r.ReceiveMessageAsync(wait, ct);
            if (m == null) { await r.DisposeAsync(); return null; }
            return new Delivery(r, m, ownsReceiver: true);
        }
        if (options.SessionlessQueues.Contains(entity))
        {
            var r = client.CreateReceiver(entity);
            var m = await r.ReceiveMessageAsync(wait, ct);
            if (m == null) { await r.DisposeAsync(); return null; }
            return new Delivery(r, m, ownsReceiver: true);
        }
        ServiceBusSessionReceiver session;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(wait);
            try { session = await client.AcceptNextSessionAsync(entity, cancellationToken: timeout.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            catch (ServiceBusException e) when (e.Reason == ServiceBusFailureReason.ServiceTimeout) { return null; }
        }
        var msg = await session.ReceiveMessageAsync(wait, ct);
        if (msg == null) { await session.DisposeAsync(); return null; }
        return new Delivery(session, msg, ownsReceiver: true);
    }

    /// <summary>"run-events/subscriptions/audit" → ("run-events", "audit").</summary>
    public static (string? Topic, string? Subscription) SplitSubscription(string entity)
    {
        var parts = entity.Split('/');
        return parts is [var t, "subscriptions", var s] ? (t, s) : (null, null);
    }

    public async Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct)
    {
        if (client.IsClosed) return (false, "Service Bus client closed");
        if (_lastReceiveFailure is { } f && f.At > _lastReceiveOk) return (false, $"Service Bus receive from {f.Entity} failing: {f.Error}");
        await _probeGate.WaitAsync(ct);
        try
        {
            var now = time.GetUtcNow();
            if (_probe is { } p && now - p.At < (p.Ok ? HealthyProbeCache : FailedProbeCache)) return (p.Ok, p.Detail);
            var result = await ProbeAsync(ct);
            _probe = (now, result.Ok, result.Detail);
            return result;
        }
        finally { _probeGate.Release(); }
    }

    /// <summary>One authenticated round trip per probe target kind: opening a sender link needs a CBS token the broker accepts for that
    /// entity (namespace, DNS, RBAC); a peek proves Listen on what the role consumes. Neither sends nor consumes anything.</summary>
    async Task<(bool Ok, string Detail)> ProbeAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProbeTimeout);
        var checkedEntities = new List<string>();
        try
        {
            if (probeTargets.SendEntities.FirstOrDefault() is { } send)
            {
                using var batch = await Sender(send).CreateMessageBatchAsync(timeout.Token);
                checkedEntities.Add($"send {send}");
            }
            if (probeTargets.PeekEntities.FirstOrDefault() is { } peek)
            {
                var (topic, subscription) = SplitSubscription(peek);
                await using var receiver = topic != null ? client.CreateReceiver(topic, subscription) : client.CreateReceiver(peek);
                await receiver.PeekMessageAsync(cancellationToken: timeout.Token);
                checkedEntities.Add($"peek {peek}");
            }
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            return (false, $"Service Bus {client.FullyQualifiedNamespace} not usable: {(e is OperationCanceledException ? $"no answer within {ProbeTimeout.TotalSeconds:0}s" : Describe(e))}");
        }
        return (true, checkedEntities.Count == 0
            ? $"Service Bus {client.FullyQualifiedNamespace} (no side-effect-free probe target; readiness follows receive results)"
            : $"Service Bus {client.FullyQualifiedNamespace}: {string.Join(", ", checkedEntities)} ok");
    }

    /// <summary>Exception type plus the Service Bus failure reason. Messages are not echoed (they can carry endpoint details).</summary>
    static string Describe(Exception e) => e is ServiceBusException sb ? $"{nameof(ServiceBusException)} ({sb.Reason})" : e.GetType().Name;

    public async ValueTask DisposeAsync()
    {
        foreach (var s in _senders.Values) await s.DisposeAsync();
    }

    sealed class Delivery(ServiceBusReceiver receiver, ServiceBusReceivedMessage m, bool ownsReceiver) : IAgentDelivery
    {
        public AgentMessage Message { get; } = new(m.MessageId, m.SessionId ?? "", m.Subject ?? "", m.Body.ToString());
        public int DeliveryCount => m.DeliveryCount;
        public async Task CompleteAsync(CancellationToken ct) { try { await receiver.CompleteMessageAsync(m, ct); } finally { await Release(); } }
        public async Task AbandonAsync(string error, CancellationToken ct)
        {
            try { await receiver.AbandonMessageAsync(m, new Dictionary<string, object> { ["secagent_error"] = error }, ct); } finally { await Release(); }
        }
        public async Task DeadLetterAsync(string reason, CancellationToken ct)
        {
            try { await receiver.DeadLetterMessageAsync(m, "rejected", reason.Length <= 4096 ? reason : reason[..4096], ct); } finally { await Release(); }
        }
        public async Task<bool> RenewLockAsync(CancellationToken ct)
        {
            try
            {
                if (receiver is ServiceBusSessionReceiver session) await session.RenewSessionLockAsync(ct);   // session queues: the session lock covers the message
                else await receiver.RenewMessageLockAsync(m, ct);
                return true;
            }
            catch (ServiceBusException e) when (e.Reason is ServiceBusFailureReason.MessageLockLost or ServiceBusFailureReason.SessionLockLost) { return false; }
        }
        async Task Release() { if (ownsReceiver) await receiver.DisposeAsync(); }
    }
}

/// <summary>Transport module "servicebus". The client is created on first use with DefaultAzureCredential (the managed identity named by
/// AZURE_CLIENT_ID in Container Apps; a developer login locally).</summary>
public sealed class ServiceBusTransportModule : IQueueTransportModule
{
    public string Key => AgentTransportKeys.ServiceBus;

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        var opts = context.Configuration.GetSection("Agent:ServiceBus").Get<ServiceBusTransportOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(opts.Namespace))
            throw new AgentHostConfigurationException("transport 'servicebus' needs SECAGENT_SERVICEBUS_NAMESPACE (Agent:ServiceBus:Namespace)");
        services.AddSingleton(opts);
        services.AddSingleton(ServiceBusProbeTargets.For(context, opts));
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<TokenCredential>(_ => new DefaultAzureCredential());
        services.AddSingleton(sp => new ServiceBusClient(opts.Namespace, sp.GetRequiredService<TokenCredential>()));
        services.AddSingleton<IAgentQueueTransport, ServiceBusAgentTransport>();
    }
}
