using System.Collections.Concurrent;
using Azure.Core;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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

/// <summary>Adapter: the worker's queue ports over Azure Service Bus. Sends set MessageId (duplicate detection) and SessionId (run id).
/// Receives accept the next session with a message (session-enabled queues) or use a plain receiver (sessionless queues, subscriptions).
/// Abandon → redelivery, then the broker dead-letters after the queue's MaxDeliveryCount.</summary>
public sealed class ServiceBusAgentTransport(ServiceBusClient client, ServiceBusTransportOptions options) : IAgentQueueTransport, IAsyncDisposable
{
    readonly ConcurrentDictionary<string, ServiceBusSender> _senders = new();

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

    public Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct) =>
        Task.FromResult(client.IsClosed ? (false, "Service Bus client closed") : (true, $"Service Bus {client.FullyQualifiedNamespace}"));

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
        services.AddSingleton<TokenCredential>(_ => new DefaultAzureCredential());
        services.AddSingleton(sp => new ServiceBusClient(opts.Namespace, sp.GetRequiredService<TokenCredential>()));
        services.AddSingleton<IAgentQueueTransport, ServiceBusAgentTransport>();
    }
}
