using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAgent.Core;

namespace SecAgent.Hosting;

/// <summary>Adapter: the worker's queue ports over the domain's <see cref="IMessageQueue"/> (in-process <see cref="InProcessQueue"/>, or the
/// shared-folder <see cref="FileSystemMessageQueue"/>). The same IMessageQueue instance also carries the intake's run queue, so intake and
/// orchestrator containers meet on it. A topic is emulated by one copy per subscription entity.</summary>
public sealed class MessageQueueAgentTransport(IMessageQueue queue, IAgentTransportHealth health, ILogger<MessageQueueAgentTransport> log) : IAgentQueueTransport
{
    static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(200);
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task PublishAsync(string entity, AgentMessage message, CancellationToken ct)
    {
        if (!queue.Publish(entity, message.MessageId, JsonSerializer.Serialize(message, Json)))
            log.LogDebug("duplicate {MessageId} on {Entity} dropped (duplicate detection)", message.MessageId, entity);
        return Task.CompletedTask;
    }

    public async Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct)
    {
        foreach (var sub in subscriptions) await PublishAsync($"{topic}/subscriptions/{sub}", message, ct);
    }

    public async Task<IAgentDelivery?> ReceiveAsync(string entity, TimeSpan wait, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + wait;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (queue.TryReceive(entity, out var m) && m != null)
            {
                AgentMessage? msg = null;
                try { msg = JsonSerializer.Deserialize<AgentMessage>(m.Body, Json); } catch (JsonException) { }
                if (msg is { MessageId.Length: > 0 }) return new Delivery(queue, m, msg);
                log.LogWarning("message {MessageId} on {Entity} is not an agent envelope: dead-lettered", m.MessageId, entity);
                DeadLetter(queue, m, "not an agent envelope");
                continue;
            }
            if (DateTime.UtcNow >= deadline) return null;
            await Task.Delay(Poll, ct);
        }
    }

    public Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct) => health.CheckAsync(ct);

    /// <summary>IMessageQueue has no explicit dead-letter call: a delivery count at the limit makes Abandon dead-letter the message
    /// (both InProcessQueue and FileSystemMessageQueue).</summary>
    static void DeadLetter(IMessageQueue q, QueueMessage m, string reason)
    {
        m.DeliveryCount = int.MaxValue / 2;
        q.Abandon(m, reason);
    }

    sealed class Delivery(IMessageQueue q, QueueMessage raw, AgentMessage msg) : IAgentDelivery
    {
        public AgentMessage Message => msg;
        public int DeliveryCount => raw.DeliveryCount;
        public Task CompleteAsync(CancellationToken ct) { q.Complete(raw); return Task.CompletedTask; }
        public Task AbandonAsync(string error, CancellationToken ct) { q.Abandon(raw, error); return Task.CompletedTask; }
        public Task DeadLetterAsync(string reason, CancellationToken ct) { DeadLetter(q, raw, reason); return Task.CompletedTask; }
    }
}

/// <summary>Health of the in-process queue: always usable.</summary>
public sealed class InProcessTransportHealth : IAgentTransportHealth
{
    public Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct) => Task.FromResult((true, "in-process queue"));
}
