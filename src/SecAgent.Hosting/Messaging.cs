using System.Text.Json;
using SecAgent.Core;

namespace SecAgent.Hosting;

/// <summary>Envelope for everything that travels between agents. <see cref="RunId"/> is the Service Bus SessionId, so one run's
/// messages are handled in order by one receiver; <see cref="MessageId"/> drives duplicate detection.</summary>
public sealed record AgentMessage(string MessageId, string RunId, string Type, string Body)
{
    public static AgentMessage Create<T>(string messageId, Guid runId, string type, T payload) =>
        new(messageId, runId.ToString(), type, JsonSerializer.Serialize(payload, Schema.Json));

    /// <summary>Deserialises the body. A body that does not parse is a poison message: it is dead-lettered, not retried.</summary>
    public T Payload<T>()
    {
        try { return JsonSerializer.Deserialize<T>(Body, Schema.Json) ?? throw new AgentMessageRejectedException($"{Type}: empty body"); }
        catch (JsonException e) { throw new AgentMessageRejectedException($"{Type}: body is not valid JSON for {typeof(T).Name} ({e.Message})"); }
    }
}

/// <summary>The message can never succeed (bad shape, policy refusal). The consumer dead-letters it at once instead of retrying.</summary>
public sealed class AgentMessageRejectedException(string message) : Exception(message);

/// <summary>A role tried to send somewhere its catalogue entry does not allow (in Azure the managed identity has no Sender role there).</summary>
public sealed class QueueNotAllowedException(string message) : Exception(message);

/// <summary>One received message plus settlement. Exactly one of Complete / Abandon / DeadLetter is called.</summary>
public interface IAgentDelivery
{
    AgentMessage Message { get; }
    int DeliveryCount { get; }
    Task CompleteAsync(CancellationToken ct);
    /// <summary>Back on the queue for redelivery; dead-lettered by the transport after its max deliveries.</summary>
    Task AbandonAsync(string error, CancellationToken ct);
    Task DeadLetterAsync(string reason, CancellationToken ct);
}

/// <summary>Port: send to a queue, or publish to a topic. Roles depend on this, never on a transport.</summary>
public interface IAgentQueuePublisher
{
    Task PublishAsync(string queue, AgentMessage message, CancellationToken ct);
    /// <param name="subscriptions">Subscriptions that should get a copy. Local transports copy to each; Service Bus fans out itself.</param>
    Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct);
}

/// <summary>Port: receive from a queue or a subscription entity (run-events/subscriptions/audit).</summary>
public interface IAgentQueueReceiver
{
    /// <summary>The next message, or null if none arrived within <paramref name="wait"/>.</summary>
    Task<IAgentDelivery?> ReceiveAsync(string entity, TimeSpan wait, CancellationToken ct);
}

/// <summary>Port: is the transport usable (readiness probe).</summary>
public interface IAgentTransportHealth
{
    Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct);
}

/// <summary>What a transport adapter implements. Consumers take the narrow ports above (interface segregation).</summary>
public interface IAgentQueueTransport : IAgentQueuePublisher, IAgentQueueReceiver, IAgentTransportHealth;

/// <summary>Context passed to a handler with each message.</summary>
public sealed record AgentDeliveryContext(AgentMessage Message, int DeliveryCount, string Entity);

/// <summary>Handles messages from one consumed entity. Registered with services.AddAgentMessageHandler&lt;T&gt;(entity); resolved in a DI scope
/// per message. Return = complete; throw = abandon (retry, then dead-letter); throw <see cref="AgentMessageRejectedException"/> = dead-letter now.</summary>
public interface IAgentMessageHandler
{
    Task HandleAsync(AgentDeliveryContext context, CancellationToken ct);
}

/// <summary>Registration record: which handler type serves which entity.</summary>
public sealed record AgentHandlerRegistration(string Entity, Type HandlerType);
