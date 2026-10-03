namespace SecAgent.Hosting;

/// <summary>Decorator: a role may only send where its deploy/agents.json entry allows, the same rule the Bicep turns into Service Bus
/// Data Sender role assignments. A wiring mistake therefore fails locally (QueueNotAllowedException) instead of as a 401 in Azure.</summary>
public sealed class CatalogScopedPublisher(IAgentQueuePublisher inner, AgentRoleContext context) : IAgentQueuePublisher
{
    public Task PublishAsync(string queue, AgentMessage message, CancellationToken ct)
    {
        if (!context.AllowedSends.Contains(queue))
            throw new QueueNotAllowedException($"agent '{context.Spec.Name}' may not send to '{queue}' (deploy/agents.json sends: {string.Join(", ", context.AllowedSends.Order())})");
        return inner.PublishAsync(queue, message, ct);
    }

    public Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct)
    {
        if (!context.Spec.PublishesEvents || topic != context.Catalog.RunEventsTopic)
            throw new QueueNotAllowedException($"agent '{context.Spec.Name}' may not publish to topic '{topic}' (publishesEvents is false)");
        return inner.PublishToTopicAsync(topic, subscriptions, message, ct);
    }
}
