using SecAgent.Abstractions.Agents;
using SecAgent.Hosting;

namespace SecAgent.Worker.Roles;

/// <summary>triage, fixer-library, fixer-secret, fixer-code, fixer-binary, verifier. Each runs as its own container on its own queue
/// (health, drain, telemetry, KEDA scaling all in place), but in this POC the step itself still executes inside the orchestrator's
/// in-process Agent Framework workflow, which needs the run's in-memory state. Until the workflow is split (open item 1 in
/// docs/containers.md) the handler acknowledges any request with a <c>deferred</c> result so nothing silently piles up.
/// One class serves all six roles: they differ only by name and queue, both of which come from deploy/agents.json.</summary>
public sealed class PipelineStepRole(string role) : IAgentRoleModule
{
    public string Role => role;

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        foreach (var queue in context.Spec.Consumes) services.AddAgentMessageHandler<DeferredStepHandler>(context, queue);
    }
}

sealed class DeferredStepHandler(IAgentQueuePublisher publisher, AgentRoleContext context, ILogger<DeferredStepHandler> log) : IAgentMessageHandler
{
    public async Task HandleAsync(AgentDeliveryContext delivery, CancellationToken ct)
    {
        var runId = Guid.TryParse(delivery.Message.RunId, out var id) ? id
            : throw new AgentMessageRejectedException($"{delivery.Entity}: message without a run id");
        log.LogWarning("{Role}: step request {MessageId} acknowledged as deferred (step runs in the orchestrator in this POC)", context.Spec.Name, delivery.Message.MessageId);
        await publisher.PublishAsync("results", AgentMessage.Create($"{delivery.Message.MessageId}:result", runId, AgentMessageTypes.WorkResult,
            new WorkResult(runId, context.Spec.Name, WorkResultStatus.Deferred,
                $"'{context.Spec.Name}' still runs inside the orchestrator's in-process workflow in this POC (docs/containers.md, open items)")), ct);
    }
}
