using SecAgent.Core;
using SecAgent.Hosting;

namespace SecAgent.Worker.Roles;

/// <summary>audit-writer: consumes the <c>audit</c> subscription of run-events and writes each event to the write-once evidence store
/// (evidence/audit/{run}/{seq}.json). Idempotent: a redelivered event maps to the same blob, which the store keeps as is. Events are
/// masked again before writing (defence in depth; RunEventBus already masks).</summary>
public sealed class AuditWriterRole : IAgentRoleModule
{
    public string Role => "audit-writer";

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        services.AddLocalBlobStore(context);
        foreach (var entity in context.Spec.Subscribes.Select(context.Catalog.SubscriptionEntity))
            services.AddAgentMessageHandler<AuditEventHandler>(context, entity);
    }
}

sealed class AuditEventHandler(LocalBlobStore blob, SecretMasker masker) : IAgentMessageHandler
{
    public Task HandleAsync(AgentDeliveryContext delivery, CancellationToken ct)
    {
        var m = delivery.Message;
        if (!Guid.TryParse(m.RunId, out var runId)) throw new AgentMessageRejectedException("run event without a run id");
        var name = Hashing.Sha256(m.MessageId)[..16];
        blob.Put("evidence", $"audit/{runId:N}/{name}.json", masker.Mask(m.Body, false));
        return Task.CompletedTask;
    }
}
