using System.Text.Json;
using System.Threading.Channels;
using SecAgent.Abstractions.Agents;
using SecAgent.Agents;
using SecAgent.Agents.Hosting;
using SecAgent.Core;
using SecAgent.Hosting;
using SecAgent.Intake;
using SecAgent.Intake.Azure;
using SecAgent.Intake.Configuration;

namespace SecAgent.Worker.Roles;

/// <summary>orchestrator: hosts the Agent Framework workflow. Consumes the run queue through the intake's existing dispatcher
/// (IntakeRunDispatcher → RunService), records worker replies from <c>results</c> as run events, and copies every run event to the
/// run-events topic for the audit writer. In this POC the scanner / triage / fixer / verifier steps still execute inside this
/// process (the same workflow as `secagent serve`); splitting them onto their queues is the next step (docs/containers.md).</summary>
public sealed class OrchestratorRole : IAgentRoleModule
{
    public string Role => "orchestrator";

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        var sql = context.RequiredSql();
        services.PostConfigure<IntakeOptions>(o =>
        {
            if (string.IsNullOrWhiteSpace(o.StorageRoot)) o.StorageRoot = context.DataRoot;
            o.DispatcherEnabled = true;
        });
        // shareQueue: false — the transport module registered the IMessageQueue the intake container also uses (file queue / Service Bus).
        services.AddSecAgentPipeline(context.ContentRoot, context.DataRoot, sql, shareQueue: false);
        services.AddSecAgentIntake(context.Configuration);
        services.AddSecAgentIntakeAzure(context.Configuration);
        services.AddAgentMessageHandler<WorkResultHandler>(context, "results");
        services.AddSingleton<RunEventFanOut>();
        services.AddHostedService(sp => sp.GetRequiredService<RunEventFanOut>());
    }
}

/// <summary>Records a worker's reply as a run event (persisted, shown in the dashboard feed, and fanned out to the audit writer).</summary>
sealed class WorkResultHandler(AgentServices svc, ILogger<WorkResultHandler> log) : IAgentMessageHandler
{
    public Task HandleAsync(AgentDeliveryContext context, CancellationToken ct)
    {
        var result = context.Message.Payload<WorkResult>();
        log.LogInformation("run {RunId}: {Agent} → {Status} {Detail}", result.RunId, result.Agent, result.Status, svc.Masker.Mask(result.Detail, false));
        svc.Bus.Publish(result.RunId, "work_result", new { agent = result.Agent, status = result.Status, detail = result.Detail, data = result.Data });
        return Task.CompletedTask;
    }
}

/// <summary>Copies each run event (already masked by RunEventBus) to the run-events topic. Local transports emulate the topic by one copy
/// per worker subscription (audit); Service Bus fans out to every subscription. Events are queued in memory so the workflow thread never
/// waits on the broker.</summary>
sealed class RunEventFanOut(AgentServices svc, IAgentQueuePublisher publisher, AgentRoleContext context, ILogger<RunEventFanOut> log) : BackgroundService
{
    readonly Channel<(Guid RunId, string Json)> _events = Channel.CreateUnbounded<(Guid, string)>(new UnboundedChannelOptions { SingleReader = true });

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        svc.Bus.OnEvent += OnEvent;
        return base.StartAsync(cancellationToken);
    }

    void OnEvent(Guid runId, string json) => _events.Writer.TryWrite((runId, json));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var topic = context.Catalog.RunEventsTopic;
        var subs = context.Catalog.TopicSubscriptions(a => a.Host == AgentHosts.Worker);
        try
        {
            await foreach (var (runId, json) in _events.Reader.ReadAllAsync(stoppingToken))
            {
                try
                {
                    var seq = JsonDocument.Parse(json).RootElement.TryGetProperty("seq", out var s) ? s.GetInt32() : 0;
                    await publisher.PublishToTopicAsync(topic, subs, new AgentMessage($"{runId:N}:{seq}", runId.ToString(), AgentMessageTypes.RunEvent, json), stoppingToken);
                }
                catch (Exception e) when (e is not OperationCanceledException) { log.LogWarning("run-events publish failed: {Error}", svc.Masker.Mask(e.Message, false)); }
            }
        }
        catch (OperationCanceledException) { }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        svc.Bus.OnEvent -= OnEvent;
        _events.Writer.TryComplete();
        return base.StopAsync(cancellationToken);
    }
}
