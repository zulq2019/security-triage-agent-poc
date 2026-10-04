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
        services.AddSingleton(new RunEventPublishRetry(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)));
        services.AddSingleton(sp => new RunEventFanOut(sp.GetRequiredService<AgentServices>().Bus, sp.GetRequiredService<AgentServices>().Masker,
            sp.GetRequiredService<IAgentQueuePublisher>(), context, sp.GetRequiredService<RunEventPublishRetry>(), sp.GetRequiredService<ILogger<RunEventFanOut>>()));
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

/// <summary>Backoff for run-event publication: first retry after <paramref name="Initial"/>, doubling up to <paramref name="Max"/>.</summary>
sealed record RunEventPublishRetry(TimeSpan Initial, TimeSpan Max);

/// <summary>Copies each run event (already masked by RunEventBus) to the run-events topic. Local transports emulate the topic by one copy
/// per worker subscription (audit); Service Bus fans out to every subscription. Events are queued in memory so the workflow thread never
/// waits on the broker.
/// <para>A failed publish is retried with backoff, in order, until it succeeds (MessageId = run:seq, so a retry that did reach the broker
/// is dropped by duplicate detection): a broker interruption delays the audit writer but does not leave gaps in its evidence. Events
/// still queued when the process stops are logged as undelivered; a durable outbox (SQL) is the follow-up for crash safety.</para></summary>
sealed class RunEventFanOut(RunEventBus bus, SecretMasker masker, IAgentQueuePublisher publisher, AgentRoleContext context, RunEventPublishRetry retry,
    ILogger<RunEventFanOut> log) : BackgroundService
{
    readonly Channel<(Guid RunId, string Json)> _events = Channel.CreateUnbounded<(Guid, string)>(new UnboundedChannelOptions { SingleReader = true });

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        bus.OnEvent += OnEvent;
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
                var seq = JsonDocument.Parse(json).RootElement.TryGetProperty("seq", out var s) ? s.GetInt32() : 0;
                var message = new AgentMessage($"{runId:N}:{seq}", runId.ToString(), AgentMessageTypes.RunEvent, json);
                await PublishWithRetryAsync(topic, subs, message, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            var left = _events.Reader.Count;
            if (left > 0) log.LogError("run-events: {Count} event(s) not delivered to the audit writer before shutdown", left);
        }
    }

    /// <summary>Retries one event until it is published or the host stops (then the event is counted as undelivered).</summary>
    async Task PublishWithRetryAsync(string topic, IReadOnlyList<string> subs, AgentMessage message, CancellationToken ct)
    {
        var delay = retry.Initial;
        for (var attempt = 1; ; attempt++)
        {
            try { await publisher.PublishToTopicAsync(topic, subs, message, ct); return; }
            catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                log.LogWarning("run-events publish of {MessageId} failed (attempt {Attempt}, retrying in {Delay}s): {Error}",
                    message.MessageId, attempt, delay.TotalSeconds, masker.Mask(e.Message, false));
            }
            await Task.Delay(delay, ct);
            delay = TimeSpan.FromTicks(Math.Min(retry.Max.Ticks, delay.Ticks * 2));
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        bus.OnEvent -= OnEvent;
        _events.Writer.TryComplete();
        return base.StopAsync(cancellationToken);
    }
}
