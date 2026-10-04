using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecAgent.Core;

namespace SecAgent.Hosting;

/// <summary>Readiness state shared by the consumer and the /readyz probe. Not ready until the consumer has started; not ready again as soon
/// as shutdown begins, so the platform stops routing to a draining replica.</summary>
public sealed class AgentReadiness
{
    volatile bool _started, _draining;
    public bool IsStarted => _started;
    public bool IsDraining => _draining;
    public bool IsReady => _started && !_draining;
    public void MarkStarted() => _started = true;
    public void BeginDrain() => _draining = true;
}

/// <summary>Worker metrics (meter "SecAgent.Agent"), created through IMeterFactory so tests and hosts get their own instances.</summary>
public sealed class AgentMetrics
{
    public const string MeterName = "SecAgent.Agent";
    readonly Counter<long> _messages;
    readonly Histogram<double> _duration;

    public AgentMetrics(IMeterFactory factory)
    {
        var meter = factory.Create(MeterName);
        _messages = meter.CreateCounter<long>("secagent.agent.messages", "{message}", "Messages settled, by entity and outcome");
        _duration = meter.CreateHistogram<double>("secagent.agent.message.duration", "s", "Handler time per message");
    }

    public void Record(string role, string entity, string outcome, TimeSpan elapsed)
    {
        var tags = new TagList { { "secagent.agent", role }, { "messaging.destination.name", entity }, { "outcome", outcome } };
        _messages.Add(1, tags);
        _duration.Record(elapsed.TotalSeconds, tags);
    }
}

/// <summary>Generic queue consumer (hosted service): one receive loop per (entity, slot) for every registered handler. Each message runs in
/// its own DI scope and an OpenTelemetry consumer span, then is completed, abandoned (retry) or dead-lettered.
/// <para>Graceful shutdown: on stop it marks the replica not ready, stops receiving, and lets in-flight messages finish for
/// Agent:DrainTimeoutSeconds. After that their token is cancelled and they are abandoned, so another replica gets them.</para></summary>
public sealed class AgentQueueConsumer(
    IEnumerable<AgentHandlerRegistration> registrations, IAgentQueueReceiver receiver, IServiceScopeFactory scopes, AgentReadiness readiness,
    AgentMetrics metrics, AgentRoleContext context, SecretMasker masker, ILogger<AgentQueueConsumer> log) : BackgroundService
{
    readonly CancellationTokenSource _processing = new();
    int _inFlight;

    public int InFlight => Volatile.Read(ref _inFlight);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var regs = registrations.ToList();
        var opts = context.Options;
        readiness.MarkStarted();
        if (regs.Count == 0) { log.LogInformation("agent {Role}: no queues to consume (HTTP-only role)", context.Spec.Name); return; }
        log.LogInformation("agent {Role}: consuming {Entities} x{Slots}", context.Spec.Name, string.Join(", ", regs.Select(r => r.Entity)), opts.MaxConcurrentMessages);
        var loops = regs.SelectMany(r => Enumerable.Range(0, opts.MaxConcurrentMessages).Select(_ => LoopAsync(r, stoppingToken)));
        await Task.WhenAll(loops);
    }

    async Task LoopAsync(AgentHandlerRegistration reg, CancellationToken stopping)
    {
        var wait = TimeSpan.FromSeconds(context.Options.ReceiveWaitSeconds);
        var backoff = TimeSpan.FromSeconds(1);
        while (!stopping.IsCancellationRequested)
        {
            IAgentDelivery? delivery;
            try { delivery = await receiver.ReceiveAsync(reg.Entity, wait, stopping); backoff = TimeSpan.FromSeconds(1); }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                log.LogError("agent {Role}: receive from {Entity} failed: {Error}", context.Spec.Name, reg.Entity, masker.Mask(e.Message, false));
                try { await Task.Delay(backoff, stopping); } catch (OperationCanceledException) { break; }
                backoff = TimeSpan.FromSeconds(Math.Min(30, backoff.TotalSeconds * 2));
                continue;
            }
            if (delivery == null) continue;
            await ProcessAsync(reg, delivery);   // not tied to `stopping`: an in-flight message gets the drain window
        }
    }

    internal async Task ProcessAsync(AgentHandlerRegistration reg, IAgentDelivery d)
    {
        Interlocked.Increment(ref _inFlight);
        var msg = d.Message;
        using var span = Telemetry.Source.StartActivity($"{reg.Entity} process", ActivityKind.Consumer);
        span?.SetTag("messaging.system", context.Options.Transport);
        span?.SetTag("messaging.destination.name", reg.Entity);
        span?.SetTag("messaging.message.id", msg.MessageId);
        span?.SetTag("messaging.operation.type", "process");
        span?.SetTag("secagent.agent", context.Spec.Name);
        span?.SetTag("secagent.run_id", msg.RunId);
        var sw = Stopwatch.StartNew();
        var token = _processing.Token;
        string outcome;
        Exception? failure = null;
        using (var renewal = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            var renewing = RenewWhileRunningAsync(d, reg.Entity, renewal.Token);
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var handler = (IAgentMessageHandler)scope.ServiceProvider.GetRequiredService(reg.HandlerType);
                await handler.HandleAsync(new AgentDeliveryContext(msg, d.DeliveryCount, reg.Entity), token);
            }
            catch (Exception e) { failure = e; }
            finally
            {
                renewal.Cancel();
                await renewing;   // never throws: renewal problems are logged
            }
        }
        try
        {
            switch (failure)
            {
                case null:
                    await SettleAsync(d, reg.Entity, "complete", () => d.CompleteAsync(CancellationToken.None));
                    outcome = "completed";
                    break;
                case AgentMessageRejectedException e:
                {
                    var reason = masker.Mask(e.Message, false);
                    log.LogWarning("agent {Role}: {MessageId} on {Entity} rejected (dead-lettered): {Reason}", context.Spec.Name, msg.MessageId, reg.Entity, reason);
                    await SettleAsync(d, reg.Entity, "dead-letter", () => d.DeadLetterAsync(reason, CancellationToken.None));
                    span?.SetStatus(ActivityStatusCode.Error, reason);
                    outcome = "rejected";
                    break;
                }
                case OperationCanceledException when token.IsCancellationRequested:
                    log.LogWarning("agent {Role}: {MessageId} cancelled at the drain deadline; abandoned for redelivery", context.Spec.Name, msg.MessageId);
                    await SettleAsync(d, reg.Entity, "abandon", () => d.AbandonAsync("shutdown: drain timeout", CancellationToken.None));
                    outcome = "abandoned";
                    break;
                default:
                {
                    var e = failure!;
                    var reason = masker.Mask(e.Message.Length <= 500 ? e.Message : e.Message[..500], false);
                    log.LogError("agent {Role}: {MessageId} on {Entity} failed (delivery {Count}): {Error}", context.Spec.Name, msg.MessageId, reg.Entity, d.DeliveryCount, reason);
                    await SettleAsync(d, reg.Entity, "abandon", () => d.AbandonAsync(reason, CancellationToken.None));
                    span?.SetStatus(ActivityStatusCode.Error, reason);
                    outcome = "failed";
                    break;
                }
            }
        }
        finally { Interlocked.Decrement(ref _inFlight); }
        span?.SetTag("secagent.outcome", outcome);
        metrics.Record(context.Spec.Name, reg.Entity, outcome, sw.Elapsed);
    }

    /// <summary>Renews the delivery's lock every Agent:LockRenewalSeconds until the handler finishes. A lost lock is logged (the broker
    /// may already be redelivering the message); the handler is not interrupted, and settlement then fails safely.</summary>
    async Task RenewWhileRunningAsync(IAgentDelivery d, string entity, CancellationToken ct)
    {
        var every = TimeSpan.FromSeconds(context.Options.LockRenewalSeconds);
        if (every <= TimeSpan.Zero) return;
        try
        {
            while (true)
            {
                await Task.Delay(every, ct);
                bool renewed;
                try { renewed = await d.RenewLockAsync(ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                catch (Exception e)
                {
                    log.LogWarning("agent {Role}: lock renewal for {MessageId} on {Entity} failed: {Error}", context.Spec.Name, d.Message.MessageId, entity, masker.Mask(e.Message, false));
                    continue;
                }
                if (!renewed)
                {
                    log.LogWarning("agent {Role}: lock for {MessageId} on {Entity} was lost while the handler ran; it may be redelivered", context.Spec.Name, d.Message.MessageId, entity);
                    return;
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>Settlement never takes the receive loop down: if it fails (lock lost, broker down) the broker redelivers the message after
    /// the lock expires, and the handler's duplicate detection / idempotency covers the second delivery.</summary>
    async Task SettleAsync(IAgentDelivery d, string entity, string action, Func<Task> settle)
    {
        try { await settle(); }
        catch (Exception e)
        {
            log.LogError("agent {Role}: {Action} of {MessageId} on {Entity} failed (it will be redelivered): {Error}", context.Spec.Name, action, d.Message.MessageId, entity, masker.Mask(e.Message, false));
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        readiness.BeginDrain();
        var drain = TimeSpan.FromSeconds(context.Options.DrainTimeoutSeconds);
        log.LogInformation("agent {Role}: draining ({InFlight} in flight, up to {Drain}s)", context.Spec.Name, InFlight, drain.TotalSeconds);
        _processing.CancelAfter(drain);
        try { await base.StopAsync(cancellationToken); }
        finally { _processing.Cancel(); }
    }

    public override void Dispose() { _processing.Dispose(); base.Dispose(); }
}
