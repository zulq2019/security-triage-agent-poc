using SecAgent.Core;

namespace SecAgent.Intake.Runs;

/// <summary>Consumes "intake-runs" and starts pipeline runs the same way POST /api/runs does (RunService.StartAsync for repo + PR).
/// One run at a time (the dashboard's rule): while a run is active or the kill switch is on, the message waits.
/// Backlog-mode intakes (no PR number, e.g. nightly on main) are recorded as backlog_pending: slice 1 has no backlog runner yet.</summary>
public sealed class IntakeRunDispatcher(IMessageQueue queue, IIntakeLedger ledger, Func<IntakeRunRequest, CancellationToken, Task<Guid>> startPrRun,
    Func<bool> canStart, Action<string>? log = null)
{
    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!queue.TryReceive(QueueRunStarter.QueueName, out var m)) { await Task.Delay(1000, ct); continue; }
                await HandleAsync(m!, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { log?.Invoke("intake dispatcher: " + e.Message); }
        }
    }

    public async Task HandleAsync(QueueMessage m, CancellationToken ct)
    {
        var req = m.As<IntakeRunRequest>();
        var rec = ledger.Get(req.IdempotencyKey);
        if (req.PrNumber is null)
        {
            if (rec != null) { rec.Status = IntakeStatus.BacklogPending; rec.Detail = "backlog mode: findings stored; no backlog runner in slice 1"; ledger.Update(rec); }
            log?.Invoke($"intake {req.IntakeId}: backlog-mode findings stored for {req.Repo}@{req.HeadSha[..7]} ({req.Findings}); no backlog runner yet");
            queue.Complete(m);
            return;
        }
        while (!canStart()) await Task.Delay(2000, ct);   // wait for the active run to finish / kill switch to be turned off
        try
        {
            var runId = await startPrRun(req, ct);
            if (rec != null) { rec.Status = IntakeStatus.RunStarted; rec.RunId = runId; rec.Detail = null; ledger.Update(rec); }
            log?.Invoke($"intake {req.IntakeId}: started run {runId} for {req.Repo} PR #{req.PrNumber}");
            queue.Complete(m);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            if (rec != null) { rec.Status = IntakeStatus.StartFailed; rec.Detail = ParsersTrunc(e.Message); ledger.Update(rec); }
            queue.Abandon(m, e.Message);   // redelivered, dead-lettered after max deliveries
        }
    }

    static string ParsersTrunc(string s) => s.Length <= 300 ? s : s[..300];
}
