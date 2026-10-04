using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Runs;

/// <summary>Hosted service: consumes run requests (<see cref="IIntakeRunSource"/>) and starts pipeline runs through the host's
/// <see cref="IPrRunLauncher"/> (same path as POST /api/runs). One run at a time: while <see cref="IRunAdmission"/> says no
/// (a run is active or the kill switch is on) the message waits. Backlog-mode intakes (no PR number) are recorded as backlog_pending:
/// slice 1 has no backlog runner yet.
/// <para>Pushed findings are about one exact commit, so the run is started for the queued head SHA only. If the PR moved on in the
/// meantime the intake is marked <see cref="IntakeStatus.Superseded"/> (its findings would not apply to the new head; the producer's
/// scan of the new head brings fresh ones) instead of run_started.</para></summary>
public sealed class IntakeRunDispatcher(IIntakeRunSource source, IIntakeLedger ledger, IPrRunLauncher launcher, IRunAdmission admission,
    IOptions<IntakeOptions> options, TimeProvider clock, SecretMasker masker, ILogger<IntakeRunDispatcher> log) : BackgroundService
{
    static readonly TimeSpan IdlePoll = TimeSpan.FromSeconds(1), AdmissionPoll = TimeSpan.FromSeconds(2);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!options.Value.DispatcherEnabled) return;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (await source.ReceiveAsync(ct) is not { } delivery) { await Task.Delay(IdlePoll, clock, ct); continue; }
                await HandleAsync(delivery, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { log.LogError("intake dispatcher: {Error}", masker.Mask(e.Message, false)); }
        }
    }

    public async Task HandleAsync(IntakeRunDelivery delivery, CancellationToken ct)
    {
        var req = delivery.Request;
        var rec = ledger.Get(req.IdempotencyKey);
        if (req.PrNumber is not { } pr)
        {
            if (rec != null) { rec.Status = IntakeStatus.BacklogPending; rec.Detail = "backlog mode: findings stored; no backlog runner in slice 1"; ledger.Update(rec); }
            log.LogInformation("intake {IntakeId}: backlog-mode findings stored for {Repo}@{Sha} ({Findings}); no backlog runner yet", req.IntakeId, req.Repo, req.HeadSha[..7], req.Findings);
            await source.CompleteAsync(delivery, ct);
            return;
        }
        while (!admission.CanStartRun) await Task.Delay(AdmissionPoll, clock, ct);
        try
        {
            var start = await launcher.StartPrRunAsync(req.Repo, pr, req.HeadSha, ct);
            if (start.RunId is { } runId)
            {
                if (rec != null) { rec.Status = IntakeStatus.RunStarted; rec.RunId = runId; rec.Detail = null; ledger.Update(rec); }
                log.LogInformation("intake {IntakeId}: started run {RunId} for {Repo} PR #{Pr} at {Sha}", req.IntakeId, runId, req.Repo, pr, Short(req.HeadSha));
            }
            else
            {
                var detail = $"superseded: PR head moved from {Short(req.HeadSha)} to {Short(start.CurrentHeadSha)} before the run started; these findings are for the old commit";
                if (rec != null) { rec.Status = IntakeStatus.Superseded; rec.Detail = detail; ledger.Update(rec); }
                log.LogInformation("intake {IntakeId}: {Repo} PR #{Pr} {Detail}", req.IntakeId, req.Repo, pr, detail);
            }
            await source.CompleteAsync(delivery, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            var reason = masker.Mask(e.Message.Length <= 300 ? e.Message : e.Message[..300], false);
            if (rec != null) { rec.Status = IntakeStatus.StartFailed; rec.Detail = reason; ledger.Update(rec); }
            await source.AbandonAsync(delivery, reason, ct);   // redelivered, dead-lettered after max deliveries
        }
    }

    static string Short(string sha) => sha.Length > 7 ? sha[..7] : sha;
}
