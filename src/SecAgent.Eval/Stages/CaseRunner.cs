using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Checks;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Stages;

/// <summary>Runs one golden case end to end and scores it.</summary>
public interface ICaseRunner
{
    Task<CaseResult> RunAsync(GoldenCase c, string runRoot, CancellationToken ct);
}

/// <summary>triage → (route → fix → verify) → outcome, with the pipeline's state rules: the policy decision decides; a fixer error or a failed
/// verification goes to a human (fix_failed); a fixer hand-off (licence) goes to a human; a verified fix is "fixed" (proposed for human review).
/// Then every check of the case runs through its IOutcomeChecker.</summary>
public sealed class CaseRunner(ICaseWorkspaceFactory workspaces, ICaseEvidenceFactory evidence, IFindingScanner scanner, ITriageStage triage,
    IFixRouter router, IVerifyStage verifier, ICheckerRegistry checkers, SecretMasker masker, TimeProvider time) : ICaseRunner
{
    public async Task<CaseResult> RunAsync(GoldenCase c, string runRoot, CancellationToken ct)
    {
        var t0 = time.GetTimestamp();
        CaseContext? ctx = null;
        var errors = new List<string>();
        try
        {
            var ws = await workspaces.CreateAsync(c, runRoot, ct);
            ctx = new CaseContext(c, ws, StableGuid(c.Id), evidence.Create(ws.Root));
            ctx.BaselineScan = await scanner.ScanAsync(ws.Root, ct);
            await PipelineAsync(ctx, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            var msg = $"{e.GetType().Name}: {masker.Mask(e.Message, false)}";
            if (ctx != null) { ctx.Errors.Add(msg); ctx.Outcome = Outcomes.Error; } else errors.Add(msg);
        }

        var results = new List<CheckResult>();
        foreach (var spec in c.AllChecks())
        {
            if (ctx == null) { results.Add(new(spec.Type, spec.Describe(), false, "case could not be set up")); continue; }
            if (!checkers.TryGet(spec.Type, out var checker)) { results.Add(new(spec.Type, spec.Describe(), false, $"no IOutcomeChecker registered for '{spec.Type}'")); continue; }
            try { results.Add(await checker.CheckAsync(ctx, spec, ct)); }
            catch (Exception e) when (e is not OperationCanceledException) { results.Add(new(spec.Type, spec.Describe(), false, $"checker error: {masker.Mask(e.Message, false)}")); }
        }
        return CaseScorer.Score(c, ctx, results, errors, (long)time.GetElapsedTime(t0).TotalMilliseconds);
    }

    async Task PipelineAsync(CaseContext ctx, CancellationToken ct)
    {
        var t = ctx.Triage = await triage.RunAsync(ctx, ct);
        switch (t.Decision)
        {
            case "suppress": ctx.Outcome = Outcomes.Suppressed; return;
            case "suppress_pending": ctx.Outcome = Outcomes.SuppressPending; return;
            case "accept_pending": ctx.Outcome = Outcomes.AcceptPending; return;
            case "fix": break;
            default: ctx.Outcome = Outcomes.NeedsHuman; return;
        }
        var fixer = router.Route(ctx.Finding, out var fixerId);
        ctx.FixerId = fixerId;
        try
        {
            ctx.Fix = await fixer.ApplyAsync(ctx, ct);
        }
        catch (Exception e) when (e is not (OperationCanceledException or Models.ReplayMissException))
        {
            // Replay misses are harness errors (the recording does not cover the call), not fixer failures.
            ctx.FixError = $"{e.GetType().Name}: {masker.Mask(e.Message, false)}";
            ctx.Outcome = Outcomes.NeedsHuman; ctx.HumanTasks.Add("fix_failed");
            return;
        }
        if (ctx.Fix.NeedsHuman) { ctx.Outcome = Outcomes.NeedsHuman; return; }
        ctx.Verify = await verifier.VerifyAsync(ctx, ct);
        if (ctx.Verify.Passed) ctx.Outcome = Outcomes.Fixed;
        else { ctx.Outcome = Outcomes.NeedsHuman; ctx.HumanTasks.Add("fix_failed"); }
    }

    static Guid StableGuid(string s) => new(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("secagent-eval-pack|" + s))[..16]);
}
