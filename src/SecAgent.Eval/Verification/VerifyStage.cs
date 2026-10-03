using SecAgent.Eval.Stages;

namespace SecAgent.Eval.Verification;

public sealed record VerifyResult(bool Passed, bool TargetGone, IReadOnlyList<ScanHit> Introduced, BuildTestResult Build, IReadOnlyList<string> Reasons);

/// <summary>Verifier stage: decides whether the fix would be proposed (as a PR for human review) or handed to a human.</summary>
public interface IVerifyStage
{
    Task<VerifyResult> VerifyAsync(CaseContext ctx, CancellationToken ct);
}

/// <summary>Same gate as the pipeline's VerifierExecutor: the target finding is gone on rescan, the fix introduced no new findings, and the
/// fixture builds and its tests pass. Single attempt (the pipeline retries a failed fix up to policies.retries.max_fix_retries).</summary>
public sealed class VerifyStage : IVerifyStage
{
    public async Task<VerifyResult> VerifyAsync(CaseContext ctx, CancellationToken ct)
    {
        var scan = ctx.Evidence.ScanAsync(ct);
        var build = await ctx.Evidence.BuildAndTestAsync(ct);
        var after = await scan;
        var target = ctx.Case.Target;
        var targetGone = target == null || !after.Any(h => h.RuleId == target.Rule && h.File == target.File);
        var introduced = RegexRuleScanner.Introduced(ctx.BaselineScan, after);
        var reasons = new List<string>();
        if (target == null) reasons.Add("case has no scanner target: 'target gone' not checked");
        if (!targetGone) reasons.Add($"target {target!.Rule} still detected in {target.File}");
        if (introduced.Count > 0) reasons.Add($"new findings: {string.Join("; ", introduced.Select(h => $"{h.RuleId} {h.File}:{h.Line}"))}");
        if (!build.Built) reasons.Add("build failed: " + build.FailureText);
        else if (!build.TestsOk) reasons.Add($"{build.Failed} test(s) failed of {build.Total}: {build.FailureText}");
        var passed = targetGone && introduced.Count == 0 && build.TestsOk;
        return new VerifyResult(passed, targetGone, introduced, build, reasons);
    }
}
