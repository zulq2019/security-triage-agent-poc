using System.Text.Json;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Policy;
using SecAgent.Core;

namespace SecAgent.Eval.Stages;

public interface ITriageStage
{
    Task<TriageResult> RunAsync(CaseContext ctx, CancellationToken ct);
}

/// <summary>Triage exactly as the pipeline's TriageExecutor does it on a first sighting: rule-pack suppression hints, the same five context
/// components, the triage prompt and schema, then the shared deterministic <see cref="TriagePolicy"/> (the model only proposes).</summary>
public sealed class TriageStage(ConfigSnapshot cfg, IModelStep step, SecretMasker masker) : ITriageStage
{
    public async Task<TriageResult> RunAsync(CaseContext ctx, CancellationToken ct)
    {
        var f = ctx.Finding;
        var rp = cfg.RulePackFor(f.IssueType);
        var hints = TriagePolicy.SuppressionHints(f, rp);
        f.Attributes["rule_hints"] = TriagePolicy.HintsText(hints);
        var snippet = TriageSnippets.Build(f, ctx.Workspace.Root, masker);
        var budget = cfg.Policies.Budgets.TryGetValue("pr", out var b) ? b.Tokens : 0;
        var call = await step.RunAsync(ctx, "triage", "triage-agent", "triage", "triage-output", f.SeverityScanner,
        [
            new("finding", $"finding:{f.FindingId}", LlmStep.FindingJson(f)),
            new("rule_pack", $"rule-packs/{rp.Id}@{rp.Version}", TriagePolicy.RulePackText(f, rp)),
            new("code_snippet", f.CodeSnippetRef ?? $"file:{f.FilePath ?? f.ComponentName}", snippet),
            new("tool_output", "suppression-rule-check", "Suppression rule check: " + f.Attributes["rule_hints"]),
            new("run_summary", $"run:{ctx.PackRunId}", ContextBuilder.RunSummary("pr", $"PR #{f.PrNumber} {f.Repo} (new vs base)", [f], budget)),
        ], ct);
        var proposed = Str(call.Json, "decision");
        var sev = Str(call.Json, "severity_effective");
        var conf = call.Json.TryGetProperty("confidence", out var c) ? c.GetDouble() : 0;
        var reason = masker.Mask(Str(call.Json, "reason"), false);
        var verdict = TriagePolicy.Apply(f, rp, proposed, sev, conf, hints, cfg.Policies);
        f.SeverityEffective = verdict.SeverityEffective;
        f.Bucket = TriagePolicy.BucketFor(verdict.Decision, verdict.SeverityEffective, rp);
        var injected = ctx.InjectionHits.Count > 0;
        f.InjectionFlag = injected;
        return new TriageResult(proposed, verdict.Decision, verdict.SeverityEffective, conf, reason, verdict.Notes, hints, injected);
    }

    static string Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
}
