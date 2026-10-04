using System.Text.Json;
using SecAgent.Agents.Workflow;
using SecAgent.Core;

namespace SecAgent.Agents.Llm;

public sealed record LlmCall(JsonElement Json, ContextPack Pack, RoutingDecision Routing, List<InjectionDetector.Hit> Injections, double Seconds);

/// <summary>One model call = one fresh ContextPack + one RoutingDecision (D-09). Shows the steps as tool lines in the feed.</summary>
public static class LlmStep
{
    public static async Task<LlmCall> RunAsync(AgentServices s, RunState run, string agentId, string uiAgent, string entryId, Guid? findingId, string? groupKey,
        IEnumerable<ComponentInput> components, CallSpec spec, CancellationToken ct)
    {
        var feed = run.Feed;
        spec = spec with { TriggerType = run.Run.TriggerType, Repo = run.Pr.Repo, PrNumber = run.Pr.Number };   // usage record context
        var t0 = feed.ToolStart(entryId, "context.build", $"agent={agentId} purpose={spec.TaskType}");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var pr = s.Context.Build(run.Run.RunId, agentId, findingId, groupKey, components);
        var p = pr.Pack;
        var trimmed = p.Components.Count(c => !c.Included);
        feed.ToolEnd(entryId, t0, "context.build",
            $"pack {p.ContextPackId.ToString()[..8]} · {p.TokenTotal}/{p.TokenBudget} tok · {p.Components.Count(c => c.Included)} parts{(trimmed > 0 ? $" · {trimmed} trimmed" : "")} · masked ✓ · {p.ContentHash[..15]}…",
            !p.OverBudget, sw.ElapsedMilliseconds);
        if (p.OverBudget) throw new OverBudgetPackException($"required context {p.TokenTotal} > budget {p.TokenBudget}");
        var (preview, _) = await s.Gateway.RouteAsync(p, spec, run.Budget, ct);
        var t1 = feed.ToolStart(entryId, "model.call", $"{preview.ChosenModelId} ({preview.Tier}) · {preview.RequiredQuality} quality");
        sw.Restart();
        try
        {
            var r = await s.Gateway.CallAsync(p, spec, run.Budget, ct);
            var rd = r.Routing;
            run.AddTokens(uiAgent, rd.TokensIn + rd.TokensOut);
            feed.ToolEnd(entryId, t1, "model.call",
                $"{rd.ChosenModelId} ({rd.Tier}{(rd.FallbackUsed ? ", fallback" : "")}) · {rd.TokensIn}→{rd.TokensOut} tok · {rd.LatencyMs / 1000.0:0.0}s inference · route {rd.RoutingId.ToString()[..8]}{(rd.SchemaAttempts > 1 ? $" · JSON retry ×{rd.SchemaAttempts - 1}" : "")}",
                true, sw.ElapsedMilliseconds);
            feed.Publish("tokens", new { agent = uiAgent, tokens = run.AgentTokens.GetValueOrDefault(uiAgent), total = run.Budget.Used, budget = run.Budget.Tokens, cost = run.Budget.CostUsed, model = rd.ChosenModelId, tier = rd.Tier });
            return new LlmCall(r.Json, p, rd, pr.InjectionHits, r.Seconds);
        }
        catch
        {
            feed.ToolEnd(entryId, t1, "model.call", $"{preview.ChosenModelId} failed", false, sw.ElapsedMilliseconds);
            throw;
        }
    }

    public static string FindingJson(Finding f) => JsonSerializer.Serialize(new
    {
        f.FindingId, f.IssueType, f.Title, f.SourceScanner, f.ScannerRuleId, f.SeverityScanner, f.CveIds, f.CweIds, f.FilePath, f.LineStart,
        f.ComponentName, f.ComponentVersion, f.FixedVersion, f.DirectOrTransitive, f.LicenceId, f.Reachability, f.Exposure, f.Message,
        rule_hints = f.Attributes.GetValueOrDefault("rule_hints"), f.Fingerprint, f.Repo, f.Branch, f.PrNumber,
    }, Schema.JsonIndented);
}
