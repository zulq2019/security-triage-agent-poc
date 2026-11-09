using System.Text;
using System.Text.RegularExpressions;
using SecAgent.Core;

namespace SecAgent.Agents.Policy;

/// <summary>An AppSec-approved suppression rule from the rule pack that matched a finding (the evidence a suppression needs).</summary>
public sealed record SuppressionHint(string RuleId, string Text, string? MaxSeverity);

/// <summary>What the policy layer decided: the final decision, the effective severity and why it overrode the model (if it did).</summary>
public sealed record TriageVerdict(string Decision, string SeverityEffective, IReadOnlyList<string> Notes);

/// <summary>The deterministic triage policy layer: the model only proposes, this decides (suppression needs an AppSec rule match,
/// high/critical suppressions need AppSec sign-off, secrets are never lowered, low confidence goes to a human).
/// Pure functions over the finding, the rule pack and policies.yaml (no state, no I/O), shared by the pipeline's TriageExecutor and
/// the evaluation harness so both run exactly the same rules.</summary>
public static class TriagePolicy
{
    public const string NoRuleMatched = "no suppression rule matched";

    /// <summary>Suppression rules of the rule pack whose path glob and attribute condition match the finding.</summary>
    public static List<SuppressionHint> SuppressionHints(Finding f, RulePack rp)
    {
        var list = new List<SuppressionHint>();
        foreach (var rule in rp.SuppressionRules)
        {
            var pathOk = rule.PathGlob.Count == 0 || (f.FilePath != null && rule.PathGlob.Any(g => Glob(g, f.FilePath)));
            var attrOk = rule.Attribute.Count == 0 || (rule.Attribute.TryGetValue("key", out var k) && rule.Attribute.TryGetValue("equals", out var v) && f.Attributes.GetValueOrDefault(k) == v);
            if (pathOk && attrOk)
                list.Add(new(rule.Id, $"rule '{rule.Id}' matched ({rule.Description}) path={f.FilePath}" + (rule.Attribute.Count > 0 ? $" {rule.Attribute["key"]}={rule.Attribute["equals"]}" : ""), rule.MaxSeverity));
        }
        return list;
    }

    /// <summary>The "Suppression rule check" text given to the model (and stored on the finding as rule_hints).</summary>
    public static string HintsText(IReadOnlyCollection<SuppressionHint> hints) => hints.Count > 0 ? string.Join("; ", hints.Select(h => h.Text)) : NoRuleMatched;

    /// <summary>Applies the policy to the model's proposal. <paramref name="proposed"/> is the model decision (fix | suppress | accept | escalate).</summary>
    public static TriageVerdict Apply(Finding f, RulePack rp, string proposed, string severity, double confidence, IReadOnlyCollection<SuppressionHint> hints, PolicyConfig policies)
    {
        var notes = new List<string>();
        var sev = severity;
        if (f.IssueType == IssueTypes.Secret && policies.Authority.NeverLowerSecretSeverity && Schema.Rank(sev) < Schema.Rank(f.SeverityScanner))
        { notes.Add($"secret severity not lowered below scanner severity ({sev} → {f.SeverityScanner})"); sev = f.SeverityScanner; }
        var thresholds = policies.Thresholds;
        // AppSec-approved rules are written against the scanner's normalised severity; a model-raised severity does not un-match them.
        var ruleSev = f.SeverityScanner;
        var ruleMax = hints.Count > 0 ? hints.Min(h => h.MaxSeverity) ?? "info" : "info";
        var ruleOk = hints.Count > 0 && Schema.Rank(ruleSev) <= Schema.Rank(ruleMax) && policies.Authority.AgentMaySuppress.Contains(ruleSev);
        if (ruleOk && proposed != "suppress" && Schema.Rank(sev) > Schema.Rank(ruleSev))
        { notes.Add($"model raised severity {ruleSev} → {sev} without rule evidence; rule evaluated at scanner severity"); sev = ruleSev; }
        var decision = proposed switch
        {
            not "suppress" when ruleOk => Note(notes, "suppress", $"AppSec-approved suppression rule matched with evidence (model proposed '{proposed}') → suppressed by rule pack {rp.Ref}"),
            "fix" => "fix",
            "suppress" when hints.Count == 0 => Note(notes, "needs_human", "agent proposed suppress but no suppression rule matched (no evidence) → human"),
            "suppress" when Schema.Rank(sev) > Schema.Rank(ruleMax) || !policies.Authority.AgentMaySuppress.Contains(sev)
                => Note(notes, "suppress_pending", $"suppress of a {sev} finding needs AppSec sign-off"),
            "suppress" => "suppress",
            "accept" => Note(notes, "accept_pending", "risk acceptance needs a named human approver"),
            _ => Note(notes, "needs_human", "model escalated"),
        };
        if (confidence < thresholds.ConfidenceMin && decision is "fix" or "suppress")
            decision = Note(notes, "needs_human", $"confidence {confidence:0.00} < {thresholds.ConfidenceMin:0.00}");
        return new TriageVerdict(decision, sev, notes);
    }

    /// <summary>Bucket for a decided finding.</summary>
    public static string BucketFor(string decision, string severity, RulePack rp) =>
        decision switch { "suppress" => Buckets.Suppress, "accept_pending" => Buckets.AcceptDefer, _ => rp.BucketFor(severity) };

    /// <summary>Finding status the policy decision moves the finding to after TRIAGED (null = stays for the router).</summary>
    public static string? StatusFor(string decision) => decision switch
    {
        "suppress" => Status.Suppressed, "suppress_pending" => Status.SuppressPending, "accept_pending" => Status.AcceptPending,
        "needs_human" => Status.NeedsHuman, _ => null,
    };

    /// <summary>The rule pack component of the triage context pack.</summary>
    public static string RulePackText(Finding f, RulePack rp)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Rule pack {rp.Ref} for issue type {f.IssueType}.");
        sb.AppendLine(rp.Guidance.Trim());
        foreach (var r in rp.SuppressionRules) sb.AppendLine($"Suppression rule {r.Id}: {r.Description} (paths {string.Join(", ", r.PathGlob)}; max severity {r.MaxSeverity}).");
        foreach (var (b, sevs) in rp.BucketRules) sb.AppendLine($"Bucket {b}: {string.Join("/", sevs)}.");
        return sb.ToString();
    }

    static string Note(List<string> notes, string decision, string note) { notes.Add(note); return decision; }

    static bool Glob(string glob, string path)
    {
        var rx = "^" + Regex.Escape(glob).Replace(@"\*\*/", "(.*/)?").Replace(@"\*\*", ".*").Replace(@"\*", "[^/]*") + "$";
        return Regex.IsMatch(path, rx);
    }
}
