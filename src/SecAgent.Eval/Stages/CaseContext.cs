using SecAgent.Agents.Policy;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Models;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Stages;

public static class Outcomes
{
    public const string Fixed = "fixed", Suppressed = "suppressed", SuppressPending = "suppress_pending", AcceptPending = "accept_pending",
        NeedsHuman = "needs_human", Error = "error";
    public static readonly string[] Human = [NeedsHuman, SuppressPending, AcceptPending];
}

public sealed record TriageResult(string Proposed, string Decision, string SeverityEffective, double Confidence, string Reason,
    IReadOnlyList<string> PolicyNotes, IReadOnlyList<SuppressionHint> Hints, bool InjectionFlagged);

/// <summary>What a fixer did. Applied = files changed and ready for verification; NeedsHuman = handed to a human by design (e.g. licence).</summary>
public sealed record FixResult(bool Applied, bool NeedsHuman, string Summary, string? HumanTaskType = null, Dictionary<string, string>? Notes = null);

/// <summary>Everything one case run produces. Written by the stages in order, read by the outcome checkers.</summary>
public sealed class CaseContext(GoldenCase c, CaseWorkspace workspace, Guid packRunId, ICaseEvidence evidence)
{
    public GoldenCase Case { get; } = c;
    public CaseWorkspace Workspace { get; } = workspace;
    public Finding Finding => Workspace.Finding;
    /// <summary>Stable per case (derived from the case id) so context packs, and therefore prompt hashes, are reproducible.</summary>
    public Guid PackRunId { get; } = packRunId;
    /// <summary>Build, test, rescan and diff evidence; computed once on first use and shared by the verifier and the checkers.</summary>
    public ICaseEvidence Evidence { get; } = evidence;
    public IReadOnlyList<ScanHit> BaselineScan { get; set; } = [];

    public TriageResult? Triage { get; set; }
    public string? FixerId { get; set; }
    public FixResult? Fix { get; set; }
    public string? FixError { get; set; }
    public VerifyResult? Verify { get; set; }
    public string Outcome { get; set; } = Outcomes.Error;
    public List<string> HumanTasks { get; } = [];
    public List<ModelUsageRecord> Usage { get; } = [];
    public List<string> Errors { get; } = [];
    /// <summary>Exact prompt text sent per call (kept in memory only, for the secret_not_exposed check).</summary>
    public List<string> Prompts { get; } = [];
    public List<string> ModelOutputs { get; } = [];
    public List<InjectionDetector.Hit> InjectionHits { get; } = [];
}
