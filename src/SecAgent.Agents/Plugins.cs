using SecAgent.Core;

namespace SecAgent.Agents;

/// <summary>What a scanner runs against: a checked-out tree of one commit.</summary>
public sealed record ScanTarget(Guid RunId, string Label, string Dir, string Repo, string Branch, string CommitSha, int? PrNumber);

public sealed record RawOutput(string ScannerId, string ScannerVersion, string Content, string StoredContent, long ElapsedMs, string Args);

/// <summary>Plug-in contract: scanner adapter (PRD 11.2).</summary>
public interface IScannerAdapter
{
    string Id { get; }
    string Version { get; }
    bool Supports(string issueType);
    Task<RawOutput> ScanAsync(ScanTarget target, CancellationToken ct);
    /// <summary>Map raw output to canonical findings (fingerprint computed here, no line numbers).</summary>
    List<Finding> Normalise(RawOutput raw, ScanTarget target, HashSet<string> trackedFiles);
}

/// <summary>Findings pushed to us by an external scanner (e.g. Black Duck via the SARIF intake, src/SecAgent.Intake) for one commit.
/// The scanners step adds them to the head batch of a PR run, so they are deduped, triaged and routed like local scanner findings.</summary>
public interface IExternalFindingSource
{
    /// <summary>Canonical findings received for this repo at this exact head commit (empty when none). Findings for an older head SHA are not returned.</summary>
    IReadOnlyList<ExternalFindingBatch> ForHead(string repo, string headSha);
}

public sealed record ExternalFindingBatch(string IntakeId, string Scanner, string ScannerVersion, string RawEvidenceRef, List<Finding> Findings);

/// <summary>Verifier policy for findings that came from an external scanner. The local rescan (gitleaks/Trivy/Semgrep) cannot prove a
/// Black Duck finding is gone (different rule ids, BDSA advisories, component naming), so the verifier never reports such a fix as verified.</summary>
public static class ExternalFindingPolicy
{
    public const string IntakeIdAttribute = "intake_id";
    public static bool IsExternal(Finding f) => f.Attributes.ContainsKey(IntakeIdAttribute);
    public static List<Finding> NotLocallyVerifiable(IEnumerable<Finding> findings) => findings.Where(IsExternal).ToList();
}

public sealed record FixContext(Workflow.RunState Run, string FixerId, string GroupKey, List<Finding> Findings, int AttemptNo, string? PriorFailure,
    string Worktree, string Branch, Feed Feed, string EntryId, CancellationToken Ct)
{
    public Guid RunId => Run.Run.RunId;
}

public sealed record FixOutcome(bool Applied, bool NeedsHuman, string Summary, string? HumanTaskType, string? HumanTaskDetails,
    Guid? ContextPackId, Guid? RoutingId, int TokensIn, int TokensOut, Dictionary<string, string> Notes);

/// <summary>Plug-in contract: fixer. Branch, commit and PR are created by the core, not the fixer.</summary>
public interface IFixer
{
    string Id { get; }
    string Version { get; }
    string AgentName { get; }
    string[] IssueTypes { get; }
    Task<FixOutcome> ApplyAsync(FixContext ctx);
}
