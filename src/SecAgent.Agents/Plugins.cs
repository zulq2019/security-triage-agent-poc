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
