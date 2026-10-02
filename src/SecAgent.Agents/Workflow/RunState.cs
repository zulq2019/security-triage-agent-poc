using System.Collections.Concurrent;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Repo;
using SecAgent.Core;

namespace SecAgent.Agents.Workflow;

/// <summary>Per-run, in-memory working state. The durable state lives in SQL (findings, decisions, fixes, ledger) and
/// workflow checkpoints; workflow messages only carry IDs so they serialise cleanly into checkpoints.</summary>
public sealed class RunState
{
    public required RunRecord Run { get; init; }
    public required PrInfo Pr { get; init; }
    public required Feed Feed { get; init; }
    public required RunBudget Budget { get; init; }
    public required bool FreshTriage { get; init; }
    /// <summary>tokens / cost / max_fixes / max_minutes from the "pr" budget (policies.yaml).</summary>
    public RunLimits Limits { get; init; } = new(0, 0, 0, 0);
    /// <summary>max_minutes deadline + push gate (set by RunService; a no-op deadline when unset, e.g. in tests).</summary>
    public RunDeadline Deadline { get; set; } = new(null, () => Task.CompletedTask);
    public int FixesDispatched;
    public int FixesDeferred;
    public string HeadDir { get; set; } = "";
    public string BaseDir { get; set; } = "";
    public HashSet<string> HeadFingerprints { get; set; } = [];
    public List<Finding> HeadFindings { get; set; } = [];
    public ConcurrentDictionary<Guid, Finding> Findings { get; } = new();
    public ConcurrentDictionary<string, int> AgentTokens { get; } = new();
    public int RetriesUsed;
    public int Injections;
    public int PrsOpened;
    public int PrsReused;
    public DateTime Started { get; } = DateTime.UtcNow;
    public ConcurrentDictionary<string, string> Outcomes { get; } = new();  // group key -> outcome
    public CancellationTokenSource Cts { get; } = new();
    public string? StopReason { get; set; }                  // kill_switch | budget | error
    public string? StopDetail { get; set; }
    public ConcurrentDictionary<string, GroupInfo> Groups { get; } = new();   // group key -> state
    public ConcurrentDictionary<string, Llm.LlmCall> Summaries { get; } = new();
    public ConcurrentDictionary<Guid, FixAttempt> Fixes { get; } = new();
    public List<Finding> BaseOnly { get; set; } = [];
    public HashSet<string> BaseFingerprints { get; set; } = [];
    public List<string> PrUrls { get; } = [];
    public object Lock { get; } = new();
    public CancellationToken Token => Cts.Token;
    public bool Finished;

    public void AddTokens(string agent, int n) => AgentTokens.AddOrUpdate(agent, n, (_, v) => v + n);
}

public sealed class GroupInfo
{
    public required string Key { get; init; }
    /// <summary>Unscoped v1 key, only used to migrate ledger entries written before keys were scoped by repo/PR.</summary>
    public string LegacyKey { get; init; } = "";
    public required string FixerId { get; init; }
    public required List<Guid> FindingIds { get; init; }
    public string Branch { get; set; } = "";
    public string Outcome { get; set; } = "pending";   // pending | pr_opened | pr_reused | needs_human | failed
    public string? PrUrl { get; set; }
    public int? PrNumber { get; set; }
    public int Attempts { get; set; }
}

public static class RunRegistry
{
    static readonly ConcurrentDictionary<Guid, RunState> Runs = new();
    public static void Add(RunState s) => Runs[s.Run.RunId] = s;
    public static RunState Get(Guid id) => Runs[id];
    public static bool TryGet(Guid id, out RunState? s) => Runs.TryGetValue(id, out s);
    public static IEnumerable<RunState> Active => Runs.Values;
}

// ---------- Workflow messages (typed, JSON-serialisable; carried between executors and stored in checkpoints) ----------
public sealed record RunRequest(Guid RunId);
public sealed record IngestDone(Guid RunId, int RawFindings, int BaseFindings);
public sealed record TriageRequest(Guid RunId, List<Guid> FindingIds);
public sealed record TriageDone(Guid RunId, List<Guid> FixFindingIds);
public sealed record RoutePlan(Guid RunId, List<string> GroupKeys);
public sealed record FixTask(Guid RunId, string FixerId, string GroupKey, List<Guid> FindingIds, int AttemptNo, string? PriorFailure);
public sealed record FixProduced(Guid RunId, string FixerId, string GroupKey, List<Guid> FindingIds, Guid FixId, int AttemptNo, string Worktree, string Branch);
public sealed record FixClosed(Guid RunId, string FixerId, string GroupKey, List<Guid> FindingIds, string Outcome, string? PrUrl, string Details);
public sealed record VerifyOutcome(Guid RunId, string FixerId, string GroupKey, List<Guid> FindingIds, Guid FixId, int AttemptNo, bool Passed, string Details, string Worktree, string Branch);
public sealed record ReviewRequest(Guid RunId, string Summary, List<string> PrUrls, int HumanTasks);
public sealed record ReviewResponse(Guid RunId, string Decision);

/// <summary>Custom Agent Framework workflow event: an agent changed state (forwarded to the dashboard).</summary>
public sealed class AgentStatusEvent(string agent, string state, string text) : Microsoft.Agents.AI.Workflows.WorkflowEvent(new { agent, state, text })
{
    public string Agent { get; } = agent; public string State { get; } = state; public string Text { get; } = text;
}
