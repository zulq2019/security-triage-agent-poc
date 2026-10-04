using SecAgent.Connectors;
using Microsoft.Agents.AI.Workflows;
using SecAgent.Agents.Llm;
using SecAgent.Core;

namespace SecAgent.Agents.Workflow;

/// <summary>Base for every workflow executor: shared services, the run's state, status events and stop handling.</summary>
public abstract class StepBase(string id, AgentServices s, RunState r) : Executor(id)
{
    protected AgentServices S { get; } = s;
    protected RunState R { get; } = r;
    protected Feed Feed => R.Feed;
    protected Guid RunId => R.Run.RunId;
    protected CancellationToken Ct => R.Token;
    /// <summary>The run tenant's source control connector (no merge capability exists on it).</summary>
    protected ISourceControlClient Scm => S.Connectors.SourceControl.ForTenant(R.TenantId);

    /// <summary>State, base and URL of a PR in the run's repository (null when it no longer exists).</summary>
    protected async Task<PullRequestSummary?> GetSummaryAsync(int number) =>
        await Scm.GetPullRequestAsync(R.Pr.Repo, number, Ct) is { } p ? new PullRequestSummary(p.Number, p.Url, p.State, p.Title, p.BaseRef, p.HeadRef) : null;

    protected async ValueTask StatusAsync(IWorkflowContext ctx, string agent, string state, string text)
    {
        Feed.Agent(agent, state, text, R.AgentTokens.GetValueOrDefault(agent));
        await ctx.AddEventAsync(new AgentStatusEvent(agent, state, text));
    }

    /// <summary>Runs a step body; kill switch, budget stop and unexpected errors stop the whole run cleanly.</summary>
    protected async ValueTask GuardAsync(string agent, Func<Task> body)
    {
        if (R.Token.IsCancellationRequested) return;
        try { await body(); }
        catch (Exception e) { Stop(agent, e); }
    }

    protected void Stop(string agent, Exception e)
    {
        var reason = e is KillSwitchEngagedException || (e is OperationCanceledException && S.Kill.IsOn) ? "kill_switch"
            : e is BudgetExceededException ? "budget" : e is OperationCanceledException ? "cancelled" : "error";
        lock (R.Lock)
        {
            if (R.StopReason != null) return;
            R.StopReason = reason; R.StopDetail = $"{agent}: {e.GetType().Name}: {S.Masker.Mask(e.Message, false)}";
        }
        Feed.Agent(agent, "failed", reason == "kill_switch" ? "Stopped · kill switch" : reason == "budget" ? "Stopped · budget" : "Failed");
        Feed.Entry(agent, reason switch
        {
            "kill_switch" => "kill switch engaged: stopping all agents, in-flight model calls cancelled",
            "budget" => "run budget exhausted: stopping (no further model calls)",
            _ => "step failed: " + R.StopDetail,
        }, "fail", ["fail", reason == "kill_switch" ? "Killed" : reason == "budget" ? "Budget" : "Error"]);
        R.Cts.Cancel();
    }

    protected void Move(Finding f, string to, string trigger, string by)
    {
        if (f.Status == to || !FindingStateMachine.IsAllowed(f.Status, to)) return;
        S.States.Transition(RunId, f, to, trigger, by);
    }

    protected void PublishCounts()
    {
        var fs = R.Findings.Values.ToList();
        bool Human(Finding f) => f.Status is Status.NeedsHuman or Status.SuppressPending or Status.AcceptPending;
        bool Sup(Finding f) => f.Status is Status.Suppressed;
        var triaged = fs.Count(f => f.Status != Status.New);
        Feed.Publish("counts", new
        {
            total = fs.Count, triaged,
            fix = fs.Count(f => !Human(f) && !Sup(f) && f.Status != Status.New && f.Bucket == Buckets.FixNow),
            batch = fs.Count(f => !Human(f) && !Sup(f) && f.Status != Status.New && f.Bucket == Buckets.FixBatch),
            sup = fs.Count(Sup), hum = fs.Count(Human),
        });
    }

    protected void PublishGuards() => Feed.Publish("guards", new
    {
        masked = S.Masker.MaskCount, injections = R.Injections, retries = R.RetriesUsed, max_retries = S.Cfg.Policies.Retries.MaxFixRetries,
        budget_used = R.Budget.Used, budget = R.Budget.Tokens, kill = S.Kill.IsOn,
        max_fixes = R.Limits.MaxFixes, fixes_dispatched = R.FixesDispatched, deferred = R.FixesDeferred, max_minutes = R.Limits.MaxMinutes, time_up = R.Deadline.Expired,
    });

    protected static string Short(string s, int n = 8) => s.Length <= n ? s : s[..n];
    public static string FixerUi(string fixerId) => fixerId switch { "library" => "lib", "secrets" => "secrets", "unsafe_code" => "unsafe", _ => "binary" };
    public static string FixerName(string fixerId) => fixerId switch { "library" => "Library fixer", "secrets" => "Secrets fixer", "unsafe_code" => "Unsafe code fixer", _ => "Binary/Licence fixer" };
    public static string BranchFor(string fixerId, string groupKey) => $"fix/{fixerId.Replace('_', '-')}-{groupKey[..8]}";
}
