using SecAgent.Connectors;
using SecAgent.Core;

namespace SecAgent.Agents.Workflow;

/// <summary>Optional outbound step when a run reaches a resting state: human tasks become issue tracker tickets (idempotent by task id,
/// linked to the scanned PR) and a summary card goes to the notifier. Both connectors are optional per tenant (TryForTenant) and
/// best-effort: a failing tracker or webhook is logged to the feed and never changes the run's outcome.</summary>
public sealed class RunOutbound(AgentServices s)
{
    public async Task PublishOnceAsync(RunState st, CancellationToken ct)
    {
        if (Interlocked.Exchange(ref st.OutboundPublished, 1) == 1) return;
        var c = s.Connectors;
        try
        {
            if (c.IssueTrackers.TryForTenant(st.TenantId, out var tracker)) await FileTasksAsync(st, tracker, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            st.Feed.Entry("orch", $"issue tracker unavailable — human tasks stay in SecAgent only ({s.Masker.Mask(e.Message, false)})", "warn");
        }
        try
        {
            if (c.Notifiers.TryForTenant(st.TenantId, out var notifier)) await notifier.NotifyAsync(Card(st), ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            st.Feed.Entry("orch", $"notifier unavailable — no run card sent ({s.Masker.Mask(e.Message, false)})", "warn");
        }
    }

    async Task FileTasksAsync(RunState st, IIssueTrackerClient tracker, CancellationToken ct)
    {
        foreach (var t in s.Store.TasksForRun(st.Run.RunId))
        {
            var issue = await tracker.CreateIssueAsync(new NewIssue("", s.Masker.Mask($"[SecAgent] {t.Title}", false),
                s.Masker.Mask($"{t.Details}\n\nRepository: {st.Pr.Repo} · PR #{st.Pr.Number} · run {st.Run.RunId} · task {t.TaskId} ({t.Type}) · owner {t.Owner}", false),
                Labels: ["secagent", "secagent-" + t.Type.Replace('_', '-')], ExternalId: t.TaskId.ToString("N")), ct);
            await tracker.LinkPullRequestAsync(issue.Key, new IssueLink(st.Pr.Url, $"{st.Pr.Repo}#{st.Pr.Number}"), ct);
            st.Feed.Entry("orch", $"human task filed as {issue.Key}: {s.Masker.Mask(t.Title, false)}");
        }
    }

    Notification Card(RunState st)
    {
        var status = st.Run.Status;
        var tasks = s.Store.TasksForRun(st.Run.RunId).Count;
        var level = status is "failed" or "stopped_kill_switch" or "stopped_budget" ? NotificationLevel.Critical
            : tasks > 0 ? NotificationLevel.Warning : NotificationLevel.Info;
        var facts = new List<NotificationFact>
        {
            new("Status", status), new("Findings", st.Findings.Count.ToString()), new("Fix PRs opened", st.PrsOpened.ToString()),
            new("Fix PRs reused", st.PrsReused.ToString()), new("Human tasks", tasks.ToString()), new("Tokens", st.Budget.Used.ToString()),
        };
        if (st.StopReason != null) facts.Add(new("Stopped", s.Masker.Mask(st.StopDetail ?? st.StopReason, false)));
        return new Notification($"SecAgent · {st.Pr.Repo} #{st.Pr.Number}", s.Masker.Mask($"Run {status}: {st.Pr.Title}", false), level, facts,
            st.Pr.Url, "Open the PR");
    }
}
