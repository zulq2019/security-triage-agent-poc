using System.Diagnostics;
using System.Text.Json;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Checkpointing;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Repo;
using SecAgent.Core;

namespace SecAgent.Agents.Workflow;

/// <summary>Builds the Agent Framework workflow graph for one run.
/// scanners → orch → triage → router → fixer-* ⇄ verifier → orch → human (RequestPort) → orch.</summary>
public static class WorkflowFactory
{
    public static Microsoft.Agents.AI.Workflows.Workflow Build(AgentServices s, RunState r)
    {
        var scanners = new ScannersExecutor(s, r);
        var orch = new OrchestratorExecutor(s, r);
        var triage = new TriageExecutor(s, r);
        var router = new RouterExecutor(s, r);
        var verifier = new VerifierExecutor(s, r);
        var human = RequestPort.Create<ReviewRequest, ReviewResponse>("human");
        var fixers = s.Fixers.Values.Select(f => new FixerExecutor(s, r, f)).ToList();

        var b = new WorkflowBuilder(scanners).WithName("security-triage-pr").WithDescription("PR mode: scan → triage → route → fix → verify → human review")
            .AddEdge<IngestDone>(scanners, orch, m => m != null)
            .AddEdge<TriageRequest>(orch, triage, m => m != null)
            .AddEdge<TriageDone>(triage, router, m => m != null)
            .AddEdge<RoutePlan>(router, orch, m => m != null)
            .AddEdge<FixClosed>(router, orch, m => m != null, label: "reused")
            .AddEdge<VerifyOutcome>(verifier, orch, m => m != null)
            .AddEdge<ReviewRequest>(orch, human, m => m != null)
            .AddEdge<ReviewResponse>(human, orch, m => m != null);
        foreach (var fx in fixers)
        {
            var fixerId = fx.Id["fixer-".Length..];
            b.AddEdge<FixTask>(router, fx, m => m != null && m.FixerId == fixerId)
             .AddEdge<FixTask>(verifier, fx, m => m != null && m.FixerId == fixerId, label: "retry")
             .AddEdge<FixTask>(fx, fx, m => m != null && m.FixerId == fixerId, label: "fixer-error-retry")
             .AddEdge<FixProduced>(fx, verifier, m => m != null)
             .AddEdge<FixClosed>(fx, orch, m => m != null);
        }
        return b.WithOutputFrom(orch).WithOpenTelemetry().Build();
    }
}

/// <summary>Starts and supervises runs: creates the Run record, executes the workflow with file-system checkpoints,
/// wires the kill switch to cancellation, and records the end state.</summary>
public sealed class RunService(AgentServices s)
{
    public sealed class Handle
    {
        public required RunState State { get; init; }
        public Task Completion { get; set; } = Task.CompletedTask;
        public StreamingRun? Run { get; set; }
        public ExternalRequest? PendingReview { get; set; }
    }
    static readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, Handle> Handles = new();
    public static Handle? Get(Guid id) => Handles.TryGetValue(id, out var h) ? h : null;
    public static bool AnyActive => Handles.Values.Any(h => !h.Completion.IsCompleted && h.PendingReview == null);

    /// <param name="expectedHeadSha">When set, the run starts only if the PR head (on the snapshot this run uses) is that commit;
    /// otherwise <see cref="PrHeadMovedException"/> is thrown and nothing is recorded.</param>
    public async Task<Handle> StartAsync(string repo, int prNumber, bool fresh, bool blockForReview, string? expectedHeadSha = null)
    {
        s.Kill.ThrowIfOn("start run");
        var pr = await GitWorkspace.GetPrAsync(repo, prNumber, CancellationToken.None);
        if (expectedHeadSha != null && !string.Equals(pr.HeadSha, expectedHeadSha, StringComparison.OrdinalIgnoreCase))
            throw new PrHeadMovedException(repo, prNumber, expectedHeadSha, pr.HeadSha);
        var budgetCfg = s.Cfg.Policies.Budgets["pr"];
        var run = new RunRecord
        {
            TriggerType = "pr",
            ScopeJson = JsonSerializer.Serialize(new { repo, pr = prNumber, head_ref = pr.HeadRef, base_ref = pr.BaseRef, head_sha = pr.HeadSha, base_sha = pr.BaseSha, mode = "new_vs_base" }, Schema.Json),
            BudgetJson = JsonSerializer.Serialize(budgetCfg, Schema.Json), ConfigSnapshot = s.Cfg.Label,
        };
        s.Store.InsertRun(run);
        var limits = RunLimits.From(budgetCfg);
        var state = new RunState { Run = run, Pr = pr, Feed = new Feed(s.Bus, run.RunId), Budget = new RunBudget(limits.Tokens, limits.Cost), FreshTriage = fresh, Limits = limits };
        state.Deadline = new RunDeadline(limits.TimeLimit, () => { OnTimeBudgetSpent(state); return Task.CompletedTask; });
        RunRegistry.Add(state);
        var h = new Handle { State = state };
        Handles[run.RunId] = h;
        state.Feed.Publish("run", RunInfo(state, "running"));
        h.Completion = Task.Run(() => ExecuteAsync(h, blockForReview));
        return h;
    }

    /// <summary>max_minutes reached. Runs while holding the push gate (no push / PR creation is half-done), records the stop,
    /// then cancels routing and execution. The last workflow checkpoint stays on disk.</summary>
    void OnTimeBudgetSpent(RunState st)
    {
        lock (st.Lock)
        {
            if (st.StopReason != null || st.Finished || st.Run.Status != "running") return;
            st.StopReason = "budget"; st.StopDetail = $"{RunLimits.MaxMinutesReason} ({st.Limits.MaxMinutes} min)";
        }
        st.Feed.Publish("guards", new { time_up = true, max_minutes = st.Limits.MaxMinutes, max_fixes = st.Limits.MaxFixes, deferred = st.FixesDeferred, event_reason = RunLimits.MaxMinutesReason });
        st.Feed.Entry("orch", $"{RunLimits.MaxMinutesReason}: run hit its {st.Limits.MaxMinutes}-minute time budget — routing and fixing stopped; no push was in flight; last checkpoint kept", "fail", ["fail", "Budget"]);
        st.Cts.Cancel();
    }

    object RunInfo(RunState st, string status) => new
    {
        run_id = st.Run.RunId, status, repo = st.Pr.Repo, pr = st.Pr.Number, title = st.Pr.Title, url = st.Pr.Url, head_ref = st.Pr.HeadRef, base_ref = st.Pr.BaseRef,
        files = st.Pr.FilesChanged, started = st.Run.StartedAt, ended = st.Run.EndedAt, budget = st.Budget.Tokens, used = st.Budget.Used, config = s.Cfg.Label,
        stop = st.StopReason, stop_detail = st.StopDetail, elapsed_s = st.Run.EndedAt != null ? (st.Run.EndedAt.Value - st.Run.StartedAt).TotalSeconds : (double?)null,
        prs = st.PrUrls.Distinct().ToList(), fresh = st.FreshTriage, max_fixes = st.Limits.MaxFixes, max_minutes = st.Limits.MaxMinutes,
    };

    async Task ExecuteAsync(Handle h, bool blockForReview)
    {
        var st = h.State;
        var id = st.Run.RunId;
        using var activity = Telemetry.Source.StartActivity("secagent.run", ActivityKind.Internal);
        activity?.SetTag("secagent.run_id", id.ToString()); activity?.SetTag("secagent.pr", st.Pr.Number);
        st.Run.TraceId = Telemetry.TraceId;
        using var killReg = s.Kill.Token.Register(() => { st.StopReason ??= "kill_switch"; st.StopDetail ??= "kill switch turned on"; st.Cts.Cancel(); });
        var sw = Stopwatch.StartNew();
        int checkpoints = 0;
        try
        {
            var workflow = WorkflowFactory.Build(s, st);
            var dir = Directory.CreateDirectory(Path.Combine(s.DataRoot, "checkpoints", id.ToString("N")));
            using var store = new FileSystemJsonCheckpointStore(dir);
            var cpm = CheckpointManager.CreateJson(store, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            await using var run = await InProcessExecution.RunStreamingAsync(workflow, new RunRequest(id), cpm, id.ToString("N"), CancellationToken.None);
            h.Run = run;
            using var cancelReg = st.Token.Register(() => { _ = run.CancelRunAsync().AsTask(); });
            await foreach (var evt in run.WatchStreamAsync(blockForReview, st.Token))
            {
                switch (evt)
                {
                    case RequestInfoEvent req:
                        h.PendingReview = req.Request;
                        Finish(st, "awaiting_human_review", sw.Elapsed, checkpoints);
                        if (!blockForReview) goto done;
                        break;
                    case SuperStepCompletedEvent ss when ss.CompletionInfo?.Checkpoint != null:
                        checkpoints++;
                        st.Feed.Publish("checkpoint", new { n = checkpoints, id = ss.CompletionInfo.Checkpoint.CheckpointId, executors = ss.CompletionInfo.ActivatedExecutors });
                        break;
                    case ExecutorFailedEvent f:
                        st.StopReason ??= "error"; st.StopDetail ??= $"{f.ExecutorId}: {s.Masker.Mask(f.Data?.Message, false)}";
                        st.Cts.Cancel();
                        break;
                    case WorkflowErrorEvent we:
                        st.StopReason ??= "error"; st.StopDetail ??= s.Masker.Mask(we.Exception?.Message, false);
                        st.Cts.Cancel();
                        break;
                    case WorkflowOutputEvent o:
                        Finish(st, "review_recorded", sw.Elapsed, checkpoints);
                        break;
                }
            }
            done:;
        }
        catch (OperationCanceledException) { }
        catch (Exception e)
        {
            st.StopReason ??= "error"; st.StopDetail ??= s.Masker.Mask(e.Message, false);
        }
        if (st.StopReason != null)
        {
            var status = st.StopReason switch { "kill_switch" => "stopped_kill_switch", "budget" => "stopped_budget", _ => "failed" };
            if (st.StopReason == "kill_switch")
            {
                foreach (var a in new[] { "scanners", "orch", "triage", "router", "lib", "secrets", "unsafe", "binary", "verifier" })
                    st.Feed.Agent(a, "stopped", "Stopped · kill switch");
                st.Feed.Entry("orch", "Run stopped by kill switch — no further tool or model calls; nothing was pushed after the switch", "fail", ["fail", "Killed"]);
            }
            Finish(st, status, sw.Elapsed, checkpoints);
        }
        else if (st.Run.Status == "running") Finish(st, "completed", sw.Elapsed, checkpoints);
        if (st.Run.Status != "awaiting_human_review") st.Deadline.Dispose();
    }

    void Finish(RunState st, string status, TimeSpan elapsed, int checkpoints)
    {
        st.Run.Status = status;
        st.Run.EndedAt ??= DateTime.UtcNow;
        st.Run.Tokens = st.Budget.Used; st.Run.Cost = st.Budget.CostUsed;
        var fs = st.Findings.Values.ToList();
        st.Run.SummaryJson = JsonSerializer.Serialize(new
        {
            elapsed_s = Math.Round((st.Run.EndedAt.Value - st.Run.StartedAt).TotalSeconds, 1), checkpoints, findings = fs.Count, backlog = st.BaseOnly.Count,
            statuses = fs.GroupBy(f => f.Status).ToDictionary(g => g.Key, g => g.Count()), prs_opened = st.PrsOpened, prs_reused = st.PrsReused,
            pr_urls = st.PrUrls.Distinct(), retries = st.RetriesUsed, injections = st.Injections, masked = s.Masker.MaskCount, tokens = st.Budget.Used,
            agent_tokens = st.AgentTokens, stop = st.StopReason, stop_detail = st.StopDetail,
            limits = new { max_fixes = st.Limits.MaxFixes, max_minutes = st.Limits.MaxMinutes, fixes_dispatched = st.FixesDispatched, fixes_deferred = st.FixesDeferred },
        }, Schema.Json);
        s.Store.UpdateRun(st.Run);
        st.Feed.Publish("run", RunInfo(st, status switch { "awaiting_human_review" => "waiting", _ => status }));
    }

    public async Task<bool> RecordReviewAsync(Guid runId, string decision)
    {
        var h = Get(runId);
        if (h?.Run == null || h.PendingReview == null) return false;
        var req = h.PendingReview; h.PendingReview = null;
        await h.Run.SendResponseAsync(req.CreateResponse(new ReviewResponse(runId, decision)));
        return true;
    }
}

/// <summary>The PR head is no longer the commit a run was requested for (a newer push arrived in between).</summary>
public sealed class PrHeadMovedException(string repo, int prNumber, string expectedHeadSha, string currentHeadSha)
    : Exception($"{repo} PR #{prNumber} head moved from {expectedHeadSha[..Math.Min(7, expectedHeadSha.Length)]} to {currentHeadSha[..Math.Min(7, currentHeadSha.Length)]}")
{
    public string ExpectedHeadSha { get; } = expectedHeadSha;
    public string CurrentHeadSha { get; } = currentHeadSha;
}
