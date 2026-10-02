using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Agents.AI.Workflows;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Repo;
using SecAgent.Agents.Scanners;
using SecAgent.Core;

namespace SecAgent.Agents.Workflow;

public sealed record FindingBatch(string Label, string Scanner, List<Finding> Findings);

// ============================================================ Scanners ============================================================
/// <summary>Clones the PR (head + base worktree), runs every registered scanner adapter on both, and publishes normalised
/// batches to the "findings" queue (Service Bus stand-in; MessageId = run:label:scanner:hash for duplicate detection).</summary>
public sealed class ScannersExecutor(AgentServices s, RunState r) : StepBase("scanners", s, r)
{
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb.AddHandler<RunRequest>(HandleAsync)).SendsMessage<IngestDone>();

    async ValueTask HandleAsync(RunRequest m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("scanners", async () =>
    {
        var pr = R.Pr;
        await StatusAsync(ctx, "scanners", "running", "Scanners running…");
        var e = Feed.Entry("scanners", $"checking out PR #{pr.Number} {pr.HeadRef} → {pr.BaseRef} · {pr.FilesChanged} files changed");
        var (head, baseDir) = await S.Tools.RunAsync("scanners", "git.clone", $"{pr.Repo} head {Short(pr.HeadSha)} + base {Short(pr.BaseSha)} worktree", Feed, e,
            () => S.Git.PrepareAsync(RunId, pr, Ct), Ct);
        R.HeadDir = head; R.BaseDir = baseDir;

        var e2 = Feed.Entry("scanners", $"running {S.Scanners.Adapters.Count} scanners on PR head and base (scope: new vs base)");
        var headT = new ScanTarget(RunId, "head", head, pr.Repo, pr.HeadRef, pr.HeadSha, pr.Number);
        var baseT = new ScanTarget(RunId, "base", baseDir, pr.Repo, pr.BaseRef, pr.BaseSha, null);
        var hs = ScanWithFeed(headT, e2);
        var bs = ScanWithFeed(baseT, e2);
        var sets = await Task.WhenAll(hs, bs);
        int published = 0;
        foreach (var (label, set) in new[] { ("head", sets[0]), ("base", sets[1]) })
            foreach (var g in set.Findings.GroupBy(f => f.SourceScanner))
            {
                var list = g.ToList();
                var hash = Hashing.Sha256(string.Join(",", list.Select(f => f.Fingerprint).Order()))[..12];
                await S.Tools.RunAsync("scanners", "queue.publish", $"findings ← {label}/{g.Key} ({list.Count})", null, null, () =>
                    Task.FromResult(S.Queue.Publish("findings", $"{RunId}:{label}:{g.Key}:{hash}", new FindingBatch(label, g.Key, list))), Ct);
                published++;
            }
        Feed.Detail(e2, new { type = "evid", text = $"Raw scanner output stored (write-once, hashed) and normalised to canonical Finding v{Schema.Version} (SARIF 2.1.0): {sets[0].SarifUri}" });
        await StatusAsync(ctx, "scanners", "done", $"{sets[0].Findings.Count} findings on head · {S.Scanners.Adapters.Count} scanners");
        await ctx.SendMessageAsync(new IngestDone(RunId, sets[0].Findings.Count, sets[1].Findings.Count), "orch");
    });

    Task<ScanSet> ScanWithFeed(ScanTarget t, string entry)
    {
        var ids = new ConcurrentDictionary<string, string>();
        return S.Scanners.ScanAsync(t, Ct,
            (id, label) => ids[id] = Feed.ToolStart(entry, "scan." + id, $"{label} {Short(t.CommitSha)}"),
            (id, raw, n) => Feed.ToolEnd(entry, ids[id], "scan." + id, $"{t.Label} {Short(t.CommitSha)} · {n} finding{(n == 1 ? "" : "s")} · v{raw.ScannerVersion}", true, raw.ElapsedMs));
    }
}

// ============================================================ Orchestrator ============================================================
/// <summary>Normalise/dedupe/PR-scope, then (after fixes) push branches and open fix PRs idempotently, then hand to human review.</summary>
public sealed class OrchestratorExecutor(AgentServices s, RunState r) : StepBase("orch", s, r)
{
    bool _planReceived, _reviewRequested;

    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb
                .AddHandler<IngestDone>(OnIngestAsync)
                .AddHandler<RoutePlan>(OnPlanAsync)
                .AddHandler<VerifyOutcome>(OnVerifiedAsync)
                .AddHandler<FixClosed>(OnClosedAsync)
                .AddHandler<ReviewResponse>(OnReviewAsync))
          .SendsMessage<TriageRequest>().SendsMessage<ReviewRequest>().YieldsOutput<string>();

    protected override ValueTask OnCheckpointingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        context.QueueStateUpdateAsync("groups", R.Groups.Values.Select(g => new { g.Key, g.FixerId, g.Outcome, g.PrUrl }).ToList(), cancellationToken: cancellationToken);

    async ValueTask OnIngestAsync(IngestDone m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("orch", async () =>
    {
        await StatusAsync(ctx, "orch", "running", "Orchestrator planning…");
        var e = Feed.Entry("orch", $"planning run: {m.RawFindings} raw findings on head");
        var batches = await S.Tools.RunAsync("orchestrator", "queue.receive", "findings (Service Bus stand-in)", Feed, e, () =>
        {
            var list = new List<FindingBatch>();
            while (S.Queue.TryReceive("findings", out var qm)) { list.Add(qm!.As<FindingBatch>()); S.Queue.Complete(qm!); }
            return Task.FromResult(list);
        }, Ct);
        var head = batches.Where(b => b.Label == "head").SelectMany(b => b.Findings).ToList();
        var baseFps = batches.Where(b => b.Label == "base").SelectMany(b => b.Findings).Select(f => f.Fingerprint).ToHashSet();
        var unique = head.GroupBy(f => f.Fingerprint).Select(g =>
        {
            var first = g.First();
            first.OtherLocations = first.OtherLocations.Concat(g.Skip(1).Select(x => $"{x.FilePath}:{x.LineStart}")).Distinct().ToList();
            first.OccurrenceCount = g.Count();
            return first;
        }).ToList();
        var dupes = head.Count - unique.Count;
        R.HeadFingerprints = unique.Select(f => f.Fingerprint).ToHashSet();
        R.BaseFingerprints = baseFps;
        var inScope = unique.Where(f => !baseFps.Contains(f.Fingerprint)).ToList();
        var pre = unique.Where(f => baseFps.Contains(f.Fingerprint)).ToList();
        var stored = await S.Tools.RunAsync("orchestrator", "finding.upsert", $"dedupe by fingerprint · {unique.Count} unique · PR scope new-vs-base", Feed, e, () =>
        {
            var res = new List<(Finding, bool)>();
            foreach (var f in inScope) res.Add(S.Store.UpsertFinding(f, RunId));
            foreach (var f in pre) { f.Attributes["scope"] = "backlog (pre-existing on base)"; S.Store.UpsertFinding(f, RunId); }
            return Task.FromResult(res);
        }, Ct);
        foreach (var (f, _) in stored) R.Findings[f.FindingId] = f;
        R.BaseOnly = pre;
        var ordered = stored.Select(x => x.Item1).OrderByDescending(f => Schema.Rank(f.SeverityScanner)).ThenBy(f => f.IssueType).ToList();
        await S.Tools.RunAsync("orchestrator", "run.plan", $"triage {ordered.Count} · fixers=registry · max_retries={S.Cfg.Policies.Retries.MaxFixRetries} · budget {R.Budget.Tokens / 1000}k tok", Feed, e, () => Task.FromResult(true), Ct);
        var reused = stored.Count(x => !x.Item2);
        Feed.Update(e, "orch", $"planning run: {unique.Count} unique findings ({dupes} duplicate folded) · {inScope.Count} new in this PR · {pre.Count} pre-existing on {R.Pr.BaseRef} → backlog" +
            (reused > 0 ? $" · {reused} already known (dedupe by fingerprint)" : ""));
        if (pre.Count > 0)
            Feed.Detail(e, new { type = "evid", text = "Out of PR scope (already on base, left for backlog sweep): " + string.Join("; ", pre.Select(f => $"{string.Join(",", f.CveIds)} {f.ComponentName} {f.ComponentVersion} ({f.SeverityScanner})".Trim())) });
        Feed.Publish("scope", new { total = ordered.Count, backlog = pre.Count });
        PublishCounts();
        await StatusAsync(ctx, "orch", "done", $"Plan · {ordered.Count} to triage · {pre.Count} backlog");
        await ctx.SendMessageAsync(new TriageRequest(RunId, ordered.Select(f => f.FindingId).ToList()), "triage");
    });

    async ValueTask OnPlanAsync(RoutePlan m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("orch", async () =>
    {
        _planReceived = true;
        await MaybeFinishAsync(ctx);
    });

    async ValueTask OnClosedAsync(FixClosed m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("orch", async () =>
    {
        if (R.Groups.TryGetValue(m.GroupKey, out var g) && g.Outcome == "pending") g.Outcome = m.Outcome;
        if (m.Outcome == "pr_reused" && m.PrUrl != null) lock (R.Lock) R.PrUrls.Add(m.PrUrl);
        await MaybeFinishAsync(ctx);
    });

    async ValueTask OnVerifiedAsync(VerifyOutcome m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("orch", async () =>
    {
        var g = R.Groups[m.GroupKey];
        if (!m.Passed) { g.Outcome = "needs_human"; await MaybeFinishAsync(ctx); return; }
        await StatusAsync(ctx, "orch", "running", "Orchestrator opening PRs…");
        await OpenPrAsync(m, g);
        await MaybeFinishAsync(ctx);
    });

    async Task OpenPrAsync(VerifyOutcome m, GroupInfo g)
    {
        var fix = R.Fixes[m.FixId];
        var findings = m.FindingIds.Select(id => R.Findings[id]).ToList();
        var key = $"fix:{g.Key}:pr";
        if (R.Pr.IsFork)
        {
            // The PR head branch lives in the contributor's fork, so a fix PR cannot target it from the base repository and
            // pushing a branch here would leave an orphan. Keep the verified fix local and hand it to a human instead.
            Feed.Entry("orch", $"PR #{R.Pr.Number} comes from fork {R.Pr.HeadRepo}: verified fix on {m.Branch} kept local (no push) → human", "warn", ["inj", "Needs human"]);
            S.Store.InsertTask(new HumanTask { RunId = RunId, Type = "fork_pr_fix", Title = $"Apply verified fix for {TriageExecutor.Label(findings[0])} in fork {R.Pr.HeadRepo}",
                Details = $"Fix commit {Short(fix.CommitSha ?? "")} on local branch {m.Branch} passed verification. The PR head ({R.Pr.HeadRef}) is in {R.Pr.HeadRepo}; ask the contributor to apply it.",
                FindingIds = m.FindingIds, Owner = "[owner team]" });
            g.Outcome = "needs_human";
            return;
        }
        var e = Feed.Entry("orch", $"opening fix PR for {FixerName(m.FixerId)} · {m.Branch}");
        var taken = S.Store.TryTake(key, "pr", TimeSpan.FromMinutes(30));
        GitHubPrs.Pr? pr = null;
        if (taken is { Status: "completed" })
        {
            pr = await S.Tools.RunAsync("orchestrator", "github.find_pr", $"head={m.Branch} (ledger hit {key[..20]}…)", Feed, e, () => GitHubPrs.FindByHeadAsync(R.Pr.Repo, m.Branch, Ct), Ct);
        }
        else if (taken != null)
        {
            Feed.Update(e, "orch", $"PR creation for {m.Branch} already in progress elsewhere (ledger) · skipped", "warn");
            g.Outcome = "pr_reused"; return;
        }
        pr ??= await S.Tools.RunAsync("orchestrator", "github.find_pr", $"head={m.Branch} state=all", Feed, e, () => GitHubPrs.FindByHeadAsync(R.Pr.Repo, m.Branch, Ct), Ct);
        var reused = pr is { State: "OPEN" };
        var branch = m.Branch;
        try
        {
            if (!reused)
            {
                // A remote branch without an open PR (e.g. an earlier crashed run) is never overwritten: push under a run-suffixed name instead.
                if (await GitWorkspace.RemoteBranchExistsAsync(m.Worktree, branch, Ct)) branch = $"{m.Branch}-r{Short(RunId.ToString("N"))}";
                await S.Tools.RunAsync("orchestrator", "git.push", $"origin {branch} (no force)", Feed, e, () => GitWorkspace.PushAsync(m.Worktree, m.Branch, Ct, branch), Ct);
                var title = PrTitle(m.FixerId, findings, fix);
                var body = PrBody(m, g, findings, fix);
                pr = await S.Tools.RunAsync("orchestrator", "github.create_pr", $"base={R.Pr.HeadRef} · head={branch}", Feed, e,
                    () => GitHubPrs.CreateAsync(R.Pr.Repo, R.Pr.HeadRef, branch, title, S.Masker.Mask(body, false), Ct), Ct);
            }
            S.Store.LedgerComplete(key, pr!.Url);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not KillSwitchEngagedException)
        {
            S.Store.LedgerFail(key, ex.Message);
            throw;
        }
        fix.PrUrl = pr!.Url; fix.UpdatedAt = DateTime.UtcNow; S.Store.UpdateFix(fix);
        g.PrUrl = pr.Url; g.PrNumber = pr.Number; g.Outcome = reused ? "pr_reused" : "pr_opened";
        lock (R.Lock) { R.PrUrls.Add(pr.Url); if (reused) R.PrsReused++; else R.PrsOpened++; }
        Feed.Update(e, "orch", reused ? $"Fix PR #{pr.Number} already open for {m.Branch} · reused (idempotent, no duplicate)" : $"Opened fix PR #{pr.Number} · awaiting human review",
            null, ["pr", $"PR #{pr.Number}"]);
        Feed.Detail(e, new { type = "pr", num = pr.Number, url = pr.Url, title = pr.Title });
        Feed.Publish("pr", new { num = pr.Number, url = pr.Url, title = pr.Title, add = fix.Additions, del = fix.Deletions, files = fix.FilesChanged, status = "Awaiting review", reused, verified = true });
        PublishFixerDone(m.FixerId);
    }

    /// <summary>When every group of a fixer has an outcome, show the fixer as done with its PR numbers.</summary>
    void PublishFixerDone(string fixerId)
    {
        var mine = R.Groups.Values.Where(x => x.FixerId == fixerId).ToList();
        if (mine.Any(x => x.Outcome == "pending")) return;
        var prs = mine.Where(x => x.PrNumber != null).Select(x => $"#{x.PrNumber}").ToList();
        var human = mine.Count(x => x.Outcome == "needs_human");
        if (prs.Count == 0) return;
        Feed.Agent(FixerUi(fixerId), "done", $"Verified · PR {string.Join(", ", prs)}" + (human > 0 ? $" · {human} to human" : ""), R.AgentTokens.GetValueOrDefault(FixerUi(fixerId)));
    }

    string PrTitle(string fixerId, List<Finding> fs, FixAttempt fix)
    {
        var f = fs[0];
        return fixerId switch
        {
            "library" => $"fix(security): bump {f.Attributes.GetValueOrDefault("package")} {f.ComponentVersion} → {FixNote(fix, "to")} ({string.Join(", ", fs.SelectMany(x => x.CveIds).Distinct())})",
            "secrets" => $"fix(security): move leaked {f.ScannerRuleId} in {Path.GetFileName(f.FilePath)} to a Key Vault reference",
            "unsafe_code" => $"fix(security): parameterise SQL in {f.Attributes.GetValueOrDefault("enclosing_symbol")} ({string.Join(",", f.CweIds)})",
            _ => $"fix(security): remove committed binary {f.FilePath}",
        };
    }

    string FixNote(FixAttempt fix, string k) => _notes.TryGetValue(fix.FixId, out var n) ? n.GetValueOrDefault(k, "") : "";
    static readonly ConcurrentDictionary<Guid, Dictionary<string, string>> _notes = new();
    public static void RememberNotes(Guid fixId, Dictionary<string, string> notes) => _notes[fixId] = notes;

    string PrBody(VerifyOutcome m, GroupInfo g, List<Finding> fs, FixAttempt fix)
    {
        var sb = new StringBuilder();
        var sum = R.Summaries.TryGetValue(g.Key, out var c) ? c.Json : default;
        string J(string p) => sum.ValueKind == JsonValueKind.Object && sum.TryGetProperty(p, out var v) ? v.GetString() ?? "" : "";
        sb.AppendLine("> Opened by the **Security Triage & Fix Agent (POC, slice 1)**. Agents have no merge rights: a human must review and merge. Synthetic sample code only.");
        sb.AppendLine();
        sb.AppendLine("## What was wrong");
        sb.AppendLine(J("what_was_wrong"));
        sb.AppendLine();
        foreach (var f in fs)
            sb.AppendLine($"- **{f.Title}** · `{f.SourceScanner}` rule `{f.ScannerRuleId}` · scanner severity **{f.SeverityScanner}**, effective **{f.SeverityEffective}** · {(f.FilePath != null ? $"`{f.FilePath}`" : $"`{f.ComponentName} {f.ComponentVersion}`")} · fingerprint `{f.Short}`{(f.InjectionFlag ? " · ⚠ prompt-injection text found near this finding (treated as data)" : "")}");
        sb.AppendLine();
        sb.AppendLine("## What changed");
        sb.AppendLine(J("what_changed"));
        sb.AppendLine();
        sb.AppendLine($"- Fixer `{fix.FixerVersion}`, attempt {fix.AttemptNo} · +{fix.Additions} −{fix.Deletions} in {fix.FilesChanged} file(s) · commit `{Short(fix.CommitSha ?? "")}`");
        if (_notes.TryGetValue(fix.FixId, out var notes))
            foreach (var (k, v) in notes.Where(kv => kv.Key is "reviewer_note" or "risk" or "explanation" or "rotation_note" or "artefact_feed" or "references" && kv.Value.Length > 0))
                sb.AppendLine($"- {k.Replace('_', ' ')}: {v}");
        sb.AppendLine($"- Risk (model): {J("risk")}");
        sb.AppendLine();
        sb.AppendLine("## Evidence");
        sb.AppendLine(m.Details);
        sb.AppendLine();
        sb.AppendLine("## Triage provenance");
        foreach (var f in fs)
        {
            var d = S.Store.LatestDecision(f.FindingId);
            if (d != null) sb.AppendLine($"- `{f.Short}` decision **{d.Decision}** (confidence {d.Confidence:0.00}) by `{d.ModelId}` · prompt `{d.PromptVersion}` · rule pack `{d.RulePackVersion}` · context pack `{d.ContextPackId?.ToString()[..8]}` · route `{d.RoutingId?.ToString()[..8]}` — {d.Reason}");
        }
        var tasks = fs.SelectMany(f => S.Store.TasksForFinding(f.FindingId)).ToList();
        if (tasks.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Human actions required");
            foreach (var t in tasks) sb.AppendLine($"- [ ] **{t.Type}** · {t.Title} (owner: {t.Owner})");
        }
        sb.AppendLine();
        sb.AppendLine($"<sub>Run `{RunId}` · config `{S.Cfg.Label}` · trace `{R.Run.TraceId}` · idempotency key `fix:{g.Key[..16]}…:pr` · branch `{m.Branch}` targets `{R.Pr.HeadRef}` (PR #{R.Pr.Number}).</sub>");
        return sb.ToString();
    }

    async Task MaybeFinishAsync(IWorkflowContext ctx)
    {
        if (!_planReceived || _reviewRequested || R.Groups.Values.Any(g => g.Outcome == "pending")) return;
        _reviewRequested = true;
        var tasks = S.Store.TasksForRun(RunId);
        var prs = R.Groups.Values.Where(g => g.PrUrl != null).Select(g => g.PrNumber).Where(n => n != null).Distinct().ToList();
        var allPrUrls = R.PrUrls.Distinct().ToList();
        await StatusAsync(ctx, "orch", "done", $"Plan · {R.PrsOpened} PR{(R.PrsOpened == 1 ? "" : "s")} opened{(R.PrsReused > 0 ? $" · {R.PrsReused} reused" : "")}");
        await StatusAsync(ctx, "human", "waiting", "Waiting for review");
        var human = R.Findings.Values.Count(f => f.Status is Status.NeedsHuman or Status.SuppressPending or Status.AcceptPending);
        var e = Feed.Entry("human", $"Run paused — {allPrUrls.Count} fix PR{(allPrUrls.Count == 1 ? "" : "s")} + {tasks.Count} human task{(tasks.Count == 1 ? "" : "s")} waiting for review" +
            (human > 0 ? $" · {human} finding{(human == 1 ? "" : "s")} need a human decision" : ""), "final", ["inj", "Needs human"]);
        Feed.Detail(e, new
        {
            type = "evid",
            text = "Agents have no merge rights. Nothing ships until a human approves " + (prs.Count > 0 ? string.Join(", ", prs.Select(n => "#" + n)) : "the findings") +
                   (tasks.Count > 0 ? " and completes: " + string.Join("; ", tasks.Select(t => $"{t.Type} — {t.Title}")) : "") + ".",
        });
        Feed.Publish("tasks", tasks.Select(t => new { t.Type, t.Title, t.Owner }).ToList());
        await ctx.SendMessageAsync(new ReviewRequest(RunId, $"{allPrUrls.Count} PRs, {tasks.Count} tasks", allPrUrls, tasks.Count), "human");
    }

    async ValueTask OnReviewAsync(ReviewResponse m, IWorkflowContext ctx, CancellationToken _)
    {
        await StatusAsync(ctx, "human", "done", $"Review recorded: {m.Decision}");
        Feed.Entry("human", $"human review recorded in the run: \"{m.Decision}\" (merges still happen on GitHub, by a human)", "ok");
        await ctx.YieldOutputAsync($"review:{m.Decision}");
    }
}

// ============================================================ Triage ============================================================
public sealed class TriageExecutor(AgentServices s, RunState r) : StepBase("triage", s, r)
{
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb.AddHandler<TriageRequest>(HandleAsync)).SendsMessage<TriageDone>();

    async ValueTask HandleAsync(TriageRequest m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("triage", async () =>
    {
        await StatusAsync(ctx, "triage", "running", "Triage running…");
        var fix = new List<Guid>();
        int real = 0, noise = 0, human = 0, i = 0;
        foreach (var id in m.FindingIds)
        {
            Ct.ThrowIfCancellationRequested();
            var f = R.Findings[id];
            i++;
            Feed.Agent("triage", "running", $"Triage running… {i}/{m.FindingIds.Count}", R.AgentTokens.GetValueOrDefault("triage"));
            var outcome = await TriageOneAsync(f);
            switch (outcome) { case "fix": real++; fix.Add(id); break; case "suppressed": noise++; break; default: human++; break; }
            PublishCounts();
        }
        await StatusAsync(ctx, "triage", "done", $"{real} real · {noise} noise · {human} human");
        await ctx.SendMessageAsync(new TriageDone(RunId, fix), "router");
    });

    public static string Label(Finding f) => f.IssueType switch
    {
        IssueTypes.VulnerableDependency => $"{string.Join(",", f.CveIds)} in {f.ComponentName?.Split('/').Last()} {f.ComponentVersion}",
        IssueTypes.Secret => $"{f.ScannerRuleId} in {f.FilePath}",
        IssueTypes.UnsafeCode => $"{(f.CweIds.Contains("CWE-89") ? "SQL injection" : f.ScannerRuleId)} in {Path.GetFileName(f.FilePath)}:{f.LineStart} ({f.Attributes.GetValueOrDefault("enclosing_symbol")})",
        IssueTypes.BinaryArtefact => $"committed binary {f.FilePath}",
        IssueTypes.Licence => $"{f.LicenceId} code vendored in {f.ComponentName?.Replace("file:", "")}",
        _ => f.Title,
    };

    static readonly string[][] SevFlag = [["info", "Info"], ["low", "Low"], ["med", "Medium"], ["high", "High"], ["crit", "Critical"]];

    /// <summary>Usage row for a triage decision reused without a model call (cache_hit = 1, zero tokens). Never fails the step.</summary>
    void UsageCacheHit(TriageDecision? prev, string detail)
    {
        try
        {
            S.Store.InsertUsage(new ModelUsage
            {
                RunId = RunId, Repo = R.Pr.Repo, PrNumber = R.Pr.Number, Mode = R.Run.TriggerType, AgentId = "triage-agent", TaskPurpose = "triage",
                Tier = S.Cfg.Gateway.TaskTiers.GetValueOrDefault("triage", "small"), ModelId = prev?.ModelId ?? "unknown", ModelVersion = prev?.ModelVersion ?? "",
                Deployment = "cache", Provider = UsageMath.ProviderOf(S.Cfg.Gateway), PriceSource = UsageMath.ProviderOf(S.Cfg.Gateway) == "ollama" ? "local" : "none",
                Outcome = "ok", OutcomeDetail = detail, CacheHit = true, TraceId = Telemetry.TraceId,
            });
        }
        catch { /* observability only */ }
    }

    async Task<string> TriageOneAsync(Finding f)
    {
        var rp = S.Cfg.RulePackFor(f.IssueType);
        var prompt = S.Cfg.Prompts["triage"];
        var label = Label(f);
        if (f.Status is not (Status.New or Status.Reopened))
        {
            var prev = S.Store.LatestDecision(f.FindingId);
            var e0 = Feed.Entry("triage", $"{label} → already {f.Status} · decision \"{prev?.Decision}\" reused (idempotent re-run)", null, ["noise", "Known"]);
            Feed.Detail(e0, new { type = "evid", text = $"Fingerprint {f.Short} already tracked since {f.FirstSeen:u}; prior decision by {prev?.ModelId} ({prev?.PromptVersion}, {prev?.RulePackVersion}): {prev?.Reason}" });
            UsageCacheHit(prev, "already_triaged");
            return f.Status is Status.Suppressed ? "suppressed" : f.Status is Status.NeedsHuman or Status.SuppressPending or Status.AcceptPending ? "human" : "fix";
        }
        var key = Hashing.Sha256($"{f.Fingerprint}|{rp.Ref}|{prompt.Ref}");
        var hints = SuppressionHints(f, rp);
        f.Attributes["rule_hints"] = hints.Count > 0 ? string.Join("; ", hints.Select(h => h.Text)) : "no suppression rule matched";
        var e = Feed.Entry("triage", $"triaging {label}…");
        var snippet = await S.Tools.RunAsync("triage-agent", "code.snippet", SnippetDisplay(f), Feed, e, () => Task.FromResult(Snippet(f)), Ct);
        var cached = R.FreshTriage ? null : S.Store.DecisionByKey(key);
        string decision, sev, reason; double conf; LlmCall? call = null; string proposed;
        if (cached != null)
        {
            (decision, sev, reason, conf, proposed) = (cached.Decision, cached.SeverityEffective, cached.Reason, cached.Confidence, cached.ProposedDecision ?? cached.Decision);
            UsageCacheHit(cached, "decision_reused");
        }
        else
        {
            var prior = S.Store.LatestDecision(f.FindingId);
            var comps = new List<ComponentInput>
            {
                new("finding", $"finding:{f.FindingId}", LlmStep.FindingJson(f)),
                new("rule_pack", $"rule-packs/{rp.Id}@{rp.Version}", RulePackText(f, rp)),
                new("code_snippet", f.CodeSnippetRef ?? $"file:{f.FilePath ?? f.ComponentName}", snippet),
                new("tool_output", "suppression-rule-check", "Suppression rule check: " + f.Attributes["rule_hints"]),
                new("run_summary", $"run:{RunId}", ContextBuilder.RunSummary("pr", $"PR #{R.Pr.Number} {R.Pr.Repo} (new vs base)", R.Findings.Values, R.Budget.Remaining)),
            };
            if (prior != null) comps.Add(new("prior_decision", $"decision:{prior.DecisionId}", $"{prior.Decision} ({prior.SeverityEffective}, {prior.Confidence:0.00}): {prior.Reason}"));
            call = await LlmStep.RunAsync(S, R, "triage-agent", "triage", e, f.FindingId, null, comps, new CallSpec("triage", "triage-output", f.SeverityScanner, 1), Ct);
            proposed = Str(call.Json, "decision");
            sev = Str(call.Json, "severity_effective");
            reason = S.Masker.Mask(Str(call.Json, "reason"), false);
            conf = call.Json.TryGetProperty("confidence", out var c) ? c.GetDouble() : 0;
            decision = proposed;
            if (call.Injections.Count > 0) Injection(f, call.Injections);
        }

        // ---------------- policy layer (deterministic; the model only proposes) ----------------
        var notes = new List<string>();
        if (cached == null)
        {
            if (f.IssueType == IssueTypes.Secret && S.Cfg.Policies.Authority.NeverLowerSecretSeverity && Schema.Rank(sev) < Schema.Rank(f.SeverityScanner))
            { notes.Add($"secret severity not lowered below scanner severity ({sev} → {f.SeverityScanner})"); sev = f.SeverityScanner; }
            var thresholds = S.Cfg.Policies.Thresholds;
            // AppSec-approved rules are written against the scanner's normalised severity; a model-raised severity does not un-match them.
            var ruleSev = f.SeverityScanner;
            var ruleOk = hints.Count > 0 && Schema.Rank(ruleSev) <= Schema.Rank(hints.Min(h => h.MaxSeverity) ?? "info") && S.Cfg.Policies.Authority.AgentMaySuppress.Contains(ruleSev);
            if (ruleOk && proposed != "suppress" && Schema.Rank(sev) > Schema.Rank(ruleSev))
            { notes.Add($"model raised severity {ruleSev} → {sev} without rule evidence; rule evaluated at scanner severity"); sev = ruleSev; }
            decision = proposed switch
            {
                not "suppress" when ruleOk => Note(notes, "suppress", $"AppSec-approved suppression rule matched with evidence (model proposed '{proposed}') → suppressed by rule pack {rp.Ref}"),
                "fix" => "fix",
                "suppress" when hints.Count == 0 => Note(notes, "needs_human", "agent proposed suppress but no suppression rule matched (no evidence) → human"),
                "suppress" when Schema.Rank(sev) > Schema.Rank(hints.Min(h => h.MaxSeverity) ?? "info") || !S.Cfg.Policies.Authority.AgentMaySuppress.Contains(sev)
                    => Note(notes, "suppress_pending", $"suppress of a {sev} finding needs AppSec sign-off"),
                "suppress" => "suppress",
                "accept" => Note(notes, "accept_pending", "risk acceptance needs a named human approver"),
                _ => Note(notes, "needs_human", "model escalated"),
            };
            if (conf < thresholds.ConfidenceMin && decision is "fix" or "suppress")
                decision = Note(notes, "needs_human", $"confidence {conf:0.00} < {thresholds.ConfidenceMin:0.00}");
        }
        var bucket = decision switch { "suppress" => Buckets.Suppress, "accept_pending" => Buckets.AcceptDefer, _ => rp.BucketFor(sev) };
        f.SeverityEffective = sev; f.Bucket = bucket;
        S.Store.SetTriageFields(f.FindingId, sev, bucket);
        var d = new TriageDecision
        {
            FindingId = f.FindingId, FixGroupKey = f.FixGroupKey, Decision = decision, ProposedDecision = proposed, Bucket = bucket, SeverityEffective = sev,
            Reason = reason, Confidence = conf, ModelId = call?.Routing.ChosenModelId ?? cached!.ModelId, ModelVersion = call?.Routing.ModelVersion ?? cached!.ModelVersion,
            PromptVersion = prompt.Ref, RulePackVersion = rp.Ref, NeedsHuman = decision is not ("fix" or "suppress"), TraceId = Telemetry.TraceId,
            ContextPackId = call?.Pack.ContextPackId ?? cached!.ContextPackId, RoutingId = call?.Routing.RoutingId ?? cached!.RoutingId, IdempotencyKey = key,
            PolicyNotes = notes.Count > 0 ? string.Join("; ", notes) : cached?.PolicyNotes, RunId = RunId,
        };
        S.Store.InsertDecision(d);
        Move(f, Status.Triaged, "triage", "triage-agent");
        var to = decision switch
        {
            "suppress" => Status.Suppressed, "suppress_pending" => Status.SuppressPending, "accept_pending" => Status.AcceptPending,
            "needs_human" => Status.NeedsHuman, _ => (string?)null,
        };
        if (to != null) Move(f, to, "triage_policy", "policy");

        var sevFlag = SevFlag[Schema.Rank(sev)];
        string text = decision switch
        {
            "fix" => $"{label} → real, {(bucket == Buckets.FixNow ? "Fix now" : "Batch")}",
            "suppress" => $"{label} → noise, suppressed with evidence",
            "suppress_pending" => $"{label} → suppress proposed, held for AppSec sign-off",
            "accept_pending" => $"{label} → accept proposed, held for a human approver",
            _ => $"{label} → needs human",
        };
        if (cached != null) text += " (cached decision)";
        Feed.Update(e, "triage", text, null, decision == "suppress" ? ["noise", "Noise"] : sevFlag, reason + (notes.Count > 0 ? "  [policy: " + string.Join("; ", notes) + "]" : ""),
            call != null ? Math.Round(call.Seconds, 1) : null);
        if (decision == "suppress")
            Feed.Detail(e, new { type = "evid", text = $"Evidence: {string.Join("; ", hints.Select(h => h.Text))} · severity {sev} ≤ rule max · agent may suppress {string.Join("/", S.Cfg.Policies.Authority.AgentMaySuppress)}" });
        return decision == "fix" ? "fix" : decision == "suppress" ? "suppressed" : "human";
    }

    static string Note(List<string> notes, string decision, string note) { notes.Add(note); return decision; }
    static string Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    void Injection(Finding f, List<InjectionDetector.Hit> hits)
    {
        f.InjectionFlag = true;
        S.Store.SetInjectionFlag(f.FindingId);
        lock (R.Lock) R.Injections += hits.Count;
        var e = Feed.Entry("triage", "ignored instruction found in code comment (treated as data)", "warn", ["inj", "Prompt injection"]);
        var h = hits[0];
        Feed.Detail(e, new
        {
            type = "quote", @ref = $"{f.FilePath}:{h.Line}", code = S.Masker.Mask(h.Text.Trim(), false),
            text = "Neutralised in the context pack and not followed. The finding is still triaged on its merits; the policy layer blocks agent suppression of high findings.",
        });
        PublishGuards();
    }

    sealed record Hint(string RuleId, string Text, string? MaxSeverity);

    static List<Hint> SuppressionHints(Finding f, RulePack rp)
    {
        var list = new List<Hint>();
        foreach (var rule in rp.SuppressionRules)
        {
            var pathOk = rule.PathGlob.Count == 0 || (f.FilePath != null && rule.PathGlob.Any(g => Glob(g, f.FilePath)));
            var attrOk = rule.Attribute.Count == 0 || (rule.Attribute.TryGetValue("key", out var k) && rule.Attribute.TryGetValue("equals", out var v) && f.Attributes.GetValueOrDefault(k) == v);
            if (pathOk && attrOk)
                list.Add(new(rule.Id, $"rule '{rule.Id}' matched ({rule.Description}) path={f.FilePath}" + (rule.Attribute.Count > 0 ? $" {rule.Attribute["key"]}={rule.Attribute["equals"]}" : ""), rule.MaxSeverity));
        }
        return list;
    }

    static bool Glob(string glob, string path)
    {
        var rx = "^" + System.Text.RegularExpressions.Regex.Escape(glob).Replace(@"\*\*/", "(.*/)?").Replace(@"\*\*", ".*").Replace(@"\*", "[^/]*") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(path, rx);
    }

    static string RulePackText(Finding f, RulePack rp)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Rule pack {rp.Ref} for issue type {f.IssueType}.");
        sb.AppendLine(rp.Guidance.Trim());
        foreach (var r in rp.SuppressionRules) sb.AppendLine($"Suppression rule {r.Id}: {r.Description} (paths {string.Join(", ", r.PathGlob)}; max severity {r.MaxSeverity}).");
        foreach (var (b, sevs) in rp.BucketRules) sb.AppendLine($"Bucket {b}: {string.Join("/", sevs)}.");
        return sb.ToString();
    }

    string SnippetDisplay(Finding f) => f.IssueType switch
    {
        IssueTypes.UnsafeCode => $"{f.FilePath}#{f.Attributes.GetValueOrDefault("enclosing_symbol")} (lines {f.Attributes.GetValueOrDefault("function_start")}-{f.Attributes.GetValueOrDefault("function_end")})",
        IssueTypes.VulnerableDependency => $"manifest + lock entry for {f.ComponentName?.Split('/').Last()}",
        IssueTypes.Secret => $"{f.FilePath}:{f.LineStart} ±2 (masked {f.Attributes.GetValueOrDefault("masked_value")})",
        IssueTypes.Licence => $"licence header of {f.ComponentName?.Replace("file:", "")}",
        _ => $"{f.FilePath} metadata",
    };

    string Snippet(Finding f)
    {
        string Numbered(string rel, int from, int to)
        {
            var path = Path.Combine(R.HeadDir, rel);
            if (!File.Exists(path)) return "";
            var lines = File.ReadAllLines(path);
            from = Math.Max(1, from); to = Math.Min(lines.Length, to);
            return string.Join('\n', Enumerable.Range(from, Math.Max(0, to - from + 1)).Select(n => $"{n,4}: {lines[n - 1]}"));
        }
        switch (f.IssueType)
        {
            case IssueTypes.UnsafeCode:
                int.TryParse(f.Attributes.GetValueOrDefault("function_start"), out var a); int.TryParse(f.Attributes.GetValueOrDefault("function_end"), out var b);
                return $"// {f.FilePath}\n" + Numbered(f.FilePath!, a > 0 ? a : (f.LineStart ?? 1) - 6, b > 0 ? b : (f.LineStart ?? 1) + 6);
            case IssueTypes.Secret:
                return $"// {f.FilePath}\n" + S.Masker.Mask(Numbered(f.FilePath!, (f.LineStart ?? 1) - 2, (f.LineStart ?? 1) + 2), false);
            case IssueTypes.VulnerableDependency:
            {
                var pkg = f.Attributes.GetValueOrDefault("package") ?? "";
                var sb = new StringBuilder();
                foreach (var proj in Directory.GetFiles(R.HeadDir, "*.csproj", SearchOption.AllDirectories))
                    foreach (var l in File.ReadAllLines(proj).Where(l => l.Contains($"\"{pkg}\"")))
                        sb.AppendLine($"{Path.GetRelativePath(R.HeadDir, proj)}: {l.Trim()}");
                sb.AppendLine($"lock file: {f.FilePath} · {f.DirectOrTransitive} dependency · fixed in {f.FixedVersion}");
                return sb.ToString();
            }
            case IssueTypes.Licence:
            {
                var dir = Path.Combine(R.HeadDir, f.ComponentName!.Replace("file:", ""));
                var sb = new StringBuilder();
                if (Directory.Exists(dir))
                    foreach (var file in Directory.GetFiles(dir).Order())
                        sb.AppendLine(Numbered(Path.GetRelativePath(R.HeadDir, file), 1, 8));
                var users = Directory.GetFiles(R.HeadDir, "*.cs", SearchOption.AllDirectories).Where(p => !p.StartsWith(dir) && !p.Replace('\\', '/').Contains("/obj/") && File.ReadAllText(p).Contains("CsvEscaper"))
                    .Select(p => Path.GetRelativePath(R.HeadDir, p)).ToList();
                sb.AppendLine("used by: " + (users.Count > 0 ? string.Join(", ", users) : "none"));
                return sb.ToString();
            }
            default:
            {
                var refs = Directory.GetFiles(R.HeadDir, "*.csproj", SearchOption.AllDirectories).Where(p => File.ReadAllText(p).Contains(Path.GetFileName(f.FilePath!))).ToList();
                return $"file {f.FilePath} · {f.Attributes.GetValueOrDefault("size")} bytes · sha256 {f.Attributes.GetValueOrDefault("sha256")?[..16]}… · referenced by project files: {(refs.Count > 0 ? string.Join(", ", refs) : "none")}";
            }
        }
    }
}

// ============================================================ Router ============================================================
/// <summary>Deterministic router: issue type → fixer via the plug-in registry (routing.yaml). Groups findings into fix groups.
/// Skips groups whose fix PR already exists (idempotency ledger) so re-runs never create duplicates.</summary>
public sealed class RouterExecutor(AgentServices s, RunState r) : StepBase("router", s, r)
{
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb.AddHandler<TriageDone>(HandleAsync)).SendsMessage<FixTask>().SendsMessage<RoutePlan>().SendsMessage<FixClosed>();

    async ValueTask HandleAsync(TriageDone m, IWorkflowContext ctx, CancellationToken _) => await GuardAsync("router", async () =>
    {
        await StatusAsync(ctx, "router", "running", "Router routing…");
        var e = Feed.Entry("router", $"routing {m.FixFindingIds.Count} real findings to specialist fixers");
        var groups = new Dictionary<string, GroupInfo>();
        foreach (var id in m.FixFindingIds)
        {
            var f = R.Findings[id];
            var route = S.Cfg.Routing.Routes[f.IssueType];
            var key = f.IssueType == IssueTypes.VulnerableDependency ? Hashing.Sha256($"fix_group|{f.ComponentName}|{f.ComponentVersion}") : f.Fingerprint;
            if (!groups.TryGetValue(key, out var g))
                groups[key] = g = new GroupInfo { Key = key, FixerId = route.Fixer, FindingIds = [], Branch = BranchFor(route.Fixer, key) };
            g.FindingIds.Add(id);
        }
        await S.Tools.RunAsync("router", "registry.read", string.Join(" · ", groups.Values.Select(g => $"{TriageExecutor.Label(R.Findings[g.FindingIds[0]]).Split(' ')[0]}→{FixerUi(g.FixerId)}")), Feed, e, () => Task.FromResult(true), Ct);
        var send = new List<object>();
        foreach (var g in groups.Values)
        {
            R.Groups[g.Key] = g;
            var ledger = await S.Tools.RunAsync("router", "ledger.read", $"fix:{g.Key[..8]}…:pr", null, null, () => Task.FromResult(S.Store.Ledger($"fix:{g.Key}:pr")), Ct);
            if (ledger is { Status: "completed" })
            {
                g.Outcome = "pr_reused"; g.PrUrl = ledger.ResultRef; g.PrNumber = int.TryParse(ledger.ResultRef?.Split('/').Last(), out var n) ? n : null;
                lock (R.Lock) R.PrsReused++;
                var e2 = Feed.Entry("router", $"{FixerName(g.FixerId)} group {Short(g.Key)} already has fix PR #{g.PrNumber} → not re-fixed (idempotent)", null, ["pr", $"PR #{g.PrNumber}"]);
                Feed.Publish("pr", new { num = g.PrNumber, url = g.PrUrl, title = $"(existing) {g.Branch}", add = 0, del = 0, files = 0, status = "Awaiting review", reused = true, verified = true });
                send.Add(new FixClosed(RunId, g.FixerId, g.Key, g.FindingIds, "pr_reused", g.PrUrl, "ledger"));
                continue;
            }
            foreach (var id in g.FindingIds) Move(R.Findings[id], Status.FixQueued, "route", "router");
            send.Add(new FixTask(RunId, g.FixerId, g.Key, g.FindingIds, 1, null));
        }
        Feed.Update(e, "router", groups.Count == 0 ? "nothing to fix" :
            $"{groups.Values.Sum(g => g.FindingIds.Count)} findings → {string.Join(", ", groups.Values.Select(g => FixerName(g.FixerId)).Distinct())}");
        await StatusAsync(ctx, "router", "done", $"{groups.Count} routed");
        foreach (var g in groups.Values) if (g.Outcome == "pending") Feed.Agent(FixerUi(g.FixerId), "queued", "Queued");
        await ctx.SendMessageAsync(new RoutePlan(RunId, groups.Keys.ToList()), "orch");
        foreach (var msg in send)
            await ctx.SendMessageAsync(msg, msg is FixTask t ? "fixer-" + t.FixerId : "orch");
    });
}

// ============================================================ Fixers ============================================================
/// <summary>Hosts one IFixer plug-in. The core (not the fixer) creates the branch/worktree, commits and records the FixAttempt.</summary>
public sealed class FixerExecutor(AgentServices s, RunState r, IFixer fixer) : StepBase("fixer-" + fixer.Id, s, r)
{
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb.AddHandler<FixTask>(HandleAsync)).SendsMessage<FixProduced>().SendsMessage<FixClosed>().SendsMessage<FixTask>();

    readonly Dictionary<string, int> _done = [];

    async ValueTask HandleAsync(FixTask t, IWorkflowContext ctx, CancellationToken _) => await GuardAsync(fixer.AgentName, async () =>
    {
        var ui = fixer.AgentName;
        var g = R.Groups[t.GroupKey];
        g.Attempts = t.AttemptNo;
        var findings = t.FindingIds.Select(id => R.Findings[id]).ToList();
        var f0 = findings[0];
        var max = S.Cfg.Policies.Retries.MaxFixRetries;
        var retry = t.AttemptNo > 1;
        var verb = f0.IssueType == IssueTypes.Licence ? "checking licence…" : f0.IssueType == IssueTypes.BinaryArtefact ? "removing binary…" : "composing fix…";
        await StatusAsync(ctx, ui, retry ? "retry" : "running", retry ? $"Retrying {t.AttemptNo - 1}/{max} · {FirstLine(t.PriorFailure)}" : $"{FixerName(fixer.Id)} {verb}");
        foreach (var f in findings) { Move(f, Status.FixInProgress, retry ? "retry" : "fix_start", fixer.Id); }
        var e = Feed.Entry(ui, Intro(f0, retry, t.AttemptNo));
        var wt = await S.Tools.RunAsync(fixer.Id, "git.worktree", $"{g.Branch} from {Short(R.Pr.HeadSha)}", Feed, e,
            () => S.Git.CreateFixWorktreeAsync(RunId, g.Branch, R.Pr.HeadSha, t.AttemptNo, Ct), Ct);
        var fix = new FixAttempt
        {
            FindingIds = t.FindingIds, FixGroupKey = t.GroupKey, FixerType = fixer.Id, FixerVersion = fixer.Version, Branch = g.Branch, AttemptNo = t.AttemptNo,
            IdempotencyKey = $"fix:{t.GroupKey}:a{t.AttemptNo}:{RunId}", RunId = RunId,
        };
        FixOutcome outcome;
        try
        {
            outcome = await fixer.ApplyAsync(new FixContext(R, fixer.Id, t.GroupKey, findings, t.AttemptNo, t.PriorFailure, wt, g.Branch, Feed, e, Ct));
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or KillSwitchEngagedException or BudgetExceededException))
        {
            var reason = S.Masker.Mask(ex.Message, false);
            fix.VerificationResult = "fix_failed"; fix.FailureReason = reason; S.Store.InsertFix(fix); R.Fixes[fix.FixId] = fix;
            Feed.Update(e, ui, Intro(f0, retry, t.AttemptNo) + " — fixer failed", "fail", ["fail", "Fixer error"]);
            Feed.Detail(e, new { type = "fail", text = "✗ " + reason });
            if (t.AttemptNo <= max)
            {
                lock (R.Lock) R.RetriesUsed++;
                PublishGuards();
                foreach (var f in findings) { Move(f, Status.FixProposed, "fix_error", fixer.Id); Move(f, Status.VerifyFailed, "fix_error", fixer.Id); }
                await ctx.SendMessageAsync(t with { AttemptNo = t.AttemptNo + 1, PriorFailure = "Fixer error: " + reason }, Id);
            }
            else await HandToHumanAsync(ctx, t, findings, "fix_failed", $"Fixer failed {t.AttemptNo} times: {reason}");
            return;
        }
        fix.ContextPackId = outcome.ContextPackId; fix.RoutingId = outcome.RoutingId; fix.TokensIn = outcome.TokensIn; fix.TokensOut = outcome.TokensOut;
        OrchestratorExecutor.RememberNotes(fix.FixId, outcome.Notes);
        if (outcome.NeedsHuman)
        {
            fix.VerificationResult = "not_applicable"; fix.FailureReason = "decision handed to human: " + outcome.HumanTaskType;
            S.Store.InsertFix(fix); R.Fixes[fix.FixId] = fix;
            foreach (var f in findings) Move(f, Status.NeedsHuman, "fixer_handoff", fixer.Id);
            Feed.Update(e, ui, outcome.Summary, "warn", ["inj", "Needs human"]);
            var alts = outcome.Notes.GetValueOrDefault("alternatives") ?? "";
            Feed.Detail(e, new { type = "evid", text = $"Options proposed: {alts}. A licence decision is a human (AppSec / legal) decision; no PR is opened for it." });
            PublishCounts();
            await StatusAsync(ctx, ui, "done", f0.IssueType == IssueTypes.Licence ? $"{f0.LicenceId} → human decision" : "→ human");
            await ctx.SendMessageAsync(new FixClosed(RunId, fixer.Id, t.GroupKey, t.FindingIds, "needs_human", null, outcome.Summary), "orch");
            return;
        }
        var msg = $"fix(security): {outcome.Summary}\n\nFindings: {string.Join(", ", findings.Select(f => f.Short))} ({string.Join(", ", findings.Select(f => f.ScannerRuleId).Distinct())}).\n" +
                  $"Fixer {fixer.Version}, attempt {t.AttemptNo}, run {RunId}. Proposed by an agent; a human must review and merge.";
        var sha = await S.Tools.RunAsync(fixer.Id, "git.commit", $"{g.Branch} · \"{Trunc(outcome.Summary, 60)}\"", Feed, e, () => GitWorkspace.CommitAllAsync(wt, msg, Ct), Ct);
        var (add, del, files, paths) = await GitWorkspace.DiffStatAsync(wt, R.Pr.HeadSha, Ct);
        fix.CommitSha = sha; fix.Additions = add; fix.Deletions = del; fix.FilesChanged = files;
        S.Store.InsertFix(fix); R.Fixes[fix.FixId] = fix;
        var diff = await GitWorkspace.DiffAsync(wt, R.Pr.HeadSha, Ct);
        Feed.Update(e, ui, outcome.Summary + (retry ? $" (attempt {t.AttemptNo})" : ""));
        Feed.Detail(e, new { type = "code", files = DiffView.Parse(S.Masker.Mask(diff, false), 28) });
        foreach (var f in findings) Move(f, Status.FixProposed, "fix_committed", fixer.Id);
        await StatusAsync(ctx, ui, retry ? "retry" : "running", $"Waiting for verifier · +{add} −{del}");
        await ctx.SendMessageAsync(new FixProduced(RunId, fixer.Id, t.GroupKey, t.FindingIds, fix.FixId, t.AttemptNo, wt, g.Branch), "verifier");
    });

    async Task HandToHumanAsync(IWorkflowContext ctx, FixTask t, List<Finding> findings, string type, string details)
    {
        foreach (var f in findings) Move(f, Status.NeedsHuman, "fix_exhausted", fixer.Id);
        S.Store.InsertTask(new HumanTask { RunId = RunId, Type = type, Title = $"Fix could not be produced/verified for {TriageExecutor.Label(findings[0])}", Details = S.Masker.Mask(details, false), FindingIds = t.FindingIds, Owner = "[owner team]" });
        PublishCounts();
        await StatusAsync(ctx, fixer.AgentName, "failed", "Handed to human");
        await ctx.SendMessageAsync(new FixClosed(RunId, fixer.Id, t.GroupKey, t.FindingIds, "needs_human", null, details), "orch");
    }

    static string Intro(Finding f, bool retry, int attempt) => (retry ? $"retry {attempt - 1}: " : "") + f.IssueType switch
    {
        IssueTypes.VulnerableDependency => $"bumping {f.Attributes.GetValueOrDefault("package")} {f.ComponentVersion} → lowest version fixing {string.Join(",", f.CveIds)}",
        IssueTypes.Secret => $"moving {f.ScannerRuleId} in {Path.GetFileName(f.FilePath)} to a Key Vault reference; flagging rotation for owner",
        IssueTypes.UnsafeCode => $"parameterising SQL query in {Path.GetFileName(f.FilePath)} ({f.Attributes.GetValueOrDefault("enclosing_symbol")})",
        IssueTypes.BinaryArtefact => $"removing committed binary {f.FilePath} (+ .gitignore)",
        IssueTypes.Licence => $"checking {f.LicenceId} in {f.ComponentName?.Replace("file:", "")} against licence policy",
        _ => f.Title,
    };
    static string FirstLine(string? s) => Trunc((s ?? "").Split('\n').FirstOrDefault(l => l.Trim().Length > 0) ?? "", 48);
    static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}

// ============================================================ Verifier ============================================================
/// <summary>Rescans the fix branch with all scanners, checks the target finding is gone and nothing new appeared, runs dotnet test,
/// stores evidence, and either passes the fix to the orchestrator or loops it back to its fixer (max retries) / to a human.
/// Messages delivered in one superstep are verified concurrently (started in the handler, awaited at delivery end).</summary>
public sealed class VerifierExecutor(AgentServices s, RunState r) : StepBase("verifier", s, r)
{
    readonly List<Task<object?>> _work = [];

    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder pb) =>
        pb.ConfigureRoutes(rb => rb.AddHandler<FixProduced>(HandleAsync)).SendsMessage<VerifyOutcome>().SendsMessage<FixTask>().SendsMessage<FixClosed>();

    ValueTask HandleAsync(FixProduced p, IWorkflowContext ctx, CancellationToken _)
    {
        lock (_work) _work.Add(Task.Run(() => VerifyAsync(p)));
        return default;
    }

    protected override async ValueTask OnMessageDeliveryFinishedAsync(IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        List<Task<object?>> work;
        lock (_work) { work = [.. _work]; _work.Clear(); }
        if (work.Count == 0) return;
        var results = await Task.WhenAll(work);
        foreach (var m in results.Where(x => x != null))
            await context.SendMessageAsync(m!, m is FixTask t ? "fixer-" + t.FixerId : "orch", cancellationToken);
        var active = R.Groups.Values.Any(g => g.Outcome == "pending" && results.OfType<FixTask>().Any(t => t.GroupKey == g.Key));
        Feed.Agent("verifier", active ? "running" : "done", active ? "Waiting for retried fix…" : $"{R.Fixes.Values.Count(f => f.VerificationResult == "passed")} verified", R.AgentTokens.GetValueOrDefault("verifier"));
    }

    static readonly SemaphoreSlim HeavySlots = new(Math.Max(1, int.TryParse(Environment.GetEnvironmentVariable("SECAGENT_VERIFY_PARALLEL"), out var n) ? n : 2));

    async Task<object?> VerifyAsync(FixProduced p)
    {
        object? result = null;
        await GuardAsync("verifier", async () => result = await VerifyCoreAsync(p));
        return result;
    }

    async Task<object?> VerifyCoreAsync(FixProduced p)
    {
        var fix = R.Fixes[p.FixId];
        var findings = p.FindingIds.Select(id => R.Findings[id]).ToList();
        var name = FixerName(p.FixerId);
        Feed.Agent("verifier", "running", $"Verifier rescanning {name.Replace(" fixer", "").ToLowerInvariant()} patch…", R.AgentTokens.GetValueOrDefault("verifier"));
        var e = Feed.Entry("verifier", $"verifying {name} patch {Short(fix.CommitSha ?? "")} on {p.Branch}");
        var t = new ScanTarget(RunId, $"verify-{p.FixerId}-{Short(p.GroupKey)}-a{p.AttemptNo}", p.Worktree, R.Pr.Repo, p.Branch, fix.CommitSha ?? "", null);
        var ids = new ConcurrentDictionary<string, string>();
        // Rescans + builds are memory-heavy next to a resident local model; cap how many verifications run at once.
        await HeavySlots.WaitAsync(Ct);
        ScanSet set; TestResult tests;
        try
        {
            var scanTask = S.Scanners.ScanAsync(t, Ct,
                (id, _) => ids[id] = Feed.ToolStart(e, "scan." + id, "fix branch"),
                (id, raw, n) => Feed.ToolEnd(e, ids[id], "scan." + id, $"fix branch · {n} finding{(n == 1 ? "" : "s")}", true, raw.ElapsedMs));
            var testTask = RunTestsAsync(p, e);
            set = await scanTask;
            tests = await testTask;
        }
        finally { HeavySlots.Release(); }

        // Target gone? (match keys survive line moves and code edits)
        static string MatchKey(Finding f) => f.IssueType switch
        {
            IssueTypes.UnsafeCode => $"{f.ScannerRuleId}|{f.FilePath}|{f.Attributes.GetValueOrDefault("enclosing_symbol")}",
            IssueTypes.VulnerableDependency => $"{f.ComponentName}|{string.Join(",", f.CveIds)}",
            IssueTypes.Secret => $"{f.ScannerRuleId}|{f.SecretHash}",
            _ => $"{f.IssueType}|{f.FilePath}|{f.ComponentName}",
        };
        var after = set.Findings.Select(MatchKey).ToHashSet();
        var remaining = findings.Where(f => after.Contains(MatchKey(f))).ToList();
        var headKeys = R.HeadFingerprints;
        var introduced = set.Findings.Where(f => !headKeys.Contains(f.Fingerprint) && !findings.Any(x => MatchKey(x) == MatchKey(f))).ToList();
        var passed = remaining.Count == 0 && introduced.Count == 0 && tests.Ok;

        var sb = new StringBuilder();
        sb.AppendLine($"- Rescan ({string.Join(", ", set.Runs.Select(x => $"{x.Scanner} {x.Version}"))}): target finding{(findings.Count > 1 ? "s" : "")} {(remaining.Count == 0 ? "**gone** ✓" : "**still present** ✗")}; new findings introduced: **{introduced.Count}**{(introduced.Count > 0 ? " — " + string.Join("; ", introduced.Select(f => f.Title)) : "")}");
        sb.AppendLine($"- `dotnet test`: **{tests.Passed} passed, {tests.Failed} failed** of {tests.Total} ({tests.Seconds:0.0}s){(tests.BuildFailed ? " — **build failed**" : "")}");
        var evidence = new List<Evidence>();
        var sarifHash = S.Blob.Put("evidence", $"{RunId}/{p.FixerId}-{Short(p.GroupKey)}-a{p.AttemptNo}/rescan.sarif.json", S.Blob.Read(set.SarifUri));
        evidence.Add(new Evidence { Type = "rescan_sarif", Uri = sarifHash.Uri, Hash = sarifHash.Hash, CreatedBy = "verifier", RelatedIds = [fix.FixId], TraceId = Telemetry.TraceId });
        if (tests.TrxUri != null) evidence.Add(new Evidence { Type = "test_results_trx", Uri = tests.TrxUri, Hash = tests.TrxHash!, CreatedBy = "verifier", RelatedIds = [fix.FixId], TraceId = Telemetry.TraceId });
        var summaryJson = JsonSerializer.Serialize(new { passed, remaining = remaining.Select(f => f.Short), introduced = introduced.Select(f => f.Title), tests = new { tests.Total, tests.Passed, tests.Failed, tests.BuildFailed }, commit = fix.CommitSha }, Schema.JsonIndented);
        var vs = S.Blob.Put("evidence", $"{RunId}/{p.FixerId}-{Short(p.GroupKey)}-a{p.AttemptNo}/verification.json", summaryJson);
        evidence.Add(new Evidence { Type = "verification_summary", Uri = vs.Uri, Hash = vs.Hash, CreatedBy = "verifier", RelatedIds = [fix.FixId], TraceId = Telemetry.TraceId });
        await S.Tools.RunAsync("verifier", "evidence.write", $"{evidence.Count} items · write-once · sha256", Feed, e, () => { foreach (var ev in evidence) S.Store.InsertEvidence(ev); return Task.FromResult(true); }, Ct);
        foreach (var ev in evidence) sb.AppendLine($"- Evidence `{ev.Type}`: `{ev.Uri}` ({ev.Hash[..19]}…)");
        fix.VerificationEvidenceRefs = evidence.Select(x => x.EvidenceId).ToList();

        if (passed)
        {
            fix.VerificationResult = "passed"; fix.UpdatedAt = DateTime.UtcNow; S.Store.UpdateFix(fix);
            foreach (var f in findings) Move(f, Status.Verified, "verify_pass", "verifier");
            var diff = await GitWorkspace.DiffAsync(p.Worktree, R.Pr.HeadSha, Ct);
            var call = await LlmStep.RunAsync(S, R, "verifier", "verifier", e, findings[0].FindingId, p.GroupKey, [
                new("finding", $"finding:{findings[0].FindingId}", LlmStep.FindingJson(findings[0])),
                new("tool_output", $"fix:{fix.FixId}", $"Diff (fix branch vs PR head):\n{Trunc(S.Masker.Mask(diff, false), 3500)}\n\nVerification:\n{sb}"),
            ], new CallSpec("summarise", "summarise-fix-output", findings[0].SeverityEffective, 1), Ct);
            R.Summaries[p.GroupKey] = call;
            Feed.Update(e, "verifier", $"{name} patch verified: rescan clean, {tests.Passed} tests passed", "ok", ["ok", "Verified"]);
            PublishGuards();
            return new VerifyOutcome(RunId, p.FixerId, p.GroupKey, p.FindingIds, p.FixId, p.AttemptNo, true, sb.ToString(), p.Worktree, p.Branch);
        }

        var why = new List<string>();
        if (remaining.Count > 0) why.Add($"target still detected by {string.Join(",", remaining.Select(f => f.SourceScanner))}");
        if (introduced.Count > 0) why.Add($"new findings: {string.Join("; ", introduced.Select(f => f.Title))}");
        if (!tests.Ok) why.Add(tests.BuildFailed ? "build failed: " + tests.FailureText : $"{tests.Failed} test(s) failed: {tests.FailureText}");
        fix.VerificationResult = "failed"; fix.FailureReason = S.Masker.Mask(string.Join(" | ", why), false); fix.UpdatedAt = DateTime.UtcNow; S.Store.UpdateFix(fix);
        foreach (var f in findings) Move(f, Status.VerifyFailed, "verify_fail", "verifier");
        var max = S.Cfg.Policies.Retries.MaxFixRetries;
        if (p.AttemptNo <= max)
        {
            lock (R.Lock) R.RetriesUsed++;
            PublishGuards();
            Feed.Update(e, "verifier", $"verification failed for {name}: {Trunc(why[0], 90)} → retry {p.AttemptNo}/{max}", "fail", ["fail", $"Retry {p.AttemptNo}/{max}"]);
            Feed.Detail(e, new { type = "fail", text = "✗ " + Trunc(fix.FailureReason, 900) });
            Feed.Agent(FixerUi(p.FixerId), "retry", $"Retrying {p.AttemptNo}/{max} · {Trunc(why[0], 40)}");
            return new FixTask(RunId, p.FixerId, p.GroupKey, p.FindingIds, p.AttemptNo + 1, fix.FailureReason);
        }
        Feed.Update(e, "verifier", $"verification failed for {name} after {p.AttemptNo} attempts → handed to human", "fail", ["fail", "Needs human"]);
        Feed.Detail(e, new { type = "fail", text = "✗ " + Trunc(fix.FailureReason, 900) });
        foreach (var f in findings) Move(f, Status.NeedsHuman, "retries_exhausted", "verifier");
        S.Store.InsertTask(new HumanTask { RunId = RunId, Type = "fix_failed", Title = $"Agent fix failed verification {p.AttemptNo}× for {TriageExecutor.Label(findings[0])}", Details = fix.FailureReason, FindingIds = p.FindingIds, Owner = "[owner team]" });
        Feed.Agent(FixerUi(p.FixerId), "failed", "Handed to human after retries");
        PublishCounts();
        return new VerifyOutcome(RunId, p.FixerId, p.GroupKey, p.FindingIds, p.FixId, p.AttemptNo, false, sb.ToString(), p.Worktree, p.Branch);
    }

    sealed record TestResult(bool Ok, bool BuildFailed, int Total, int Passed, int Failed, double Seconds, string FailureText, string? TrxUri, string? TrxHash);

    async Task<TestResult> RunTestsAsync(FixProduced p, string entry)
    {
        var resultsDir = Path.Combine(p.Worktree, ".secagent-test");
        var sln = Directory.GetFiles(p.Worktree, "*.slnx").Concat(Directory.GetFiles(p.Worktree, "*.sln")).FirstOrDefault() ?? p.Worktree;
        var r = await S.Tools.RunAsync("verifier", "dotnet.test", $"{Path.GetFileName(sln)} · trx", Feed, entry,
            () => Proc.RunAsync(Proc.Which("dotnet"), ["test", sln, "--logger", "trx;LogFileName=results.trx", "--results-directory", resultsDir, "-nologo", "--disable-build-servers"], p.Worktree, Ct, timeoutSeconds: 600), Ct,
            x => x.ExitCode == 0);
        var trx = Path.Combine(resultsDir, "results.trx");
        int total = 0, passed = 0, failed = 0; string fails = "";
        string? uri = null, hash = null;
        if (File.Exists(trx))
        {
            var x = System.Xml.Linq.XDocument.Load(trx);
            var ns = x.Root!.Name.Namespace;
            var c = x.Descendants(ns + "Counters").FirstOrDefault();
            if (c != null) { total = (int?)c.Attribute("total") ?? 0; passed = (int?)c.Attribute("passed") ?? 0; failed = (int?)c.Attribute("failed") ?? 0; }
            fails = string.Join("\n", x.Descendants(ns + "UnitTestResult").Where(u => (string?)u.Attribute("outcome") == "Failed")
                .Select(u => $"{u.Attribute("testName")?.Value}: {u.Descendants(ns + "Message").FirstOrDefault()?.Value?.Split('\n')[0]}").Take(5));
            (uri, hash) = S.Blob.Put("evidence", $"{RunId}/{p.FixerId}-{Short(p.GroupKey)}-a{p.AttemptNo}/results.trx", await File.ReadAllBytesAsync(trx, Ct));
            Directory.Delete(resultsDir, true);
        }
        var buildFailed = r.ExitCode != 0 && total == 0;
        if (buildFailed)
            fails = string.Join("\n", (r.StdOut + "\n" + r.StdErr).Split('\n').Where(l => l.Contains(": error ")).Select(l => l.Trim()).Distinct().Take(6));
        fails = System.Text.RegularExpressions.Regex.Replace(fails.Replace(p.Worktree + Path.DirectorySeparatorChar, "").Replace(p.Worktree + "/", ""), @"\s*\[[^\]]+\.csproj\]", "");
        return new TestResult(r.ExitCode == 0 && failed == 0 && total > 0, buildFailed, total, passed, failed, r.ElapsedMs / 1000.0, S.Masker.Mask(fails, false), uri, hash);
    }

    static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}

// ============================================================ Diff view ============================================================
public static class DiffView
{
    public sealed record Line(string T, string S);
    public sealed record FileDiff(string File, List<Line> Lines, int More);

    public static List<FileDiff> Parse(string diff, int maxLinesPerFile)
    {
        var files = new List<FileDiff>();
        FileDiff? cur = null; int more = 0;
        foreach (var raw in diff.Replace("\r", "").Split('\n'))
        {
            if (raw.StartsWith("diff --git"))
            {
                if (cur != null) files.Add(cur with { More = more });
                var name = raw.Split(" b/").Last();
                cur = new FileDiff(name, [], 0); more = 0; continue;
            }
            if (cur == null || raw.StartsWith("index ") || raw.StartsWith("--- ") || raw.StartsWith("+++ ") || raw.StartsWith("new file") || raw.StartsWith("deleted file") || raw.StartsWith("similarity")) continue;
            if (raw.StartsWith("Binary files")) { cur.Lines.Add(new("del", "binary file removed")); continue; }
            if (raw.StartsWith("@@")) { if (cur.Lines.Count < maxLinesPerFile) cur.Lines.Add(new("hunk", raw.Split("@@").ElementAtOrDefault(1)?.Trim() ?? "")); continue; }
            if (raw.Length == 0) continue;
            var t = raw[0] == '+' ? "add" : raw[0] == '-' ? "del" : "ctx";
            if (cur.Lines.Count < maxLinesPerFile) cur.Lines.Add(new(t, raw.Length > 1 ? raw[1..] : "")); else more++;
        }
        if (cur != null) files.Add(cur with { More = more });
        return files;
    }
}
