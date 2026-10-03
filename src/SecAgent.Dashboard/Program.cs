using System.Diagnostics;
using System.Text.Json;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using SecAgent.Agents;
using SecAgent.Agents.Workflow;
using SecAgent.Core;
using SecAgent.Intake;

// ---------------------------------------------------------------------------------------------------------------
// secagent serve [--port 8795]                         dashboard (live run via SSE) + API
// secagent run --repo owner/name --pr N [--fresh]      CLI run (local runner; ends at "waiting for human review")
// secagent reset-db                                    dev only: clear the local SecAgent database (demo reset)
// secagent seed-usage [--days 30] [--seed 42] [--clear] SYNTHETIC usage rows for the Usage tab demo (flagged synthetic=1)
// ---------------------------------------------------------------------------------------------------------------
LocalEnv.Load();
var repoRoot = LocalEnv.FindRepoRoot();
var dataRoot = Path.Combine(repoRoot, ".data");
Directory.CreateDirectory(dataRoot);
var sql = Environment.GetEnvironmentVariable("SECAGENT_SQL") ?? throw new InvalidOperationException("SECAGENT_SQL not set (see ~/.secagent/secagent.env)");
var cmd = args.FirstOrDefault() ?? "serve";
string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }

if (cmd == "reset-db")
{
    var st = new SqlStore(sql);
    st.EnsureSchema(Path.Combine(repoRoot, "db", "schema.sql"));
    st.EnsureMigrations(Path.Combine(repoRoot, "db", "migrations"));
    st.ResetAll();
    Console.WriteLine("SecAgent database cleared (local dev).");
    return 0;
}

if (cmd == "seed-usage")
{
    // SYNTHETIC demo data only (scripts/seed-usage.sh). Re-seeding replaces earlier synthetic rows; real rows are never touched.
    var st = new SqlStore(sql);
    st.EnsureSchema(Path.Combine(repoRoot, "db", "schema.sql"));
    st.EnsureMigrations(Path.Combine(repoRoot, "db", "migrations"));
    var removed = st.DeleteSyntheticUsage();
    if (args.Contains("--clear")) { Console.WriteLine($"removed {removed} synthetic usage rows (real rows untouched)"); return 0; }
    var cfg = ConfigSnapshot.Load(Path.Combine(repoRoot, "rules"), ModelProviderSettings.Load(repoRoot));
    var rows = SyntheticUsage.Generate(cfg.Gateway, int.Parse(Arg("--days") ?? "30"), int.Parse(Arg("--seed") ?? "42"));
    var n = st.InsertUsageBatch(rows);
    Console.WriteLine($"SYNTHETIC usage seeded: {n} rows over {Arg("--days") ?? "30"} days (replaced {removed}); flagged synthetic=1. Remove with: scripts/seed-usage.sh --clear");
    foreach (var g in rows.GroupBy(r => (r.Provider, r.ModelId)).OrderBy(g => g.Key.Provider))
        Console.WriteLine($"  {g.Key.Provider,-12} {g.Key.ModelId,-26} {g.Count(),5} rows  {g.Sum(r => (long)r.TotalTokens),10:N0} tokens  ${g.Sum(r => r.Cost):0.0000}{(g.Any(r => r.PriceSource == "placeholder") ? "  (placeholder prices)" : "")}");
    return 0;
}

if (cmd == "run")
{
    using var tp = Otel.Configure(Sdk.CreateTracerProviderBuilder(), dataRoot).Build();
    var s = AgentServices.Create(repoRoot, dataRoot, sql);
    var repo = Arg("--repo") ?? "zulq2019/sec-agent-sample-app";
    var pr = int.Parse(Arg("--pr") ?? "1");
    s.Bus.OnEvent += (_, json) => ConsoleFeed.Print(json);
    var h = await new RunService(s).StartAsync(repo, pr, args.Contains("--fresh"), blockForReview: false);
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; h.State.Cts.Cancel(); };
    await h.Completion;
    var run = s.Store.GetRun(h.State.Run.RunId)!;
    Console.WriteLine($"\nRun {run.RunId} → {run.Status} in {(run.EndedAt!.Value - run.StartedAt).TotalSeconds:0.0}s · tokens {run.Tokens}");
    Console.WriteLine(run.SummaryJson);
    return run.Status is "awaiting_human_review" or "review_recorded" ? 0 : 2;
}

if (cmd == "export")
{
    // secagent export [--run <id>] [--out replay-static/run.json] [--usage-sample <days>]: recorded run → static JSON for the no-backend replay UI.
    // --usage-sample adds a SYNTHETIC usage sample (SyntheticUsage, seed 42, every row synthetic = true) ending on the run's IST day, for the replay Usage tab.
    var s = AgentServices.Create(repoRoot, dataRoot, sql);
    var id = Arg("--run") is { } rid ? Guid.Parse(rid) : s.Store.Runs(50).First(r => r.Status is "awaiting_human_review" or "review_recorded").RunId;
    var run = s.Store.GetRun(id) ?? throw new InvalidOperationException($"run {id} not found");
    var events = s.Store.Events(id).Select(e => JsonDocument.Parse(e).RootElement.Clone()).ToList();
    var fixes = s.Store.FixesForRun(id);
    var export = new
    {
        format = "secagent-run-replay/1", exported_at = DateTime.UtcNow, note = "Replay of a recorded run. Synthetic sample repo; secret values were masked before they were recorded.",
        run, provider = s.Cfg.Gateway.Label, duration_seconds = run.EndedAt is { } en ? (en - run.StartedAt).TotalSeconds : (double?)null,
        events, findings = FindingsView(s, id), decisions = s.Store.DecisionsForRun(id), fixes, tasks = s.Store.TasksForRun(id),
        routing = s.Store.RoutingForRun(id).Select(r => new { r.task_type, r.tier, r.chosen_model_id, r.required_quality, r.reason, r.tokens_in, r.tokens_out, r.latency_ms, r.outcome }),
        prs = fixes.Where(f => f.PrUrl != null).Select(f => new { f.FixerType, f.PrUrl, f.Branch, f.VerificationResult }).DistinctBy(x => x.PrUrl),
        controls = ControlsView(s),
        usage = UsageReplay(s, run),   // per-call usage + precomputed Usage-tab views for this run (replay has no backend)
        usage_sample = UsageSample(s, run, int.Parse(Arg("--usage-sample") ?? "0")),   // optional SYNTHETIC sample (flagged), off unless --usage-sample <days>
    };
    var node = JsonSerializer.SerializeToNode(export, new JsonSerializerOptions(Schema.Json))!;
    static void Strip(System.Text.Json.Nodes.JsonNode? n)   // internal hashes the replay does not need (and that secret scanners flag as "generic key")
    {
        if (n is System.Text.Json.Nodes.JsonObject o) { o.Remove("idempotency_key"); foreach (var kv in o.ToList()) Strip(kv.Value); }
        else if (n is System.Text.Json.Nodes.JsonArray a) foreach (var x in a) Strip(x);
    }
    Strip(node);
    var text = node.ToJsonString();
    if (s.Masker.ContainsSecret(text)) throw new InvalidOperationException("export refused: a secret pattern was found in the run data (D-08)");
    var outPath = Path.GetFullPath(Arg("--out") ?? Path.Combine(repoRoot, "replay-static", "run.json"));
    Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
    File.WriteAllText(outPath, text);
    File.WriteAllText(Path.ChangeExtension(outPath, ".js"), "window.SECAGENT_RUN = " + text + ";\n");   // lets index.html work from file:// too
    Console.WriteLine($"exported run {id} ({events.Count} events, {fixes.Count} fix attempts) → {outPath}");
    return 0;
}

// ------------------------------------------------ dashboard ------------------------------------------------
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, WebRootPath = Path.Combine(repoRoot, "src", "SecAgent.Dashboard", "wwwroot") });
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("secagent-dashboard"))
    .WithTracing(t => Otel.Configure(t, dataRoot));
var svc = AgentServices.Create(repoRoot, dataRoot, sql);
var runner = new RunService(svc);
builder.Services.AddSingleton(svc);
// SARIF / Black Duck intake (docs/intake.md): pushed results are stored, parsed to canonical findings and start a PR run like POST /api/runs.
var intakeOpts = IntakeOptions.Load(repoRoot, dataRoot);
var intake = IntakeHost.Create(intakeOpts, svc,
    async (req, _) => (await runner.StartAsync(req.Repo, req.PrNumber!.Value, fresh: false, blockForReview: true)).State.Run.RunId,
    () => !svc.Kill.IsOn && !RunService.AnyActive, msg => Console.WriteLine(svc.Masker.Mask(msg, false)));
svc.External = intake.ExternalFindings;
var app = builder.Build();
var json = new JsonSerializerOptions(Schema.Json);
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapIntake(intake.Service, intake.Authenticator);
_ = Task.Run(() => intake.Dispatcher.RunAsync(app.Lifetime.ApplicationStopping));
intake.DropWatcher?.Start();

app.MapPost("/api/runs", async (StartRun req) =>
{
    if (svc.Kill.IsOn) return Results.Conflict(new { error = "Kill switch is on — runs are refused until it is turned off." });
    if (RunService.AnyActive) return Results.Conflict(new { error = "A run is already in progress." });
    var h = await runner.StartAsync(req.Repo ?? "zulq2019/sec-agent-sample-app", req.Pr ?? 1, req.Fresh ?? false, blockForReview: true);
    return Results.Ok(new { run_id = h.State.Run.RunId });
});
app.MapGet("/api/runs", () => Results.Json(svc.Store.Runs(), json));
app.MapGet("/api/runs/latest", () => svc.Store.LatestRun() is { } r ? Results.Json(r, json) : Results.NotFound());
app.MapGet("/api/runs/{id:guid}/events", async (Guid id, HttpContext ctx) =>
{
    ctx.Response.Headers.ContentType = "text/event-stream";
    ctx.Response.Headers.CacheControl = "no-cache";
    var (subId, reader) = svc.Bus.Subscribe(id);           // subscribe first, then replay persisted history (dedupe by seq on the client)
    try
    {
        foreach (var ev in svc.Store.Events(id)) await ctx.Response.WriteAsync($"data: {ev}\n\n");
        await ctx.Response.Body.FlushAsync();
        while (!ctx.RequestAborted.IsCancellationRequested)
        {
            var read = reader.ReadAsync(ctx.RequestAborted).AsTask();
            var done = await Task.WhenAny(read, Task.Delay(15000, ctx.RequestAborted));
            if (done == read) await ctx.Response.WriteAsync($"data: {await read}\n\n");
            else await ctx.Response.WriteAsync(": keep-alive\n\n");
            await ctx.Response.Body.FlushAsync();
        }
    }
    catch (OperationCanceledException) { }
    finally { svc.Bus.Unsubscribe(id, subId); }
});
app.MapPost("/api/runs/{id:guid}/review", async (Guid id, Review r) =>
    await runner.RecordReviewAsync(id, r.Decision ?? "acknowledged") ? Results.Ok() : Results.NotFound(new { error = "no pending review for this run (or the run is not in this process)" }));
app.MapGet("/api/runs/{id:guid}/detail", (Guid id) => Results.Json(new
{
    run = svc.Store.GetRun(id), fixes = svc.Store.FixesForRun(id), tasks = svc.Store.TasksForRun(id), decisions = svc.Store.DecisionsForRun(id),
    routing = svc.Store.RoutingForRun(id), packs = svc.Store.PacksForRun(id),
}, json));
app.MapGet("/api/findings", () => Results.Json(FindingsView(svc), json));
app.MapGet("/api/controls", () => Results.Json(ControlsView(svc), json));
app.MapPost("/api/controls/killswitch", (Kill k) =>
{
    svc.Kill.Set(k.On, k.By ?? "dashboard");
    foreach (var st in RunRegistry.Active) st.Feed.Publish("guards", new { kill = svc.Kill.IsOn });
    return Results.Ok(new { kill_switch = svc.Kill.IsOn });
});
// ------------------------------------------------ usage (model calls, tokens, cost) ------------------------------------------------
app.MapGet("/api/usage/summary", (HttpRequest q) =>
{
    if (!TryUsageFilter(q, out var f, out var err)) return Results.BadRequest(new { error = err });
    var groupBy = q.Query["groupBy"].FirstOrDefault();
    if (groupBy != null && !UsageAggregator.GroupKeys.Contains(groupBy)) return Results.BadRequest(new { error = $"groupBy must be one of {string.Join("|", UsageAggregator.GroupKeys)}" });
    var rows = svc.Store.QueryUsage(f);
    return Results.Json(new { filter = FilterView(f), totals = UsageAggregator.Totals(rows), group_by = groupBy, groups = groupBy == null ? null : UsageAggregator.Group(rows, groupBy, f.From, f.To) }, json);
});
app.MapGet("/api/usage/calls", (HttpRequest q) =>
{
    if (!TryUsageFilter(q, out var f, out var err)) return Results.BadRequest(new { error = err });
    var page = int.TryParse(q.Query["page"], out var pg) && pg > 0 ? pg : 1;
    var size = int.TryParse(q.Query["pageSize"], out var ps) ? Math.Clamp(ps, 1, 500) : 25;
    var (total, items) = svc.Store.QueryUsagePage(f, page, size);
    return Results.Json(new { filter = FilterView(f), page, page_size = size, total, pages = (total + size - 1) / size, items }, json);
});
app.MapGet("/api/usage/calls.csv", (HttpRequest q) =>
{
    if (!TryUsageFilter(q, out var f, out var err)) return Results.BadRequest(new { error = err });
    var rows = svc.Store.QueryUsage(f);
    var csv = UsageCsv(rows);
    var name = $"secagent-usage_{f.From:yyyyMMdd}-{f.To:yyyyMMdd}{(f.Synthetic == "exclude" ? "_real" : rows.Any(r => r.Synthetic) ? "_incl-synthetic" : "")}.csv";
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv; charset=utf-8", name);
});
app.MapGet("/api/usage/budget", (HttpRequest q) =>
{
    if (!TryUsageFilter(q, out var f, out var err)) return Results.BadRequest(new { error = err });
    var today = UsageMath.TodayIst();
    var month = new UsageFilter { From = new DateOnly(today.Year, today.Month, 1), To = today, Synthetic = f.Synthetic, Model = f.Model, Agent = f.Agent, Run = f.Run, Provider = f.Provider };
    return Results.Json(UsageAggregator.Budget(svc.Store.QueryUsage(f), svc.Store.QueryUsage(month), f, svc.Cfg.Policies), json);
});
app.MapGet("/api/usage/facets", (HttpRequest q) =>
    TryUsageFilter(q, out var f, out var err) ? Results.Json(svc.Store.UsageFacets(f), json) : Results.BadRequest(new { error = err }));

var port = Arg("--port") ?? Environment.GetEnvironmentVariable("SECAGENT_PORT") ?? "8795";
Console.WriteLine($"Security Triage & Fix Agent dashboard on http://localhost:{port} (config {svc.Cfg.Label})");
Console.WriteLine($"Intake: POST /api/intake/{{sarif|blackduck-rapid}} {(intakeOpts.Enabled ? intakeOpts.HmacSecret != null ? "enabled" : $"refusing (set {intakeOpts.HmacSecretEnv})" : "disabled")}" +
    (intake.DropWatcher != null ? $" · drop folder {intake.DropWatcher.Folder}" : ""));
app.Run($"http://127.0.0.1:{port}");
return 0;

// Shared projections (API and `secagent export` use the same shapes, so the replay UI renders exactly what the live UI rendered).
// runId = null: every finding in the store (live dashboard). With a run id: only findings that run saw (FindingOccurrence), for the replay export.
static object FindingsView(AgentServices svc, Guid? runId = null) => (runId is { } rid ? svc.Store.FindingsForRun(rid) : svc.Store.ListFindings()).Select(f => new
{
    f.FindingId, f.IssueType, f.Title, f.SourceScanner, f.ScannerRuleId, f.SeverityScanner, f.SeverityEffective, f.Status, f.Bucket, f.FilePath, f.ComponentName,
    f.ComponentVersion, f.FixedVersion, f.CveIds, f.LicenceId, f.Fingerprint, f.InjectionFlag, f.FirstSeen, f.LastSeen, f.OccurrenceCount,
    scope = f.Attributes.GetValueOrDefault("scope") ?? "pr", decision = svc.Store.LatestDecision(f.FindingId),
    fixes = svc.Store.FixesForFinding(f.FindingId).Select(x => new { x.AttemptNo, x.VerificationResult, x.PrUrl, x.Branch }),
}).ToList();
static object ControlsView(AgentServices svc) => new
{
    kill_switch = svc.Kill.IsOn, config = svc.Cfg.Label, budgets = svc.Cfg.Policies.Budgets, thresholds = svc.Cfg.Policies.Thresholds, retries = svc.Cfg.Policies.Retries,
    authority = svc.Cfg.Policies.Authority, routes = svc.Cfg.Routing.Routes, tiers = svc.Cfg.Gateway.Tiers.ToDictionary(t => t.Key, t => t.Value.Select(d => d.Model)),
    tool_allow_lists = svc.Cfg.Routing.Agents,
};

// Usage query string: range=today|7d|30d or from/to (IST dates, inclusive), model, agent, provider, task, run, synthetic=include|exclude|only.
static bool TryUsageFilter(HttpRequest q, out UsageFilter f, out string? error)
{
    var qs = q.Query; error = null;
    DateOnly? D(string k) => DateOnly.TryParseExact(qs[k].FirstOrDefault(), "yyyy-MM-dd", out var d) ? d : null;
    var (pf, pt) = UsageMath.Preset(qs["range"].FirstOrDefault() ?? "7d");
    string? S(string k) => qs[k].FirstOrDefault() is { Length: > 0 } v ? v : null;
    f = new UsageFilter
    {
        From = D("from") ?? pf, To = D("to") ?? pt, Model = S("model"), Agent = S("agent"), Provider = S("provider"), Task = S("task"),
        Run = Guid.TryParse(qs["run"].FirstOrDefault(), out var g) ? g : null,
        Synthetic = S("synthetic") is "exclude" or "only" ? S("synthetic")! : "include",
    };
    if (f.To < f.From) { error = "to is before from"; return false; }
    if (f.Days > 366) { error = "range is limited to 366 days"; return false; }
    return true;
}
static object FilterView(UsageFilter f) => new
{
    from = f.From, to = f.To, days = f.Days, tz = "Asia/Kolkata (IST, UTC+5:30)", from_utc = f.Window.FromUtc, to_utc_exclusive = f.Window.ToUtcExclusive,
    f.Model, f.Agent, f.Provider, f.Task, f.Run, f.Synthetic,
};
static string UsageCsv(IEnumerable<ModelUsage> rows)
{
    static string C(object? v) { var s = Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? ""; return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s; }
    var sb = new System.Text.StringBuilder("ts_utc,ts_ist,run_id,repo,pr_number,mode,agent_id,task_purpose,tier,model_id,model_version,deployment,provider,input_tokens,output_tokens,total_tokens,latency_ms,cost_usd,price_source,outcome,outcome_detail,schema_attempts,fallback_used,cache_hit,synthetic\n");
    foreach (var u in rows)
        sb.AppendJoin(',', new object?[] { u.TsUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"), u.TsIst, u.RunId, u.Repo, u.PrNumber, u.Mode, u.AgentId, u.TaskPurpose, u.Tier, u.ModelId, u.ModelVersion,
            u.Deployment, u.Provider, u.InputTokens, u.OutputTokens, u.TotalTokens, u.LatencyMs, u.Cost, u.PriceSource, u.Outcome, u.OutcomeDetail, u.SchemaAttempts,
            u.FallbackUsed ? 1 : 0, u.CacheHit ? 1 : 0, u.Synthetic ? 1 : 0 }.Select(C)).Append('\n');
    return sb.ToString();
}
static object UsageReplay(AgentServices s, RunRecord run)
{
    var f = new UsageFilter { From = UsageMath.IstDay(run.StartedAt).AddDays(-1), To = UsageMath.IstDay(run.EndedAt ?? DateTime.UtcNow).AddDays(1), Run = run.RunId, Synthetic = "exclude" };
    var rows = s.Store.QueryUsage(f);
    var day = new UsageFilter { From = UsageMath.IstDay(run.StartedAt), To = UsageMath.IstDay(run.EndedAt ?? run.StartedAt), Run = run.RunId, Synthetic = "exclude" };
    return new
    {
        note = "Per-call usage of this recorded run (real rows only). Local Ollama models cost $0.",
        filter = FilterView(day), calls = rows, totals = UsageAggregator.Totals(rows),
        by = UsageAggregator.GroupKeys.Where(k => k != "run").ToDictionary(k => k, k => UsageAggregator.Group(rows, k, day.From, day.To)),   // single run: no run grouping
        budget = UsageAggregator.Budget(rows, rows, day, s.Cfg.Policies, run.EndedAt ?? run.StartedAt),
        // lets the replay UI run the same filters/aggregation as /api/usage/* in the browser ("today" = the run's IST day)
        as_of = UsageMath.IstDay(run.EndedAt ?? run.StartedAt),
        policy = new { budgets = s.Cfg.Policies.Budgets.ToDictionary(kv => kv.Key, kv => new { tokens = kv.Value.Tokens }), usage_budgets = s.Cfg.Policies.UsageBudgets },
    };
}
// SYNTHETIC usage sample for the replay Usage tab (same generator as `secagent seed-usage`, seed 42). Columnar to keep run.json small.
// Ends on the run's IST day (not "now") so a rebuild is reproducible and the recorded run sits on the last day of the sample.
static object? UsageSample(AgentServices s, RunRecord run, int days)
{
    if (days <= 0) return null;
    var asOf = UsageMath.IstDay(run.EndedAt ?? run.StartedAt);
    var endUtc = UsageMath.IstWindow(asOf, asOf).ToUtcExclusive.AddSeconds(-1);
    var cap = s.Cfg.Policies.Budgets.TryGetValue("pr", out var b) ? b.Tokens : 60000;
    var rows = SyntheticUsage.Generate(s.Cfg.Gateway, days, 42, endUtc, cap);
    return new
    {
        note = "SYNTHETIC sample data, not real usage: generated by SyntheticUsage (seed 42) for fictional synthetic-org/* repos. Hosted model names and prices are PLACEHOLDERS from rules/gateway/models.yaml, not real or current prices.",
        seed = 42, days, as_of = asOf,
        price_book = s.Cfg.Gateway.PriceBook,
        columns = new[] { "ts_utc", "run_id", "repo", "pr_number", "mode", "agent_id", "task_purpose", "tier", "model_id", "model_version", "deployment", "provider",
                          "input_tokens", "output_tokens", "latency_ms", "cost", "price_source", "outcome", "outcome_detail", "schema_attempts", "fallback_used", "cache_hit" },
        rows = rows.Select(r => new object?[] { DateTime.SpecifyKind(r.TsUtc, DateTimeKind.Utc), r.RunId, r.Repo, r.PrNumber, r.Mode, r.AgentId, r.TaskPurpose, r.Tier, r.ModelId,
                          r.ModelVersion, r.Deployment, r.Provider, r.InputTokens, r.OutputTokens, r.LatencyMs, r.Cost, r.PriceSource, r.Outcome, r.OutcomeDetail, r.SchemaAttempts,
                          r.FallbackUsed ? 1 : 0, r.CacheHit ? 1 : 0 }),
    };
}

record StartRun(string? Repo, int? Pr, bool? Fresh);
record Review(string? Decision);
record Kill(bool On, string? By);

static class LocalEnv
{
    public static void Load()
    {
        var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".secagent", "secagent.env");
        if (!File.Exists(file)) return;
        foreach (var line in File.ReadAllLines(file))
        {
            var i = line.IndexOf('=');
            if (i <= 0 || line.TrimStart().StartsWith('#')) continue;
            var k = line[..i].Trim();
            if (Environment.GetEnvironmentVariable(k) == null) Environment.SetEnvironmentVariable(k, line[(i + 1)..].Trim());
        }
    }
    public static string FindRepoRoot()
    {
        foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
            for (var d = new DirectoryInfo(start); d != null; d = d.Parent)
                if (Directory.Exists(Path.Combine(d.FullName, "rules")) && File.Exists(Path.Combine(d.FullName, "SecAgent.slnx"))) return d.FullName;
        throw new InvalidOperationException("Cannot find repo root (folder with rules/ and SecAgent.slnx)");
    }
}

static class Otel
{
    public static TracerProviderBuilder Configure(TracerProviderBuilder t, string dataRoot)
    {
        t.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("secagent"))
         .AddSource(Telemetry.SourceName, "SecAgent.GenAI", "Microsoft.Agents.AI.Workflows", "Experimental.Microsoft.Agents.AI")
         .AddProcessor(new SimpleActivityExportProcessor(new JsonlFileExporter(Path.Combine(dataRoot, "traces"))));
        if (Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT") is { Length: > 0 }) t.AddOtlpExporter();
        if (Environment.GetEnvironmentVariable("SECAGENT_OTEL_CONSOLE") == "1") t.AddConsoleExporter();
        return t;
    }
}

/// <summary>Writes finished spans as JSON lines (stands in for App Insights in slice 1).</summary>
sealed class JsonlFileExporter : BaseExporter<Activity>
{
    readonly string _file;
    readonly object _lock = new();
    public JsonlFileExporter(string dir) { Directory.CreateDirectory(dir); _file = Path.Combine(dir, $"spans-{DateTime.UtcNow:yyyyMMdd}.jsonl"); }
    public override ExportResult Export(in Batch<Activity> batch)
    {
        var lines = new List<string>();
        foreach (var a in batch)
            lines.Add(JsonSerializer.Serialize(new
            {
                trace_id = a.TraceId.ToString(), span_id = a.SpanId.ToString(), parent = a.ParentSpanId.ToString(), name = a.DisplayName, source = a.Source.Name,
                start = a.StartTimeUtc, ms = a.Duration.TotalMilliseconds, status = a.Status.ToString(),
                tags = a.TagObjects.Where(t => !t.Key.Contains("message") && !t.Key.Contains("content")).ToDictionary(t => t.Key, t => t.Value?.ToString()),
            }));
        lock (_lock) File.AppendAllLines(_file, lines);
        return ExportResult.Success;
    }
}

static class ConsoleFeed
{
    public static void Print(string json)
    {
        using var d = JsonDocument.Parse(json);
        var t = d.RootElement.GetProperty("type").GetString();
        var x = d.RootElement.GetProperty("data");
        string S(string p) => x.TryGetProperty(p, out var v) && v.ValueKind != JsonValueKind.Null ? v.ToString() : "";
        var ts = DateTime.Now.ToString("HH:mm:ss");
        switch (t)
        {
            case "agent": Console.WriteLine($"{ts}  [{S("id"),-9}] {S("state"),-8} {S("text")}"); break;
            case "entry": Console.WriteLine($"{ts}  {S("agent"),-9} ▸ {S("text")}{(S("think").Length > 0 ? "\n            ↳ " + S("think") : "")}"); break;
            case "tool" when S("state") != "running": Console.WriteLine($"{ts}      tool {(S("state") == "ok" ? "✓" : "✗")} {S("name")} {S("args")} ({S("ms")}ms)"); break;
            case "pr": Console.WriteLine($"{ts}  PR #{S("num")} {S("url")}"); break;
            case "detail" when x.GetProperty("detail").GetProperty("type").GetString() is "fail" or "quote":
                Console.WriteLine($"{ts}      {x.GetProperty("detail")}"); break;
        }
    }
}
