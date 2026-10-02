using System.Diagnostics;
using System.Text.Json;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using SecAgent.Agents;
using SecAgent.Agents.Workflow;
using SecAgent.Core;

// ---------------------------------------------------------------------------------------------------------------
// secagent serve [--port 8790]                         dashboard (live run via SSE) + API
// secagent run --repo owner/name --pr N [--fresh]      CLI run (local runner; ends at "waiting for human review")
// secagent reset-db                                    dev only: clear the local SecAgent database (demo reset)
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
    st.ResetAll();
    Console.WriteLine("SecAgent database cleared (local dev).");
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

// ------------------------------------------------ dashboard ------------------------------------------------
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, WebRootPath = Path.Combine(repoRoot, "src", "SecAgent.Dashboard", "wwwroot") });
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("secagent-dashboard"))
    .WithTracing(t => Otel.Configure(t, dataRoot));
var svc = AgentServices.Create(repoRoot, dataRoot, sql);
var runner = new RunService(svc);
builder.Services.AddSingleton(svc);
var app = builder.Build();
var json = new JsonSerializerOptions(Schema.Json);
app.UseDefaultFiles();
app.UseStaticFiles();

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
app.MapGet("/api/findings", () => Results.Json(svc.Store.ListFindings().Select(f => new
{
    f.FindingId, f.IssueType, f.Title, f.SourceScanner, f.ScannerRuleId, f.SeverityScanner, f.SeverityEffective, f.Status, f.Bucket, f.FilePath, f.ComponentName,
    f.ComponentVersion, f.FixedVersion, f.CveIds, f.LicenceId, f.Fingerprint, f.InjectionFlag, f.FirstSeen, f.LastSeen, f.OccurrenceCount,
    scope = f.Attributes.GetValueOrDefault("scope") ?? "pr", decision = svc.Store.LatestDecision(f.FindingId),
    fixes = svc.Store.FixesForFinding(f.FindingId).Select(x => new { x.AttemptNo, x.VerificationResult, x.PrUrl, x.Branch }),
}), json));
app.MapGet("/api/controls", () => Results.Json(new
{
    kill_switch = svc.Kill.IsOn, config = svc.Cfg.Label, budgets = svc.Cfg.Policies.Budgets, thresholds = svc.Cfg.Policies.Thresholds, retries = svc.Cfg.Policies.Retries,
    authority = svc.Cfg.Policies.Authority, routes = svc.Cfg.Routing.Routes, tiers = svc.Cfg.Gateway.Tiers.ToDictionary(t => t.Key, t => t.Value.Select(d => d.Model)),
    tool_allow_lists = svc.Cfg.Routing.Agents,
}, json));
app.MapPost("/api/controls/killswitch", (Kill k) =>
{
    svc.Kill.Set(k.On, k.By ?? "dashboard");
    foreach (var st in RunRegistry.Active) st.Feed.Publish("guards", new { kill = svc.Kill.IsOn });
    return Results.Ok(new { kill_switch = svc.Kill.IsOn });
});
var port = Arg("--port") ?? Environment.GetEnvironmentVariable("SECAGENT_PORT") ?? "8795";
Console.WriteLine($"Security Triage & Fix Agent dashboard on http://localhost:{port} (config {svc.Cfg.Label})");
app.Run($"http://127.0.0.1:{port}");
return 0;

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
