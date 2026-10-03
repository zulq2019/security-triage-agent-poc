using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Http;
using YamlDotNet.RepresentationModel;
using Xunit;

namespace SecAgent.Tests;

/// <summary>End to end over real HTTP: Kestrel on 127.0.0.1:random → MapIntake → real HMAC check, parsers, ledger, raw store → fake run starter.</summary>
public sealed class IntakeHttpTests : IAsyncLifetime
{
    readonly IntakeKit _kit = new(o => o.MaxBodyBytes = 64 * 1024);
    WebApplication _app = null!;
    readonly HttpClient _http = new();
    string _base = "";

    public async Task InitializeAsync()
    {
        var b = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        b.Logging.ClearProviders();
        b.WebHost.UseUrls("http://127.0.0.1:0");
        _kit.Wire(b.Services);   // same composition root as the dashboard (services.AddSecAgentIntake), test doubles for the pipeline ports
        _app = b.Build();
        _app.MapSecAgentIntake();
        await _app.StartAsync();
        _base = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First().TrimEnd('/');
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        _kit.Dispose();
    }

    HttpRequestMessage Signed(IntakeMetadata m, byte[] body, string? secret = IntakeKit.Secret, long? ts = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, $"{_base}/api/intake/{m.Format}") { Content = new ByteArrayContent(body) };
        req.Content.Headers.ContentType = new("application/json");
        var headers = IntakeSignature.HeadersFor(m);
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);
        var t = (ts ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
        req.Headers.TryAddWithoutValidation(IntakeHeaders.Timestamp, t);
        if (secret != null) req.Headers.TryAddWithoutValidation(IntakeHeaders.Signature, IntakeSignature.Sign(secret, m.Format, headers, t, body));
        return req;
    }

    async Task<(HttpStatusCode code, JsonElement body)> Send(HttpRequestMessage req)
    {
        using var res = await _http.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();
        return (res.StatusCode, text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    [Fact]
    public async Task Signed_sarif_is_accepted_once_then_deduped_and_listed()
    {
        var body = IntakeKit.Fixture("blackduck-sca.sarif.json");
        var meta = IntakeKit.Meta();

        var (c1, b1) = await Send(Signed(meta, body));
        Assert.Equal(HttpStatusCode.Accepted, c1);
        Assert.Equal("accepted", b1.GetProperty("status").GetString());
        Assert.Equal(6, b1.GetProperty("findings").GetInt32());

        // Same workflow run retried (same body, new timestamp and signature) → 200 duplicate, no second run.
        var (c2, b2) = await Send(Signed(meta, body));
        Assert.Equal(HttpStatusCode.OK, c2);
        Assert.Equal("duplicate", b2.GetProperty("status").GetString());
        Assert.Single(_kit.Runs.Requests);
        var run = _kit.Runs.Requests.Single();
        Assert.Equal("synthetic-org/sample-orders", run.Repo);
        Assert.Equal(7, run.PrNumber);

        // Same idempotency key, different content → conflict.
        var (c3, _) = await Send(Signed(meta, IntakeKit.Fixture("secret.sarif.json")));
        Assert.Equal(HttpStatusCode.Conflict, c3);
        Assert.Single(_kit.Runs.Requests);

        var list = JsonDocument.Parse(await _http.GetStringAsync($"{_base}/api/intake")).RootElement;
        var row = Assert.Single(list.EnumerateArray());
        Assert.Equal(meta.HeadSha, row.GetProperty("head_sha").GetString());
        Assert.Equal(6, row.GetProperty("findings").GetInt32());
        Assert.DoesNotContain("CVE-2099", list.GetRawText());   // listing never carries payload content
    }

    [Fact]
    public async Task Rapid_scan_json_is_accepted()
    {
        var (code, body) = await Send(Signed(IntakeKit.Meta(IntakeFormats.BlackDuckRapid, runId: "2002-1"), IntakeKit.Fixture("blackduck-rapid.json")));
        Assert.Equal(HttpStatusCode.Accepted, code);
        Assert.True(body.GetProperty("findings").GetInt32() > 0);
        Assert.Single(_kit.Runs.Requests);
    }

    [Fact]
    public async Task Unsigned_wrong_secret_stale_or_tampered_requests_are_401()
    {
        var body = IntakeKit.Fixture("blackduck-sca.sarif.json");
        var meta = IntakeKit.Meta();
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Signed(meta, body, secret: null))).code);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Signed(meta, body, secret: "not-the-secret"))).code);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Signed(meta, body, ts: DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds()))).code);

        // Signed for PR 7, header rewritten to PR 8 in transit → signature no longer matches.
        var req = Signed(meta, body);
        req.Headers.Remove(IntakeHeaders.Pr);
        req.Headers.TryAddWithoutValidation(IntakeHeaders.Pr, "8");
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(req)).code);
        Assert.Empty(_kit.Runs.Requests);
    }

    [Fact]
    public async Task Oversize_invalid_and_unknown_format_are_rejected_without_starting_runs()
    {
        var big = Encoding.UTF8.GetBytes("{\"version\":\"2.1.0\",\"runs\":[],\"pad\":\"" + new string('x', 70 * 1024) + "\"}");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Send(Signed(IntakeKit.Meta(runId: "big"), big))).code);

        var (bad, badBody) = await Send(Signed(IntakeKit.Meta(runId: "bad"), Encoding.UTF8.GetBytes("{\"version\":\"1.0\",\"runs\":{}}")));
        Assert.True(bad is HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity, $"got {(int)bad}");
        Assert.Equal("rejected", badBody.GetProperty("status").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, (await Send(Signed(IntakeKit.Meta(runId: "junk"), Encoding.UTF8.GetBytes("not json at all")))).code);

        var unknown = IntakeKit.Meta() with { Format = "xml-report" };
        Assert.Equal(HttpStatusCode.NotFound, (await Send(Signed(unknown, Encoding.UTF8.GetBytes("{}")))).code);
        Assert.Empty(_kit.Runs.Requests);
    }

    [Fact]
    public async Task Bad_metadata_is_400_and_disallowed_repo_is_403()
    {
        var body = IntakeKit.Fixture("blackduck-sca.sarif.json");
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(Signed(IntakeKit.Meta(sha: "not-a-sha"), body))).code);
        _app.Services.GetRequiredService<IOptions<IntakeOptions>>().Value.AllowedRepos = ["synthetic-org/*"];   // test-only runtime change
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Signed(IntakeKit.Meta(repo: "other-org/app"), body))).code);
        Assert.Equal(HttpStatusCode.Accepted, (await Send(Signed(IntakeKit.Meta(runId: "allowed"), body))).code);
    }

    // ---- The example GitHub workflows: run their actual sign-and-POST bash against this server. ----------------------------

    [Fact]
    public async Task Example_pr_workflow_push_step_signs_and_posts_accepted()
    {
        var res = await RunWorkflowStep("blackduck-push.yml", "Sign and push to the Security Triage Agent", new()
        {
            ["RESULT_FILE"] = FixturePath("blackduck-rapid.json"), ["RESULT_FORMAT"] = IntakeFormats.BlackDuckRapid,
            ["SA_PR"] = "42", ["SA_REF"] = "feature/synthetic-pr", ["SA_SHA"] = "fedcba9876543210fedcba9876543210fedcba98", ["SA_RUN_ID"] = "555-1",
        });
        if (res == null) return;   // bash/curl/python3 not available on this machine
        Assert.True(res.Value.exit == 0, res.Value.output);
        Assert.Contains("intake: HTTP 202", res.Value.output);
        var run = Assert.Single(_kit.Runs.Requests);
        Assert.Equal(42, run.PrNumber);
        Assert.Equal("fedcba9876543210fedcba9876543210fedcba98", run.HeadSha);
        Assert.Equal(IntakeFormats.BlackDuckRapid, _kit.Ledger.All().Single(r => r.IntakeId == run.IntakeId).Meta!.Format);
        Assert.Equal("pr", run.Mode);
    }

    [Fact]
    public async Task Example_nightly_workflow_push_step_posts_backlog_mode()
    {
        var res = await RunWorkflowStep("blackduck-nightly-main.yml", "Sign and push SARIF (backlog mode, no PR)", new()
        {
            ["RESULT_FILE"] = FixturePath("blackduck-sca.sarif.json"), ["SA_SHA"] = "1111111111111111111111111111111111111111", ["SA_RUN_ID"] = "777-1",
        });
        if (res == null) return;
        Assert.True(res.Value.exit == 0, res.Value.output);
        var run = Assert.Single(_kit.Runs.Requests);
        Assert.Null(run.PrNumber);
        Assert.Equal("main", run.Ref);
        Assert.Equal("backlog", run.Mode);
    }

    [Fact]
    public void Example_workflows_are_not_active_and_use_the_documented_secrets()
    {
        var dir = Path.Combine(TestEnv.RepoRoot, ".github", "workflows", "examples");
        foreach (var f in new[] { "blackduck-push.yml", "blackduck-nightly-main.yml" })
        {
            var text = File.ReadAllText(Path.Combine(dir, f));
            Assert.Contains("secrets.INTAKE_URL", text);
            Assert.Contains("secrets.INTAKE_HMAC_SECRET", text);
            Assert.Contains("EXAMPLE ONLY", text);
        }
        // GitHub only runs workflows directly in .github/workflows; nothing Black Duck related is placed there.
        var active = Path.Combine(TestEnv.RepoRoot, ".github", "workflows");
        Assert.DoesNotContain(Directory.GetFiles(active, "*.yml"), p => Path.GetFileName(p).Contains("blackduck", StringComparison.OrdinalIgnoreCase));
    }

    static string FixturePath(string name) => Path.Combine(TestEnv.RepoRoot, "tests", "SecAgent.Tests", "Fixtures", "intake", name);

    /// <summary>Loads the step from the example YAML, maps its env block (every ${{ }} expression must be covered by the test, so renaming
    /// a variable in the workflow breaks this test), and runs its `run:` script with bash.</summary>
    async Task<(int exit, string output)?> RunWorkflowStep(string file, string stepName, Dictionary<string, string> values)
    {
        foreach (var tool in new[] { "bash", "curl", "python3", "sha256sum" }) if (!OnPath(tool)) return null;

        var yaml = new YamlStream();
        using (var r = new StreamReader(Path.Combine(TestEnv.RepoRoot, ".github", "workflows", "examples", file))) yaml.Load(r);
        var jobs = (YamlMappingNode)((YamlMappingNode)yaml.Documents[0].RootNode)["jobs"];
        var step = jobs.Children.Values.Cast<YamlMappingNode>()
            .SelectMany(j => ((YamlSequenceNode)j["steps"]).Children.Cast<YamlMappingNode>())
            .Single(s => s.Children.TryGetValue("name", out var n) && n.ToString() == stepName);
        var script = step["run"].ToString();
        Assert.DoesNotContain("${{", script);   // all inputs via env: (injection-safe)

        var known = new Dictionary<string, string>(values)
        {
            ["INTAKE_URL"] = _base, ["INTAKE_HMAC_SECRET"] = IntakeKit.Secret, ["SA_REPO"] = "synthetic-org/sample-orders",
        };
        var psi = new ProcessStartInfo("bash", ["-c", script]) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.Environment["RUNNER_TEMP"] = _kit.Root;
        Directory.CreateDirectory(_kit.Root);
        foreach (var (k, v) in ((YamlMappingNode)step["env"]).Children.Select(c => (c.Key.ToString(), c.Value.ToString())))
        {
            if (known.TryGetValue(k, out var given)) psi.Environment[k] = given;
            else if (!v.Contains("${{")) psi.Environment[k] = v;   // literal in the workflow (e.g. SA_SCANNER: blackduck)
            else Assert.Fail($"workflow env {k} = '{v}' is not mapped by the test");
        }
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await p.WaitForExitAsync(cts.Token);
        return (p.ExitCode, await stdout + await stderr);
    }

    static bool OnPath(string tool) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Any(d => File.Exists(Path.Combine(d, tool)));
}
