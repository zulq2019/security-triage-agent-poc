using Xunit;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Agents;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Scanners;
using SecAgent.Agents.Workflow;
using SecAgent.Connectors;
using SecAgent.Connectors.Fakes;
using SecAgent.Core;

namespace SecAgent.Tests.Connectors;

/// <summary>Database for pipeline runs against fakes. SECAGENT_E2E_SQL points at an isolated database when one is available (CI); the local
/// login can neither CREATE DATABASE nor create tables in tempdb, so by default the shared dev database is used and every row a test
/// writes is deleted again (by run id, synthetic repository and fix-group ledger keys). Tests that write runs share the
/// "SharedDevDatabase" collection with the golden tests, so the golden tests never see a synthetic run as the latest completed one.</summary>
public static class ConnectorE2EDatabase
{
    public const string Collection = "SharedDevDatabase";
    static readonly Lazy<string> Conn = new(() =>
    {
        var cs = Environment.GetEnvironmentVariable("SECAGENT_E2E_SQL") ?? TestEnv.Sql ?? throw new InvalidOperationException("SECAGENT_SQL not set");
        var store = new SqlStore(cs);
        store.EnsureSchema(Path.Combine(TestEnv.RepoRoot, "db", "schema.sql"));
        store.EnsureMigrations(Path.Combine(TestEnv.RepoRoot, "db", "migrations"));
        return cs;
    });
    public static string ConnectionString => Conn.Value;

    /// <summary>Deletes everything a synthetic test run wrote. Table names come from INFORMATION_SCHEMA (dbo, column run_id); values are parameters.</summary>
    public static void Cleanup(IEnumerable<Guid> runIds, string? syntheticRepo = null, IEnumerable<string>? ledgerKeys = null)
    {
        using var c = new SqlConnection(ConnectionString);
        c.Open();
        var tables = new List<string>();
        using (var q = new SqlCommand("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND COLUMN_NAME = 'run_id'", c))
        using (var r = q.ExecuteReader()) while (r.Read()) tables.Add(r.GetString(0));
        foreach (var id in runIds)
            foreach (var t in tables)
            {
                using var d = new SqlCommand($"DELETE FROM dbo.[{t.Replace("]", "]]")}] WHERE run_id = @id", c);
                d.Parameters.AddWithValue("@id", id);
                d.ExecuteNonQuery();
            }
        if (syntheticRepo != null)
        {
            using var d = new SqlCommand("DELETE FROM dbo.Finding WHERE repo = @repo", c);
            d.Parameters.AddWithValue("@repo", syntheticRepo);
            d.ExecuteNonQuery();
        }
        foreach (var key in ledgerKeys ?? [])
        {
            using var d = new SqlCommand("DELETE FROM dbo.IdempotencyLedger WHERE [key] = @k", c);
            d.Parameters.AddWithValue("@k", key);
            d.ExecuteNonQuery();
        }
    }
}

static class Synthetic
{
    public const string TriageJson = "{\"decision\":\"fix\",\"severity_effective\":\"medium\",\"reason\":\"Synthetic: committed binary should come from the artefact feed\",\"confidence\":0.9}";
    public const string SummaryJson = "{\"what_was_wrong\":\"A compiled binary was committed (synthetic)\",\"what_changed\":\"Removed it and added an ignore rule\",\"risk\":\"Low\"}";

    public static ContextPack Pack(string agent = "triage") => new() { RunId = Guid.NewGuid(), AgentId = agent, MaskingApplied = true, TokenTotal = 200, TokenBudget = 8000,
        SystemText = "You are a synthetic test agent.", UserText = "Synthetic finding: committed binary lib/helper.dll",
        Components = [new() { Type = "finding", Content = "synthetic finding", Included = true, Required = true, SourceRef = "test" }] };
}

/// <summary>The model gateway on the model provider port: routing, schema output, failover and configuration errors (fake provider).</summary>
[Collection(ConnectorE2EDatabase.Collection)]
public class GatewayOnModelPortTests : IDisposable
{
    readonly List<Guid> _runs = [];
    public void Dispose() => ConnectorE2EDatabase.Cleanup(_runs);
    ContextPack Pack() { var p = Synthetic.Pack(); _runs.Add(p.RunId); return p; }

    (ModelGateway Gateway, FakeConnectorWorld World) Build()
    {
        var (_, world, ports) = ConnectorTestKit.Fakes();
        var store = new SqlStore(ConnectorE2EDatabase.ConnectionString);
        var g = new ModelGateway(TestEnv.Cfg, store, new KillSwitch(Path.Combine(Path.GetTempPath(), "ks-" + Guid.NewGuid()), false),
            new SchemaValidator(TestEnv.Cfg, new JsonSchemaCache()), ports);
        return (g, world);
    }

    [Fact]
    public async Task A_call_goes_through_the_model_port_with_the_json_schema_and_counts_tokens()
    {
        var (g, world) = Build();
        world.Models.RespondToSchema("triage_output", _ => Synthetic.TriageJson);
        var budget = new RunBudget(60000, 0);
        var r = await g.CallAsync(Pack(), new CallSpec("triage", "triage-output", Severity: "medium", Repo: "acme/app"), budget, default);
        Assert.Equal("fix", r.Json.GetProperty("decision").GetString());
        Assert.True(r.Routing.TokensIn > 0 && r.Routing.TokensOut > 0);
        Assert.Equal(r.Routing.TokensIn + r.Routing.TokensOut, budget.Used);
        var call = Assert.Single(world.InteractionsFor(ConnectorKind.ModelProvider, "model.complete"));
        Assert.Equal(("triage_output", "triage"), (call.Args["output"], call.Args["agent"]));
    }

    [Fact]
    public async Task Invalid_output_is_retried_then_rejected_by_the_schema()
    {
        var (g, world) = Build();
        world.Models.RespondToSchema("triage_output", _ => "{\"decision\":\"maybe\"}");
        await Assert.ThrowsAsync<SchemaInvalidException>(() => g.CallAsync(Pack(), new CallSpec("triage", "triage-output", Repo: "acme/app"), new RunBudget(60000, 0), default));
        Assert.Equal(TestEnv.Cfg.Policies.Retries.MaxSchemaRetries + 1, world.InteractionsFor(ConnectorKind.ModelProvider, "model.complete").Count);
    }

    [Fact]
    public async Task A_transient_provider_error_fails_over_to_the_next_deployment()
    {
        var (g, world) = Build();
        world.Models.RespondToSchema("triage_output", _ => Synthetic.TriageJson);
        world.FailNext("model.complete", new ConnectorException("synthetic 503", true, System.Net.HttpStatusCode.ServiceUnavailable));
        var r = await g.CallAsync(Pack(), new CallSpec("triage", "triage-output", Repo: "acme/app"), new RunBudget(60000, 0), default);
        if (r.Routing.FallbackUsed) Assert.Contains("failover", r.Routing.Reason);
        else Assert.Fail("expected a failover to a second deployment in the tier (rules/gateway/models.yaml lists more than one)");
    }

    [Fact]
    public async Task A_configuration_error_is_model_unavailable_without_failover()
    {
        var (g, world) = Build();
        world.FailNext("model.complete", new ConnectorConfigurationException("Environment variable OPENAI_API_KEY is not set"), times: 5);
        var e = await Assert.ThrowsAsync<ModelUnavailableException>(() => g.CallAsync(Pack(), new CallSpec("triage", "triage-output", Repo: "acme/app"), new RunBudget(60000, 0), default));
        Assert.Contains("OPENAI_API_KEY", e.Message);
        Assert.Single(world.InteractionsFor(ConnectorKind.ModelProvider, "model.complete:fault"));
    }
}

/// <summary>Full pipeline run against fakes: local bare git repo (synthetic), fake GitHub / model / Jira / Teams. Rows are cleaned up.</summary>
[Collection(ConnectorE2EDatabase.Collection)]
public class PipelineEndToEndOnFakesTests
{
    const string Repo = "acme/synthetic-app";

    static async Task<string> Git(string dir, params string[] args)
    {
        var psi = new ProcessStartInfo("git") { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-c", "user.name=SecAgent Test", "-c", "user.email=test@secagent.invalid", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false" }.Concat(args))
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = await p.StandardOutput.ReadToEndAsync();
        var stderr = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (p.ExitCode != 0) throw new InvalidOperationException($"git {string.Join(' ', args)}: {stderr}");
        return stdout.Trim();
    }

    /// <summary>main = README only; feature/x adds a synthetic PE file (MZ header + zeros). Published as refs/pull/7/head too.</summary>
    static async Task<(string Bare, string HeadSha, string BaseSha)> SyntheticRepoAsync(string root)
    {
        var work = Directory.CreateDirectory(Path.Combine(root, "src-repo")).FullName;
        var bare = Path.Combine(root, "remote.git");
        await Git(root, "init", "--quiet", "--bare", bare);
        await Git(work, "init", "--quiet");
        await File.WriteAllTextAsync(Path.Combine(work, "README.md"), "# Synthetic test repository\n");
        await File.WriteAllTextAsync(Path.Combine(work, ".gitignore"), "bin/\nobj/\n");
        // The verifier runs `dotnet test` and needs at least one passing test (same package versions as this test project: already in the NuGet cache).
        await File.WriteAllTextAsync(Path.Combine(work, "SyntheticTests.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><TargetFramework>net10.0</TargetFramework><IsPackable>false</IsPackable><NuGetAudit>false</NuGetAudit></PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.10.1" />
                <PackageReference Include="xunit" Version="2.9.3" />
                <PackageReference Include="xunit.runner.visualstudio" Version="3.1.4" />
              </ItemGroup>
            </Project>
            """);
        await File.WriteAllTextAsync(Path.Combine(work, "SmokeTests.cs"), "public class SmokeTests { [Xunit.Fact] public void Adds() => Xunit.Assert.Equal(2, 1 + 1); }\n");
        await Git(work, "add", "-A");
        await Git(work, "commit", "--quiet", "-m", "base");
        var baseSha = await Git(work, "rev-parse", "HEAD");
        await Git(work, "checkout", "--quiet", "-b", "feature/x");
        Directory.CreateDirectory(Path.Combine(work, "lib"));
        var pe = new byte[256]; pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        await File.WriteAllBytesAsync(Path.Combine(work, "lib", "helper.dll"), pe);
        await Git(work, "add", "-A");
        await Git(work, "commit", "--quiet", "-m", "add helper (synthetic binary)");
        var headSha = await Git(work, "rev-parse", "HEAD");
        await Git(work, "push", "--quiet", bare, "main", "feature/x", "feature/x:refs/pull/7/head");
        return (bare, headSha, baseSha);
    }

    [Fact]
    public async Task A_pr_run_executes_end_to_end_against_fake_connectors()
    {
        var root = Directory.CreateTempSubdirectory("secagent-e2e-").FullName;
        Guid? runId = null; List<string> ledger = [];
        try
        {
            var (bare, headSha, baseSha) = await SyntheticRepoAsync(root);
            var world = new FakeConnectorWorld();
            var repo = world.SourceControl.AddRepository(ConnectorTestKit.Tenant, Repo);
            repo.CloneUrl = bare;
            repo.AddPullRequest(7, "Add helper", "feature/x", "main", headSha, baseSha, null, new ChangedFile("lib/helper.dll", "added", 0, 0));
            world.Models.RespondToSchema("triage_output", _ => Synthetic.TriageJson).RespondToSchema("summarise_fix_output", _ => Synthetic.SummaryJson);
            using var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.AddFakeConnectors(world));
            var ports = PipelineConnectors.From(sp);
            var s = AgentServices.Create(TestEnv.RepoRoot, Path.Combine(root, "data"), ConnectorE2EDatabase.ConnectionString, ports, cfg: TestEnv.Cfg,
                scanners: (cfg, _) => [new BinaryCheckAdapter(cfg)]);

            var h = await new RunService(s).StartAsync(Repo, 7, fresh: true, blockForReview: false);
            runId = h.State.Run.RunId;
            await h.Completion.WaitAsync(TimeSpan.FromMinutes(4));
            ledger = h.State.Groups.Keys.Select(FixKeys.PrLedger).ToList();
            var run = s.Store.GetRun(h.State.Run.RunId)!;

            Assert.True(run.Status == "awaiting_human_review", $"run ended {run.Status}: {h.State.StopReason} {h.State.StopDetail}");
            Assert.Equal(ConnectorTestKit.Tenant, h.State.TenantId);
            // Source control: PR read through the port; fix branch published (plain push) and a fix PR opened against the PR head.
            Assert.NotEmpty(world.InteractionsFor(ConnectorKind.SourceControl, "pull_request.get"));
            var fixPr = Assert.Single(repo.PullRequests, p => p.Number != 7);
            Assert.Equal("feature/x", fixPr.BaseRef);
            Assert.Contains(repo.Pushes, p => p.RemoteBranch == fixPr.HeadRef);
            Assert.NotEqual("main", fixPr.HeadRef);
            Assert.Contains(fixPr.Url, h.State.PrUrls);
            Assert.True(FixKeys.PrUrlInRepo(fixPr.Url, Repo));
            // Models: both scripted outputs were requested through the model port.
            Assert.Contains(world.InteractionsFor(ConnectorKind.ModelProvider, "model.complete"), i => i.Args["output"] == "triage_output");
            Assert.Contains(world.InteractionsFor(ConnectorKind.ModelProvider, "model.complete"), i => i.Args["output"] == "summarise_fix_output");
            // Outbound: the run card went to the notifier; any human tasks became idempotent tickets linked to the PR.
            var card = Assert.Single(world.Notifier.Sent(ConnectorTestKit.Tenant));
            Assert.Contains("acme/synthetic-app", card.Title);
            var tasks = s.Store.TasksForRun(run.RunId);
            Assert.Equal(tasks.Count, world.IssueTracker.Issues(ConnectorTestKit.Tenant).Count);
            Assert.All(world.IssueTracker.Issues(ConnectorTestKit.Tenant), i => Assert.Contains(i.Links, l => l.Url.EndsWith("/pull/7")));
            // No merge anywhere in the recorded interactions.
            Assert.DoesNotContain(world.Interactions, i => i.Operation.Contains("merge", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (runId is { } id) ConnectorE2EDatabase.Cleanup([id], Repo, ledger);
            try { Directory.Delete(root, true); } catch { /* git may hold files briefly */ }
        }
    }

    [Fact]
    public async Task Outbound_step_files_human_tasks_once_and_never_fails_the_run_when_connectors_are_down()
    {
        var world = new FakeConnectorWorld();
        using var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.AddFakeConnectors(world));
        var root = Directory.CreateTempSubdirectory("secagent-outbound-").FullName;
        Guid? runId = null;
        try
        {
            var s = AgentServices.Create(TestEnv.RepoRoot, root, ConnectorE2EDatabase.ConnectionString, PipelineConnectors.From(sp), cfg: TestEnv.Cfg, scanners: (_, _) => []);
            var run = new RunRecord { TriggerType = "pr", ScopeJson = "{}", BudgetJson = "{}", ConfigSnapshot = "test" };
            s.Store.InsertRun(run);
            runId = run.RunId;
            var pr = new SecAgent.Agents.Repo.PrInfo(Repo, 7, "Synthetic", "feature/x", "main", "a", "b", 1, 1, 0, "https://scm.fake.invalid/acme/synthetic-app/pull/7");
            var st = new RunState { Run = run, Pr = pr, TenantId = ConnectorTestKit.Tenant, Feed = new Feed(s.Bus, run.RunId), Budget = new RunBudget(1000, 0), FreshTriage = true };
            s.Store.InsertTask(new HumanTask { RunId = run.RunId, Type = "rotation", Title = "Rotate synthetic credential", Details = "synthetic" });
            run.Status = "awaiting_human_review";

            await new RunOutbound(s).PublishOnceAsync(st, default);
            await new RunOutbound(s).PublishOnceAsync(st, default);   // second call is a no-op
            var issue = Assert.Single(world.IssueTracker.Issues(ConnectorTestKit.Tenant));
            Assert.Equal(("SEC", "To Do"), (issue.ProjectKey, issue.Status));
            Assert.Contains("secagent-rotation", issue.Labels);
            Assert.Single(world.Notifier.Sent());

            // Connectors down: logged to the feed, no exception.
            var st2 = new RunState { Run = run, Pr = pr, TenantId = ConnectorTestKit.Tenant, Feed = new Feed(s.Bus, run.RunId), Budget = new RunBudget(1000, 0), FreshTriage = true };
            world.FailNext("issue.find_by_external_id", new ConnectorException("jira down", true), times: 10);
            world.FailNext("issue.create", new ConnectorException("jira down", true), times: 10);
            world.FailNext("notification.send", new ConnectorException("webhook down", true), times: 10);
            await new RunOutbound(s).PublishOnceAsync(st2, default);
            Assert.Single(world.IssueTracker.Issues(ConnectorTestKit.Tenant));
        }
        finally
        {
            if (runId is { } id) ConnectorE2EDatabase.Cleanup([id]);
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
