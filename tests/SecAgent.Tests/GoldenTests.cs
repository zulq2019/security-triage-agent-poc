using System.Diagnostics;
using SecAgent.Core;
using Xunit;
using Xunit.Abstractions;
using YamlDotNet.RepresentationModel;

namespace SecAgent.Tests;

/// <summary>Golden tests (PRD 4.3): check the latest completed PR-mode run in the store against rules/golden-tests/expected-outcomes.yaml.
/// They need the local SQL Server and a completed `secagent run --pr 1` (they read real run output; nothing is mocked).</summary>
[Trait("Category", "Golden")]
// Shares the database collection with the pipeline-on-fakes tests: they write (and then delete) synthetic runs in the same database.
[Collection(SecAgent.Tests.Connectors.ConnectorE2EDatabase.Collection)]
public class GoldenTests(ITestOutputHelper output)
{
    static readonly string[] FixedStates = [Status.FixProposed, Status.Verified, Status.Resolved];
    static readonly string[] HumanStates = [Status.NeedsHuman, Status.SuppressPending, Status.AcceptPending];

    static RunRecord LatestCompletedRun(SqlStore s) =>
        s.Runs(50).FirstOrDefault(r => r.Status is "awaiting_human_review" or "review_recorded")
        ?? throw new InvalidOperationException("No completed run in the store: run `secagent run --repo zulq2019/sec-agent-sample-app --pr 1` first");

    public static IEnumerable<object[]> Cases()
    {
        var y = new YamlStream(); y.Load(new StringReader(File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "rules/golden-tests/expected-outcomes.yaml"))));
        foreach (YamlMappingNode c in (YamlSequenceNode)((YamlMappingNode)y.Documents[0].RootNode)["cases"])
        {
            var match = ((YamlMappingNode)c["match"]).Children.ToDictionary(k => k.Key.ToString(), v => v.Value.ToString());
            var expect = ((YamlMappingNode)c["expect"]).Children.ToDictionary(k => k.Key.ToString(), v => v.Value.ToString());
            yield return [c["id"].ToString(), match, expect];
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Planted_issue_has_expected_outcome(string id, Dictionary<string, string> match, Dictionary<string, string> expect)
    {
        var s = TestEnv.Store();
        var run = LatestCompletedRun(s);
        var findings = s.ListFindings().Where(f => f.Repo == "zulq2019/sec-agent-sample-app").Where(f =>
            (!match.TryGetValue("issue_type", out var it) || f.IssueType == it) &&
            (!match.TryGetValue("file_path", out var fp) || (f.FilePath ?? "").Replace('\\', '/').Equals(fp, StringComparison.OrdinalIgnoreCase)) &&
            (!match.TryGetValue("licence_id", out var li) || (f.LicenceId ?? "").Contains(li, StringComparison.OrdinalIgnoreCase)) &&
            (!match.TryGetValue("component_contains", out var cc) || (f.ComponentName ?? "").Contains(cc, StringComparison.OrdinalIgnoreCase))).ToList();
        Assert.True(findings.Count > 0, $"{id}: no finding matched {string.Join(",", match)}");
        var f = findings[0];
        var decisions = s.DecisionsForRun(run.RunId).Concat(s.Runs(50).SelectMany(r => s.DecisionsForRun(r.RunId))).Where(d => d.FindingId == f.FindingId).ToList();
        var tasks = s.TasksForFinding(f.FindingId);
        var fixes = s.FixesForFinding(f.FindingId);
        output.WriteLine($"{id}: finding {f.Short} status={f.Status} bucket={f.Bucket} injection={f.InjectionFlag} decisions=[{string.Join(",", decisions.Select(d => d.Decision).Distinct())}] tasks=[{string.Join(",", tasks.Select(t => t.Type).Distinct())}] prs=[{string.Join(",", fixes.Select(x => x.PrUrl).Where(u => u != null).Distinct())}]");

        switch (expect.GetValueOrDefault("outcome"))
        {
            case "fixed":
                Assert.Contains(f.Status, FixedStates);
                Assert.Contains(fixes, x => x.VerificationResult == "passed" && x.PrUrl != null);
                break;
            case "suppressed": Assert.Equal(Status.Suppressed, f.Status); break;
            case "needs_human": Assert.Contains(f.Status, HumanStates); break;
        }
        if (expect.TryGetValue("human_task", out var ht)) Assert.Contains(tasks, t => t.Type == ht);
        if (expect.TryGetValue("injection_flag", out var inj) && bool.Parse(inj)) Assert.True(f.InjectionFlag, $"{id}: injection not flagged");
        if (expect.TryGetValue("decision_not", out var dn)) Assert.DoesNotContain(decisions, d => d.Decision == dn);
    }

    [Fact]
    public void D08_no_secret_values_in_any_store()
    {
        // The real planted values are read from the sample repo (synthetic, fake keys) and must not appear anywhere we persist.
        var sample = Environment.GetEnvironmentVariable("SECAGENT_SAMPLE_REPO") ?? "/workspace/sec-agent-sample-app";
        var values = new List<string>();
        foreach (var path in new[] { "src/SampleOrders.Api/appsettings.json", "tests/SampleOrders.Tests/Fixtures/test-settings.json" })
        {
            var text = Git(sample, "show", $"feature/orders-export:{path}");
            values.AddRange(System.Text.RegularExpressions.Regex.Matches(text, @"(AKIA[A-Z2-7]{16}|sk_test_[A-Za-z0-9]{10,}|""SecretAccessKey""\s*:\s*""([^""]+)"")")
                .Select(m => m.Groups[2].Success ? m.Groups[2].Value : m.Value));
        }
        Assert.NotEmpty(values);
        var s = TestEnv.Store();
        var leaks = s.AllText().Where(t => values.Any(v => t.Contains(v, StringComparison.Ordinal))).Take(3).ToList();
        Assert.True(leaks.Count == 0, "secret value found in SQL store: " + string.Join(" | ", leaks.Select(l => l[..Math.Min(80, l.Length)])));
        var dataDir = Path.Combine(TestEnv.RepoRoot, ".data");
        foreach (var dir in new[] { "blob", "traces" }.Select(d => Path.Combine(dataDir, d)).Where(Directory.Exists))
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}raw{Path.DirectorySeparatorChar}")) continue; // raw scanner output container is restricted, masked at write
                var text = File.ReadAllText(file);
                Assert.False(values.Any(v => text.Contains(v, StringComparison.Ordinal)), $"secret value found in {file}");
            }
        output.WriteLine($"checked {values.Count} planted secret values against SQL text columns, blobs and traces");
    }

    [Fact]
    public void D09_every_model_call_has_a_context_pack_and_routing_decision()
    {
        // Every completed run (including idempotent re-runs with zero model calls) must satisfy D-09; at least one must have made model calls.
        var s = TestEnv.Store();
        var runs = s.Runs(50).Where(r => r.Status is "awaiting_human_review" or "review_recorded").ToList();
        Assert.NotEmpty(runs);
        var withCalls = 0;
        foreach (var run in runs)
        {
            var routes = s.RoutingForRun(run.RunId);
            var packs = s.PacksForRun(run.RunId).Select(p => (Guid)p.context_pack_id).ToHashSet();
            foreach (var r in routes) Assert.Contains((Guid)r.context_pack_id, packs);
            var calls = s.Events(run.RunId).Count(e => e.Contains("\"name\":\"model.call\"") && e.Contains("\"state\":\"running\""));
            output.WriteLine($"run {run.RunId}: {routes.Count} routing decisions, {packs.Count} packs, {calls} model.call events");
            Assert.True(routes.Count >= calls, $"{calls} model calls but only {routes.Count} routing decisions");
            if (routes.Count > 0) withCalls++;
        }
        Assert.True(withCalls > 0, "no completed run made model calls");
    }

    static string Git(string dir, params string[] args)
    {
        var psi = new ProcessStartInfo("git") { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!; var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o;
    }
}
