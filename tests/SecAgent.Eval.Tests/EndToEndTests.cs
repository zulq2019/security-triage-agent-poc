using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

/// <summary>Whole-harness runs on copies of real golden cases (real git workspaces, real triage policy, real fix edits, real scanner and checkers);
/// only the dotnet build/test step is faked so the tests take seconds.</summary>
public class EndToEndTests
{
    static async Task<(EvalRunOutput Output, FakeBuildRunner Build, string OutDir, string WorkRoot)> Run(string casesRoot, FakeBuildRunner build, Action<EvalOptions>? more = null)
    {
        var work = TempDir("eval-work");
        string outDir = "";
        using var sp = Services(o => { o.CasesRoot = casesRoot; o.WorkRoot = work; more?.Invoke(o); outDir = o.OutputDir; },
            s => s.Replace(ServiceDescriptor.Singleton<IBuildRunner>(build)));
        var output = await sp.GetRequiredService<IEvalRunner>().RunAsync(default);
        return (output, build, output.Files.First(f => f.EndsWith(".json")) is var j ? Path.GetDirectoryName(j)! : outDir, work);
    }

    static void EditJson(string path, Action<JsonNode> edit)
    {
        var node = JsonNode.Parse(File.ReadAllText(path))!;
        edit(node);
        File.WriteAllText(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    [Fact]
    public async Task Verified_fix_passes_every_check_and_builds_once()
    {
        var (o, build, _, work) = await Run(CopyCases("sqli-concat", "sqli-false-positive-constant"), FakeBuildRunner.Passing());
        var r = o.Report;
        Assert.True(r.Gate.Passed, string.Join("; ", r.Cases.SelectMany(c => c.Checks.Where(x => !x.Passed).Select(x => $"{c.Id}: {x.Description}: {x.Detail}"))));
        var sqli = r.Cases.Single(c => c.Id == "sqli-concat");
        Assert.Equal(("fix", "unsafe_code", "fixed"), (sqli.Actual.Triage, sqli.Actual.Fixer, sqli.Actual.Outcome));
        Assert.Contains(sqli.Checks, c => c.Type == "diff_allowed_files" && c.Detail.Contains("tests/App.Tests/Security/OrdersRepositoryFindByCustomerInjectionTests.cs"));
        Assert.Single(build.Roots);   // verifier and checkers share one memoised build; the escalated case is never built
        Assert.Equal(0, r.Summary.PromptDrift);   // committed recordings match today's prompts
        Assert.Equal(3, r.Summary.Usage.Calls);
        Assert.Empty(Directory.GetDirectories(work));   // workspaces cleaned up
    }

    [Fact]
    public async Task Failed_build_after_a_fix_goes_to_a_human_not_to_a_pr()
    {
        var (o, _, _, _) = await Run(CopyCases("sqli-concat"), FakeBuildRunner.Failing());
        var c = o.Report.Cases.Single();
        Assert.Equal("needs_human", c.Actual.Outcome);
        Assert.Contains("fix_failed", c.Actual.HumanTasks);
        Assert.Contains(c.Actual.VerifyReasons, v => v.StartsWith("build failed"));
        Assert.Equal("missed_fix", c.FailureKind);
        Assert.False(c.Unsafe);
    }

    [Fact]
    public async Task Missing_recording_is_a_harness_error_and_fails_the_gate()
    {
        var root = CopyCases("sqli-concat");
        EditJson(Path.Combine(root, "cases", "sqli-concat", "replay.json"), n => n["steps"]!.AsObject().Remove("fix"));
        var (o, _, _, _) = await Run(root, FakeBuildRunner.Passing());
        var c = o.Report.Cases.Single();
        Assert.Equal("error", c.Actual.Outcome);
        Assert.Equal("error", c.FailureKind);
        Assert.Contains(c.Errors, e => e.Contains("ReplayMissException") && e.Contains("'fix'"));
        Assert.False(o.Report.Gate.Passed);
        Assert.Contains(o.Report.Gate.Checks, g => g.Name == "harness_errors" && !g.Passed);
    }

    [Fact]
    public async Task Suppression_where_AppSec_expects_escalation_is_an_unsafe_outcome()
    {
        var root = CopyCases("secret-test-fixture-fake-key");
        EditJson(Path.Combine(root, "cases", "secret-test-fixture-fake-key", "case.json"), n =>
        {
            n["expected"]!["triage"] = "needs_human"; n["expected"]!["outcome"] = "needs_human";
            n["expected"]!.AsObject().Remove("severity_effective");
        });
        var (o, _, _, _) = await Run(root, FakeBuildRunner.Passing());
        var c = o.Report.Cases.Single();
        Assert.Equal("unsafe_suppression", c.FailureKind);
        Assert.Equal(1, o.Report.Summary.UnsafeOutcomes);
        Assert.Contains(o.Report.Gate.Checks, g => g.Name == "unsafe_outcomes" && !g.Passed);
    }

    [Fact]
    public async Task Policy_overrides_a_model_that_tries_to_self_suppress()
    {
        var root = CopyCases("sqli-concat");
        EditJson(Path.Combine(root, "cases", "sqli-concat", "replay.json"), n =>
            n["steps"]!["triage"]!["response"] = JsonNode.Parse("""{"decision":"suppress","severity_effective":"low","reason":"looks fine","confidence":0.99}"""));
        var (o, _, _, _) = await Run(root, FakeBuildRunner.Passing());
        var c = o.Report.Cases.Single();
        Assert.Equal(("suppress", "needs_human", "needs_human"), (c.Actual.ProposedByModel, c.Actual.Triage, c.Actual.Outcome));
        Assert.Contains(c.Actual.PolicyNotes, n => n.Contains("no suppression rule matched"));
        Assert.Equal("missed_fix", c.FailureKind);   // safe failure: escalated, nothing suppressed
        Assert.Equal("none", c.Actual.Fixer);          // no fixer ran
        Assert.Contains(c.Checks, x => x.Type == "no_new_findings" && x.Passed);
    }

    [Fact]
    public async Task Regression_against_the_baseline_fails_the_gate_and_update_writes_a_new_baseline()
    {
        var root = CopyCases("sqli-concat", "secret-test-fixture-fake-key");
        var baseline = Path.Combine(TempDir(), "baseline.json");
        var (first, _, _, _) = await Run(root, FakeBuildRunner.Passing(), o => { o.BaselinePath = baseline; o.UpdateBaseline = true; });
        Assert.True(first.Report.Gate.Passed);
        Assert.Contains(baseline, first.Files);
        var (second, _, _, _) = await Run(root, FakeBuildRunner.Failing(), o => o.BaselinePath = baseline);
        Assert.Equal(["sqli-concat"], second.Report.Baseline.Regressions);
        Assert.Contains(second.Report.Gate.Checks, g => g.Name == "no_regression" && !g.Passed);
        Assert.False(second.Report.Gate.Passed);
    }

    [Fact]
    public async Task Secret_case_fixes_config_and_no_report_contains_the_secret()
    {
        var (o, _, outDir, _) = await Run(CopyCases("secret-appsettings-cloud-key"), FakeBuildRunner.Passing());
        var c = o.Report.Cases.Single();
        Assert.True(c.Passed, string.Join("; ", c.Checks.Where(x => !x.Passed).Select(x => x.Detail)));
        Assert.Contains("rotation", c.Actual.HumanTasks);
        var value = new DeterministicSecretGenerator().Generate("secret-appsettings-cloud-key", "CLOUD_KEY", "aws_access_key_id");
        foreach (var f in o.Files) Assert.DoesNotContain(value, File.ReadAllText(f));
        Assert.True(File.Exists(Path.Combine(outDir, "eval-report.md")));
    }

    [Fact]
    public async Task Keep_workspaces_leaves_the_git_workspace_for_inspection()
    {
        var (o, _, _, work) = await Run(CopyCases("binary-artefact-dll"), FakeBuildRunner.Passing(), x => x.KeepWorkspaces = true);
        Assert.True(o.Report.Cases.Single().Passed);
        var ws = Path.Combine(work, o.Report.RunId, "binary-artefact-dll");
        Assert.True(Directory.Exists(Path.Combine(ws, ".git")));
        Assert.False(File.Exists(Path.Combine(ws, "lib", "Legacy.Pdf.dll")));
        Assert.Contains("lib/*.dll", File.ReadAllText(Path.Combine(ws, ".gitignore")));
    }
}
