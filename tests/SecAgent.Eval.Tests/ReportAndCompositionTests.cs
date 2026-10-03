using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Eval.Checks;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Models;
using SecAgent.Eval.Reporting;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Stages;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

public class ReportTests
{
    static EvalReport Report(bool gatePassed, BaselineComparison? cmp = null)
    {
        var usage = new ModelUsageRecord("triage", "replay", "authored-reference", 900, 50, "estimate", 0m, "replay", 3, 1, false);
        var failing = Result("sqli-x", false, outcome: "needs_human") with
        {
            Checks = [new CheckResult("outcome", "outcome(expected=fixed)", false, "expected fixed, got needs_human")],
        };
        var cases = new List<CaseResult> { Result("a-ok", true, usage: [usage]), failing };
        var s = EvalSummary.From(cases);
        var gate = new GateResult(gatePassed, [new GateCheck("pass_rate", gatePassed, "1/2 = 50.0 % (minimum 90 %)")]);
        return new EvalReport("1.0", "eval-test", "replay", "**Replay mode.** test description", ["replay: authored-reference"], "2026-10-03T15:00:00Z", "2026-10-03T15:01:00Z",
            "cfg-label", "0123456789abcdef", s, new GateOptions(), gate, cmp ?? BaselineComparison.Compare(null, cases), cases);
    }

    [Fact]
    public void Markdown_shows_mode_gate_cases_failures_usage_and_ist_time()
    {
        var md = MarkdownReportWriter.Render(Report(false));
        Assert.Contains("# SecAgent evaluation: replay mode · gate ❌ failed", md);
        Assert.Contains("**Replay mode.**", md);
        Assert.Contains("| pass_rate | ❌ |", md);
        Assert.Contains("`sqli-x`", md);
        Assert.Contains("missed_fix", md);
        Assert.Contains("## Failures", md);
        Assert.Contains("2026-10-03 20:30 IST (15:00 UTC)", md);
        Assert.Contains("commit `0123456`", md);
        Assert.Contains("| 1 | 900 | 50 | estimate | 0.0000 | replay |", md);
        Assert.Contains("No baseline file yet.", md);
    }

    [Fact]
    public void Markdown_lists_regressions_against_the_baseline()
    {
        var b = new Baseline { Mode = "replay", PassRate = 1, Cases = new(StringComparer.Ordinal) { ["sqli-x"] = new() { Passed = true }, ["a-ok"] = new() { Passed = true } } };
        var r = Report(false);
        var md = MarkdownReportWriter.Render(r with { Baseline = BaselineComparison.Compare(b, r.Cases) });
        Assert.Contains("Regressions (passed before, fail now): `sqli-x`", md);
    }

    [Fact]
    public async Task Writers_produce_json_and_markdown_files()
    {
        var dir = TempDir();
        var r = Report(true);
        var json = await new JsonReportWriter().WriteAsync(r, dir, default);
        var md = await new MarkdownReportWriter().WriteAsync(r, dir, default);
        var doc = JsonDocument.Parse(File.ReadAllText(json)).RootElement;
        Assert.Equal("replay", doc.GetProperty("mode").GetString());
        Assert.Equal(2, doc.GetProperty("cases").GetArrayLength());
        Assert.True(doc.GetProperty("summary").TryGetProperty("pass_rate", out _));
        Assert.Contains("gate ✅ passed", File.ReadAllText(md));
    }

    [Fact]
    public void Markdown_escapes_table_breaking_characters()
    {
        var r = Report(false);
        var bad = r.Cases[1] with { Checks = [new CheckResult("x", "x", false, "a | b\nc")] };
        var md = MarkdownReportWriter.Render(r with { Cases = [r.Cases[0], bad] });
        Assert.Contains(@"a \| b c", md);
    }
}

public class CompositionTests
{
    [Fact]
    public void Container_builds_and_resolves_the_runner_with_validated_options()
    {
        using var sp = Services();
        Assert.NotNull(sp.GetRequiredService<IEvalRunner>());
        Assert.IsType<ReplayModelClient>(sp.GetRequiredService<IEvalModelClient>());
        Assert.Equal(16, sp.GetServices<IOutcomeChecker>().Count());
        Assert.Equal(4, sp.GetServices<IEvalFixer>().Count());
        Assert.Equal(4, sp.GetServices<IGateRule>().Count());
        Assert.Equal(2, sp.GetServices<IReportWriter>().Count());
    }

    [Fact]
    public void Mode_selects_the_model_client_strategy()
    {
        using var stamp = Services(o => o.Mode = EvalModes.Stamp);
        Assert.IsType<StampingModelClient>(stamp.GetRequiredService<IEvalModelClient>());
        using var replay = Services();
        Assert.IsType<RecordingModelClient>(replay.GetRequiredKeyedService<IEvalModelClient>(EvalModes.Record));   // registered, resolved lazily
    }

    [Fact]
    public void Invalid_options_fail_before_any_work()
    {
        using var sp = Services(o => o.Mode = "turbo");
        Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptions<EvalOptions>>().Value);
    }

    [Fact]
    public void Extra_strategies_plug_in_without_editing_the_harness()
    {
        using var sp = Services(replace: s => s.AddOutcomeChecker<AlwaysPassChecker>().AddOutcomeChecker<AlwaysPassChecker>());   // idempotent
        Assert.True(sp.GetRequiredService<ICheckerRegistry>().TryGet("always_pass", out _));
        Assert.Equal(17, sp.GetServices<IOutcomeChecker>().Count());
    }

    sealed class AlwaysPassChecker : IOutcomeChecker
    {
        public string Type => "always_pass";
        public Task<CheckResult> CheckAsync(CaseContext ctx, SecAgent.Eval.Cases.CheckSpec spec, CancellationToken ct) => Task.FromResult(new CheckResult(Type, Type, true, ""));
    }
}

public class ArchitectureTests
{
    static readonly Assembly Eval = typeof(IEvalRunner).Assembly;

    [Fact]
    public void Eval_assembly_exposes_no_merge_or_approve_method()
    {
        var methods = Eval.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(m => m.Name.Contains("merge", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("approve", StringComparison.OrdinalIgnoreCase))
            .Select(m => $"{m.DeclaringType!.FullName}.{m.Name}").ToList();
        Assert.Empty(methods);
    }

    [Fact]
    public void Eval_source_never_calls_gh_merge_or_pushes()
    {
        foreach (var f in Directory.GetFiles(Path.Combine(RepoRoot, "src", "SecAgent.Eval"), "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(f);
            Assert.DoesNotContain("\"merge\"", text);
            Assert.DoesNotContain("\"push\"", text);
            Assert.DoesNotContain("--approve", text);
        }
    }

    [Fact]
    public void Eval_assembly_has_no_mutable_static_state()
    {
        var fields = Eval.GetTypes()
            .Where(t => !t.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute)) && !t.Name.Contains('<'))
            .SelectMany(t => t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(f => !f.IsLiteral && !f.IsInitOnly && !f.Name.Contains('<'))
            .Select(f => $"{f.DeclaringType!.Name}.{f.Name}").ToList();
        Assert.Empty(fields);
    }

    [Fact]
    public void Harness_services_depend_on_harness_interfaces_not_classes()
    {
        // Dependency inversion: a service class (one implementing a harness interface) never takes another harness class in its constructor.
        static bool IsEval(Type t) => t.Namespace?.StartsWith("SecAgent.Eval", StringComparison.Ordinal) == true;
        var offenders = Eval.GetTypes().Where(t => t.IsClass && !t.IsAbstract && t.GetInterfaces().Any(IsEval))
            .SelectMany(t => t.GetConstructors().SelectMany(c => c.GetParameters()).Select(p => (t, p)))
            .Where(x => x.p.ParameterType.IsClass && IsEval(x.p.ParameterType))
            .Select(x => $"{x.t.Name}({x.p.ParameterType.Name} {x.p.Name})").ToList();
        Assert.Empty(offenders);
    }
}
