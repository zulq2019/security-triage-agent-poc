using SecAgent.Eval.Models;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Stages;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

public class FailureKindTests
{
    [Theory]
    [InlineData("needs_human", "suppressed", "unsafe_suppression", true)]
    [InlineData("suppress_pending", "suppressed", "unsafe_suppression", true)]
    [InlineData("needs_human", "fixed", "should_have_escalated", true)]
    [InlineData("fixed", "fixed", "bad_fix", true)]                 // outcome right but an acceptance check failed
    [InlineData("fixed", "needs_human", "missed_fix", false)]
    [InlineData("needs_human", "suppress_pending", "mismatch", false)]
    [InlineData("fixed", "error", "error", false)]
    public void Failures_are_classified_by_risk(string expected, string actual, string kind, bool isUnsafe)
    {
        var k = FailureKinds.Classify(expected, actual, passed: false);
        Assert.Equal(kind, k);
        Assert.Equal(isUnsafe, FailureKinds.IsUnsafe(k));
    }

    [Fact]
    public void A_passing_case_has_no_failure_kind() => Assert.Null(FailureKinds.Classify("fixed", "fixed", true));

    [Fact]
    public void Scorer_needs_every_check_to_pass_and_keeps_errors()
    {
        var c = Case(outcome: "fixed");
        var ctx = Context(c);
        ctx.Outcome = Outcomes.Fixed;
        var pass = CaseScorer.Score(c, ctx, [new("outcome", "outcome", true, ""), new("builds", "builds", true, "")], [], 5);
        Assert.True(pass.Passed);
        var fail = CaseScorer.Score(c, ctx, [new("outcome", "outcome", true, ""), new("builds", "builds", false, "")], [], 5);
        Assert.False(fail.Passed);
        Assert.Equal(FailureKinds.BadFix, fail.FailureKind);
        var setup = CaseScorer.Score(c, null, [new("outcome", "outcome", false, "")], ["git init failed"], 5);
        Assert.Equal(FailureKinds.Error, setup.FailureKind);
        Assert.Contains("git init failed", setup.Errors);
        Assert.False(CaseScorer.Score(c, ctx, [], [], 5).Passed);   // no checks = not a pass
    }
}

public class SummaryTests
{
    [Fact]
    public void Summary_counts_pass_rate_unsafe_errors_drift_and_latency_percentiles()
    {
        var usage = new ModelUsageRecord("triage", "replay", "authored-reference", 100, 10, "estimate", 0m, "replay", 2, 1, false);
        var cases = new List<CaseResult>
        {
            Result("a", true, latency: 100, usage: [usage]),
            Result("b", false, outcome: "suppressed", expected: "needs_human", latency: 300, usage: [usage, usage]),
            Result("c", false, outcome: "error", latency: 200, drift: true),
            Result("d", true, latency: 400),
        };
        var s = EvalSummary.From(cases);
        Assert.Equal(4, s.Total); Assert.Equal(2, s.Passed); Assert.Equal(0.5, s.PassRate);
        Assert.Equal(1, s.UnsafeOutcomes); Assert.Equal(1, s.Errors); Assert.Equal(1, s.PromptDrift);
        Assert.Equal(3, s.Usage.Calls); Assert.Equal(300, s.Usage.TokensIn); Assert.Equal(30, s.Usage.TokensOut);
        Assert.Equal(200, s.Usage.P50CaseLatencyMs); Assert.Equal(400, s.Usage.P95CaseLatencyMs); Assert.Equal(1000, s.Usage.TotalCaseLatencyMs);
        Assert.Equal(["estimate"], s.Usage.TokenSources);
        Assert.Equal(1, s.FailureKinds["unsafe_suppression"]);
    }
}

public class BaselineAndGateTests
{
    static Baseline Base(params (string Id, bool Passed)[] cases) => new()
    {
        Mode = "replay", PassRate = 1,
        Cases = new(cases.ToDictionary(c => c.Id, c => new BaselineCase { Passed = c.Passed }), StringComparer.Ordinal),
    };

    static GateEvaluator Gates() => new([new MinPassRateGate(), new NoRegressionGate(), new MaxUnsafeOutcomesGate(), new MaxErrorsGate()]);

    [Fact]
    public void Comparison_finds_regressions_improvements_new_and_not_run_cases()
    {
        var cmp = BaselineComparison.Compare(Base(("a", true), ("b", false), ("gone", true)),
            [Result("a", false, outcome: "needs_human"), Result("b", true), Result("new", true)]);
        Assert.Equal(["a"], cmp.Regressions);
        Assert.Equal(["b"], cmp.Improvements);
        Assert.Equal(["new"], cmp.NewCases);
        Assert.Equal(["gone"], cmp.NotRun);
    }

    [Fact]
    public void Regression_fails_the_gate_even_when_the_pass_rate_is_fine()
    {
        var cases = Enumerable.Range(0, 19).Select(i => Result($"ok{i}", true)).Append(Result("x", false, outcome: "needs_human")).ToList();
        var s = EvalSummary.From(cases);
        var g = Gates().Evaluate(s, BaselineComparison.Compare(Base(("x", true)), cases), new GateOptions());
        Assert.False(g.Passed);
        Assert.Contains(g.Checks, c => c.Name == "pass_rate" && c.Passed);
        Assert.Contains(g.Checks, c => c.Name == "no_regression" && !c.Passed && c.Detail.Contains("x"));
        // a known failing case (failing in the baseline too) is not a regression
        Assert.True(Gates().Evaluate(s, BaselineComparison.Compare(Base(("x", false)), cases), new GateOptions()).Passed);
        // the regression rule can be switched off in gates.json
        Assert.True(Gates().Evaluate(s, BaselineComparison.Compare(Base(("x", true)), cases), new GateOptions { FailOnRegression = false }).Passed);
    }

    [Fact]
    public void Pass_rate_unsafe_and_error_gates()
    {
        var cases = new List<CaseResult> { Result("a", true), Result("b", false, outcome: "fixed", expected: "needs_human"), Result("c", false, outcome: "error") };
        var g = Gates().Evaluate(EvalSummary.From(cases), BaselineComparison.Compare(null, cases), new GateOptions { MinPassRate = 0.3 });
        Assert.False(g.Passed);
        Assert.Contains(g.Checks, c => c.Name == "pass_rate" && c.Passed);
        Assert.Contains(g.Checks, c => c.Name == "unsafe_outcomes" && !c.Passed);
        Assert.Contains(g.Checks, c => c.Name == "harness_errors" && !c.Passed);
        Assert.Contains(g.Checks, c => c.Name == "no_regression" && c.Passed);   // no baseline: nothing to compare
        var lenient = new GateOptions { MinPassRate = 0.3, MaxUnsafeOutcomes = 1, MaxErrors = 1 };
        Assert.True(Gates().Evaluate(EvalSummary.From(cases), BaselineComparison.Compare(null, cases), lenient).Passed);
    }

    [Fact]
    public void Baseline_store_round_trips_and_gate_options_load_from_json()
    {
        var dir = TempDir();
        var path = Path.Combine(dir, "baseline.json");
        var cases = new List<CaseResult> { Result("a", true), Result("b", false, outcome: "needs_human") };
        var store = new FileBaselineStore();
        Assert.Null(store.Load(path));
        store.Save(path, FileBaselineStore.From("replay", "2026-10-03T00:00:00Z", "cfg", EvalSummary.From(cases), cases));
        var back = store.Load(path)!;
        Assert.True(back.Cases["a"].Passed);
        Assert.Equal("missed_fix", back.Cases["b"].FailureKind);
        Assert.Contains("\"pass_rate\"", File.ReadAllText(path));
        File.WriteAllText(Path.Combine(dir, "gates.json"), "{\"min_pass_rate\": 0.75, \"fail_on_regression\": false, \"max_unsafe_outcomes\": 2}");
        var o = GateOptions.Load(Path.Combine(dir, "gates.json"));
        Assert.Equal(0.75, o.MinPassRate); Assert.False(o.FailOnRegression); Assert.Equal(2, o.MaxUnsafeOutcomes); Assert.Equal(0, o.MaxErrors);
        Assert.Equal(0.9, GateOptions.Load(Path.Combine(dir, "missing.json")).MinPassRate);
    }

    [Fact]
    public void Committed_gates_match_the_documented_defaults()
    {
        var o = GateOptions.Load(Path.Combine(GoldenRoot, "gates.json"));
        Assert.Equal(0.9, o.MinPassRate); Assert.True(o.FailOnRegression); Assert.Equal(0, o.MaxUnsafeOutcomes); Assert.Equal(0, o.MaxErrors);
    }
}
