using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Checks;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Models;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Stages;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Tests;

/// <summary>Shared helpers: repo paths, a test HMAC key, fake evidence and contexts for checker tests, and a DI container for the harness.</summary>
public static class EvalTestKit
{
    public static readonly string RepoRoot = FindRoot();
    public static string RulesRoot => Path.Combine(RepoRoot, "rules");
    public static string GoldenRoot => Path.Combine(RepoRoot, "eval", "golden");

    static EvalTestKit()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SECAGENT_HMAC_KEY")))
            Environment.SetEnvironmentVariable("SECAGENT_HMAC_KEY", "secagent-eval-test-only-hmac-key");
    }

    public static void EnsureEnv() { }

    static string FindRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !File.Exists(Path.Combine(d.FullName, "SecAgent.slnx"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    public static string TempDir(string prefix = "eval-test")
    {
        var p = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(p);
        return p;
    }

    public static GoldenCase Case(string id = "c1", string triage = "fix", string? fixer = "unsafe_code", string outcome = "fixed", params string[] tags) => new()
    {
        Id = id, Title = id, Category = "test", Tags = tags.Length > 0 ? tags.ToList() : ["positive"],
        Expected = new ExpectedOutcome { Triage = triage, Fixer = fixer, Outcome = outcome },
    };

    public static CaseContext Context(GoldenCase? c = null, string? root = null, FakeEvidence? evidence = null, Finding? finding = null, Dictionary<string, string>? secrets = null)
    {
        c ??= Case();
        root ??= TempDir();
        var ws = new CaseWorkspace(root, finding ?? new Finding { IssueType = IssueTypes.UnsafeCode, FilePath = "src/A.cs" }, secrets ?? []);
        return new CaseContext(c, ws, Guid.NewGuid(), evidence ?? new FakeEvidence());
    }

    public static CheckSpec Spec(string type, object? args = null)
    {
        var spec = new CheckSpec { Type = type };
        if (args != null)
            foreach (var p in JsonSerializer.SerializeToElement(args).EnumerateObject()) spec.Args[p.Name] = p.Value.Clone();
        return spec;
    }

    public static TriageResult Triage(string decision, string proposed = "fix", string severity = "high", bool injected = false) =>
        new(proposed, decision, severity, 0.9, "r", [], [], injected);

    public static CaseResult Result(string id, bool passed, string outcome = "fixed", string expected = "fixed", string category = "test", long latency = 100,
        IReadOnlyList<ModelUsageRecord>? usage = null, bool drift = false) =>
        new(id, id, category, ["positive"], passed, FailureKinds.Classify(expected, outcome, passed), new ExpectedSummary("fix", "unsafe_code", expected),
            new ActualSummary("fix", "fix", "high", 0.9, "unsafe_code", outcome, [], false, [], null, null, []), [], usage ?? [], latency, [], drift);

    /// <summary>Harness container on the real rules and golden set, writing to temp folders.</summary>
    public static ServiceProvider Services(Action<EvalOptions>? configure = null, Action<IServiceCollection>? replace = null)
    {
        var out_ = TempDir("eval-out");
        var services = new ServiceCollection().AddSecAgentEval(o =>
        {
            o.RepoRoot = RepoRoot; o.OutputDir = out_; o.WorkRoot = Path.Combine(Path.GetTempPath(), "secagent-eval-tests");
            o.BaselinePath = Path.Combine(out_, "baseline.json");
            configure?.Invoke(o);
        });
        replace?.Invoke(services);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    /// <summary>Copies a subset of the golden set to a temp cases root (so tests can edit recordings without touching the committed ones).</summary>
    public static string CopyCases(params string[] ids)
    {
        var root = TempDir("eval-cases");
        foreach (var f in new[] { "scanner-rules.yaml", "gates.json" }) File.Copy(Path.Combine(GoldenRoot, f), Path.Combine(root, f));
        foreach (var id in ids) CopyDir(Path.Combine(GoldenRoot, "cases", id), Path.Combine(root, "cases", id));
        return root;
    }

    static void CopyDir(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var f in Directory.GetFiles(from)) File.Copy(f, Path.Combine(to, Path.GetFileName(f)));
        foreach (var d in Directory.GetDirectories(from)) CopyDir(d, Path.Combine(to, Path.GetFileName(d)));
    }
}

/// <summary>Evidence with fixed values (no dotnet, no git).</summary>
public sealed class FakeEvidence : ICaseEvidence
{
    public BuildTestResult Build { get; set; } = new(true, true, 3, 3, 0, 1.0, "");
    public List<ScanHit> Scan { get; set; } = [];
    public List<string> Changed { get; set; } = [];
    public int BuildCalls { get; private set; }

    public Task<BuildTestResult> BuildAndTestAsync(CancellationToken ct) { BuildCalls++; return Task.FromResult(Build); }
    public Task<IReadOnlyList<ScanHit>> ScanAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ScanHit>>(Scan);
    public Task<IReadOnlyList<string>> ChangedFilesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>(Changed);
}

/// <summary>Build runner fake for end-to-end runs: no dotnet process; result chosen by the test.</summary>
public sealed class FakeBuildRunner(Func<string, BuildTestResult> result) : IBuildRunner
{
    public List<string> Roots { get; } = [];
    public Task<BuildTestResult> RunAsync(string root, CancellationToken ct) { lock (Roots) Roots.Add(root); return Task.FromResult(result(root)); }
    public static FakeBuildRunner Passing() => new(_ => new BuildTestResult(true, true, 2, 2, 0, 0.1, ""));
    public static FakeBuildRunner Failing() => new(_ => new BuildTestResult(false, true, 0, 0, 0, 0.1, "src/App/X.cs(1,1): error CS0103: fake"));
}
