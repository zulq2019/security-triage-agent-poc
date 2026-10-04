using System.Xml.Linq;
using Microsoft.Extensions.Options;
using SecAgent.Core;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Verification;

/// <summary>Result of building the fixture and running its tests (dotnet test when it has a test project, else dotnet build).</summary>
/// <param name="Built">Compiled (for dotnet test: non-zero exit with no tests run = build failure). Counters tell build from test failures.</param>
/// <param name="ExitCode">Process exit status. A non-zero exit after passing tests (test host, logger or post-test failure) is not a pass.</param>
public sealed record BuildTestResult(bool Built, bool HasTests, int Total, int Passed, int Failed, double Seconds, string FailureText, int ExitCode = 0)
{
    public bool TestsOk => Built && ExitCode == 0 && (!HasTests || (Total > 0 && Failed == 0));
}

public interface IBuildRunner
{
    Task<BuildTestResult> RunAsync(string root, CancellationToken ct);
}

/// <summary>Builds and tests a workspace the way the pipeline's verifier does (dotnet test with a trx logger; build failed = non-zero exit and no tests ran).</summary>
public sealed class DotnetBuildRunner(IProcessRunner proc, SecretMasker masker, IOptions<EvalOptions> options) : IBuildRunner
{
    public async Task<BuildTestResult> RunAsync(string root, CancellationToken ct)
    {
        var target = Directory.GetFiles(root, "*.slnx").Concat(Directory.GetFiles(root, "*.sln")).FirstOrDefault()
                     ?? Directory.GetFiles(root, "*.csproj", SearchOption.AllDirectories).FirstOrDefault()
                     ?? throw new InvalidOperationException("fixture has no solution or project file");
        var hasTests = Directory.GetFiles(root, "*.csproj", SearchOption.AllDirectories).Any(p => File.ReadAllText(p).Contains("Microsoft.NET.Test.Sdk"));
        var resultsDir = Path.Combine(root, ".secagent-test");
        var args = hasTests
            ? new List<string> { "test", target, "--logger", "trx;LogFileName=results.trx", "--results-directory", resultsDir, "-nologo", "--disable-build-servers" }
            : ["build", target, "-nologo", "--disable-build-servers"];
        var r = await proc.RunAsync("dotnet", args, root, ct, options.Value.BuildTimeoutSeconds);
        int total = 0, passed = 0, failed = 0; var fails = "";
        var trx = Path.Combine(resultsDir, "results.trx");
        if (File.Exists(trx))
        {
            var x = XDocument.Load(trx);
            var ns = x.Root!.Name.Namespace;
            var c = x.Descendants(ns + "Counters").FirstOrDefault();
            if (c != null) { total = (int?)c.Attribute("total") ?? 0; passed = (int?)c.Attribute("passed") ?? 0; failed = (int?)c.Attribute("failed") ?? 0; }
            fails = string.Join("\n", x.Descendants(ns + "UnitTestResult").Where(u => (string?)u.Attribute("outcome") == "Failed")
                .Select(u => $"{u.Attribute("testName")?.Value}: {u.Descendants(ns + "Message").FirstOrDefault()?.Value?.Split('\n')[0]}").Take(5));
        }
        var built = hasTests ? !(r.ExitCode != 0 && total == 0) : r.ExitCode == 0;
        if (!built)
            fails = string.Join("\n", (r.StdOut + "\n" + r.StdErr).Split('\n').Where(l => l.Contains(": error ")).Select(l => l.Trim()).Distinct().Take(6));
        else if (r.ExitCode != 0 && failed == 0)
            fails = $"dotnet {args[0]} exited {r.ExitCode} although {passed}/{total} tests passed (test host, logger or post-test failure)";
        fails = System.Text.RegularExpressions.Regex.Replace(fails.Replace(root + Path.DirectorySeparatorChar, ""), @"\s*\[[^\]]+\.csproj\]", "");
        return new BuildTestResult(built, hasTests, total, passed, failed, r.ElapsedMs / 1000.0, masker.Mask(fails, false), r.ExitCode);
    }
}

/// <summary>Lazily computed, memoised evidence for one workspace, shared by the verifier and the checkers (so the fixture is built once).</summary>
public interface ICaseEvidence
{
    Task<BuildTestResult> BuildAndTestAsync(CancellationToken ct);
    Task<IReadOnlyList<ScanHit>> ScanAsync(CancellationToken ct);
    Task<IReadOnlyList<string>> ChangedFilesAsync(CancellationToken ct);
}

public interface ICaseEvidenceFactory
{
    ICaseEvidence Create(string root);
}

public sealed class CaseEvidenceFactory(IBuildRunner build, IFindingScanner scanner, IGitDiff diff) : ICaseEvidenceFactory
{
    public ICaseEvidence Create(string root) => new CaseEvidence(root, build, scanner, diff);

    sealed class CaseEvidence(string root, IBuildRunner build, IFindingScanner scanner, IGitDiff diff) : ICaseEvidence
    {
        readonly object _lock = new();
        Task<BuildTestResult>? _build; Task<IReadOnlyList<ScanHit>>? _scan; Task<IReadOnlyList<string>>? _diff;

        public Task<BuildTestResult> BuildAndTestAsync(CancellationToken ct) { lock (_lock) return _build ??= build.RunAsync(root, ct); }
        public Task<IReadOnlyList<ScanHit>> ScanAsync(CancellationToken ct) { lock (_lock) return _scan ??= scanner.ScanAsync(root, ct); }
        public Task<IReadOnlyList<string>> ChangedFilesAsync(CancellationToken ct) { lock (_lock) return _diff ??= diff.ChangedFilesAsync(root, ct); }
    }
}
