using Microsoft.Extensions.Options;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Fixers;
using SecAgent.Eval.Stages;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

public class ScannerTests
{
    static RegexRuleScanner Scanner(string yaml)
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "scanner-rules.yaml"), yaml);
        return new RegexRuleScanner(Options.Create(new EvalOptions { CasesRoot = dir }));
    }

    const string Rules = """
        rules:
          - id: sqli
            globs: ['**/*.cs']
            pattern: 'CommandText\s*=\s*".*"\s*\+\s*[A-Za-z_]'
          - id: no-auth
            kind: absent
            globs: ['**/*Controller.cs']
            when: '\[HttpDelete\b'
            pattern: '\[Authorize\b'
          - id: dep
            kind: dependency
            packages: [ { package: Newtonsoft.Json, below: 13.0.1 } ]
          - id: bin
            kind: binary
            extensions: [.dll]
        """;

    [Fact]
    public async Task All_rule_kinds_detect_and_skip_build_output()
    {
        var root = TempDir();
        void W(string rel, string text) { Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(root, rel))!); File.WriteAllText(Path.Combine(root, rel), text); }
        W("src/Repo.cs", "x\ncmd.CommandText = \"SELECT \" + name;\n");
        W("src/AdminController.cs", "[HttpDelete(\"x\")]\npublic void D() {}\n");
        W("src/OkController.cs", "[Authorize]\n[HttpDelete(\"x\")]\n");
        W("src/App.csproj", "<PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.3\" />\n<PackageReference Include=\"Other\" Version=\"1.0.0\" />");
        W("lib/a.dll", "MZ...");
        W("lib/not-pe.dll", "PK..");
        W("src/obj/Gen.cs", "cmd.CommandText = \"SELECT \" + name;");
        var hits = await Scanner(Rules).ScanAsync(root, default);
        Assert.Equal(
            ["bin lib/a.dll:1", "dep src/App.csproj:1", "no-auth src/AdminController.cs:1", "sqli src/Repo.cs:2"],
            hits.Select(h => $"{h.RuleId} {h.File}:{h.Line}").Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Introduced_ignores_moved_lines_and_counts_extra_hits()
    {
        var before = new List<ScanHit> { new("r", "a.cs", 1) };
        Assert.Empty(RegexRuleScanner.Introduced(before, [new("r", "a.cs", 7)]));
        Assert.Single(RegexRuleScanner.Introduced(before, [new("r", "a.cs", 1), new("r", "a.cs", 2)]));
        Assert.Single(RegexRuleScanner.Introduced(before, [new("r2", "a.cs", 1)]));
    }

    [Fact]
    public async Task Unknown_rule_kind_is_rejected_on_scan()
    {
        var s = Scanner("rules:\n  - id: x\n    kind: magic\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => s.ScanAsync(TempDir(), default));
    }

    [Theory]
    [InlineData("13.0.1", "13.0.1", 0)]
    [InlineData("12.0.3", "13.0.1", -1)]
    [InlineData("10.1.1", "9.0.0", 1)]
    [InlineData("13.0.1-beta1", "13.0.1", 0)]
    public void Version_comparison_is_numeric(string a, string b, int sign) => Assert.Equal(sign, Math.Sign(Versions.Compare(a, b)));
}

public class RoutingAndResolverTests
{
    sealed class StubFixer(string id) : IEvalFixer
    {
        public string Id => id;
        public Task<FixResult> ApplyAsync(CaseContext ctx, CancellationToken ct) => Task.FromResult(new FixResult(true, false, id));
    }

    static ConfigSnapshot Cfg() => ConfigSnapshot.Load(RulesRoot);

    [Fact]
    public void Routes_each_issue_type_to_the_fixer_in_routing_yaml()
    {
        var router = new RoutingTableFixRouter(Cfg(), new[] { "library", "secrets", "unsafe_code", "binary_licence" }.Select(i => (IEvalFixer)new StubFixer(i)));
        foreach (var (type, fixer) in new[] { ("secret", "secrets"), ("vulnerable_dependency", "library"), ("unsafe_code", "unsafe_code"), ("binary_artefact", "binary_licence"), ("licence", "binary_licence") })
        {
            Assert.Equal(fixer, router.Route(new Finding { IssueType = type }, out var id).Id);
            Assert.Equal(fixer, id);
        }
        Assert.Throws<InvalidOperationException>(() => router.Route(new Finding { IssueType = "unknown" }, out _));
    }

    [Fact]
    public void Missing_or_duplicate_fixers_fail_at_start_up()
    {
        Assert.Throws<InvalidOperationException>(() => new RoutingTableFixRouter(Cfg(), [new StubFixer("library")]));
        Assert.Throws<InvalidOperationException>(() => new RoutingTableFixRouter(Cfg(), new[] { "library", "library", "secrets", "unsafe_code", "binary_licence" }.Select(i => (IEvalFixer)new StubFixer(i))));
    }

    [Fact]
    public void Offline_resolver_picks_the_lowest_safe_version()
    {
        var c = Case(); c.PackageVersions["Pkg"] = ["9.0.0", "10.1.1", "8.1.1"];
        Assert.Equal(("9.0.0", "10.1.1"), new OfflinePackageVersionResolver().Resolve(c, "Pkg", "9.0.0"));
        Assert.Equal(("2.0.0", "2.0.0"), new OfflinePackageVersionResolver().Resolve(c, "Other", "2.0.0"));
        Assert.Equal((null, "10.1.1"), new OfflinePackageVersionResolver().Resolve(c, "Pkg", "11.0.0"));
    }
}

public class SyntheticSecretTests
{
    [Theory]
    [InlineData("aws_access_key_id", "^AKIA[A-Z2-7]{16}$")]
    [InlineData("stripe_test_key", "^sk_test_[0-9A-Za-z]{24}$")]
    [InlineData("stripe_live_key", "^sk_live_[0-9A-Za-z]{24}$")]
    [InlineData("github_pat", "^ghp_[0-9A-Za-z]{36}$")]
    [InlineData("password", "^Pw-[0-9A-Za-z]{18}$")]
    public void Values_have_detector_shape_and_are_deterministic(string kind, string shape)
    {
        var g = new DeterministicSecretGenerator();
        var v = g.Generate("case-a", "K", kind);
        Assert.Matches(shape, v);
        Assert.Equal(v, g.Generate("case-a", "K", kind));
        Assert.NotEqual(v, g.Generate("case-b", "K", kind));
    }

    [Fact]
    public void Unknown_kind_is_rejected() => Assert.Throws<InvalidOperationException>(() => new DeterministicSecretGenerator().Generate("c", "K", "nope"));
}

public class OptionsTests
{
    static EvalOptions Valid() { var o = new EvalOptions { RepoRoot = RepoRoot }; o.ApplyDefaults(); return o; }

    [Fact]
    public void Defaults_point_into_the_repository_and_work_outside_it()
    {
        var o = Valid();
        Assert.Equal(Path.Combine(RepoRoot, "eval", "golden"), o.CasesRoot);
        Assert.Equal(Path.Combine(RepoRoot, "eval", "golden", "baseline.json"), o.BaselinePath);
        Assert.Equal(EvalModes.Replay, o.Mode);
        Assert.True(new EvalOptionsValidator().Validate(null, o).Succeeded);
    }

    [Fact]
    public void Validator_rejects_bad_mode_parallelism_missing_folders_and_work_root_inside_the_repo()
    {
        var v = new EvalOptionsValidator();
        var o = Valid(); o.Mode = "turbo"; Assert.True(v.Validate(null, o).Failed);
        o = Valid(); o.MaxParallel = 0; Assert.True(v.Validate(null, o).Failed);
        o = Valid(); o.CasesRoot = "/nonexistent/eval"; Assert.True(v.Validate(null, o).Failed);
        o = Valid(); o.WorkRoot = Path.Combine(RepoRoot, "eval", "work"); Assert.True(v.Validate(null, o).Failed);
        foreach (var m in EvalModes.All) { o = Valid(); o.Mode = m; Assert.True(v.Validate(null, o).Succeeded, m); }
    }
}
