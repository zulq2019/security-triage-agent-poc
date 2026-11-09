using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Agents;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Checks;
using SecAgent.Eval.Composition;
using SecAgent.Eval.Models;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

/// <summary>Structural checks on the committed golden set, so a broken case fails in seconds instead of in the eval run.</summary>
public class CaseSetTests
{
    static readonly ServiceProvider Sp = Services();
    static IReadOnlyList<GoldenCase> All => Sp.GetRequiredService<ICaseSource>().Load();

    [Fact]
    public void Golden_set_has_about_twenty_cases_with_positive_and_negative_ones()
    {
        Assert.InRange(All.Count, 18, 40);
        Assert.True(All.Count(c => c.IsNegative) >= 8, "need refuse/escalate cases");
        Assert.True(All.Count(c => c.Tags.Contains("positive")) >= 8);
        Assert.All(All, c => Assert.True(c.Tags.Contains("positive") ^ c.Tags.Contains("negative"), $"{c.Id}: tag exactly one of positive/negative"));
    }

    [Fact]
    public void Required_vulnerability_classes_are_covered()
    {
        var cats = All.Select(c => c.Category).ToHashSet();
        foreach (var k in new[] { "vulnerable_dependency", "secret_in_config", "sql_injection", "path_traversal", "weak_crypto", "insecure_deserialization",
                     "xss", "ssrf", "missing_authorization", "outdated_runtime", "licence" })
            Assert.Contains(k, cats);
        var tags = All.SelectMany(c => c.Tags).ToHashSet();
        foreach (var t in new[] { "test_only_fake_key", "false_positive", "breaking_major_upgrade", "ambiguous_fix", "prompt_injection" }) Assert.Contains(t, tags);
    }

    [Fact]
    public void Every_check_type_used_has_a_registered_checker()
    {
        var registry = Sp.GetRequiredService<ICheckerRegistry>();
        foreach (var c in All)
            foreach (var spec in c.AllChecks())
                Assert.True(registry.TryGet(spec.Type, out _), $"{c.Id}: no checker for '{spec.Type}'");
    }

    [Fact]
    public void Expected_values_use_the_known_vocabulary()
    {
        var cfg = Sp.GetRequiredService<ConfigSnapshot>();
        var fixers = cfg.Routing.Routes.Values.Select(r => r.Fixer).ToHashSet();
        foreach (var c in All)
        {
            Assert.Contains(c.Expected.Triage, new[] { "fix", "suppress", "suppress_pending", "accept_pending", "needs_human" });
            Assert.Contains(c.Expected.Outcome, new[] { "fixed", "suppressed", "suppress_pending", "accept_pending", "needs_human" });
            if (c.Expected.Fixer != null) Assert.Contains(c.Expected.Fixer, fixers);
            Assert.Equal(c.Expected.Triage == "fix", c.Expected.Fixer != null);
            if (c.IsNegative) Assert.NotEqual("fixed", c.Expected.Outcome);
        }
    }

    [Fact]
    public void Findings_fill_and_validate_against_the_canonical_schema()
    {
        var validator = Sp.GetRequiredService<SchemaValidator>();
        var gen = new DeterministicSecretGenerator();
        foreach (var c in All)
        {
            var text = File.ReadAllText(c.FindingTemplatePath);
            text = Regex.Replace(text, @"\{\{(secret|hmac|masked):([A-Z0-9_]+)\}\}", m =>
            {
                var v = gen.Generate(c.Id, m.Groups[2].Value, c.SyntheticSecrets[m.Groups[2].Value]);
                return m.Groups[1].Value == "hmac" ? Hashing.Hmac(v) : v;
            });
            var json = JsonDocument.Parse(text).RootElement;
            Assert.Null(validator.Validate("finding", json));
            var f = JsonSerializer.Deserialize<Finding>(text, Schema.Json)!;
            Assert.True(Sp.GetRequiredService<ConfigSnapshot>().Routing.Routes.ContainsKey(f.IssueType), c.Id);
            Assert.StartsWith("zulq2019/sec-agent-eval-fixture", f.Repo);   // synthetic repo, never a real one
        }
    }

    [Fact]
    public void Recordings_cover_triage_and_match_the_output_schemas()
    {
        var validator = Sp.GetRequiredService<SchemaValidator>();
        var store = new FileCassetteStore();
        var schemaFor = new Dictionary<string, string> { ["library"] = "fix-library-output", ["secrets"] = "fix-secrets-output", ["unsafe_code"] = "fix-unsafe-code-output", ["binary_licence"] = "fix-licence-output" };
        foreach (var c in All)
        {
            var cas = store.Load(c);
            Assert.True(cas != null, $"{c.Id}: replay.json missing");
            Assert.Equal(c.Id, cas!.CaseId);
            Assert.True(cas.Steps.ContainsKey("triage"), $"{c.Id}: no triage recording");
            Assert.Null(validator.Validate("triage-output", cas.Steps["triage"].Response));
            if (cas.Steps.TryGetValue("fix", out var fix)) Assert.Null(validator.Validate(schemaFor[c.Expected.Fixer!], fix.Response));
            Assert.True(cas.Source == "authored-reference" || cas.Source.StartsWith("recorded:"), c.Id);
        }
    }

    [Fact]
    public void Targets_name_existing_scanner_rules_and_fixture_files()
    {
        var scanner = (RegexRuleScanner)Sp.GetRequiredService<IFindingScanner>();
        foreach (var c in All.Where(c => c.Target != null))
        {
            Assert.Contains(c.Target!.Rule, scanner.RuleIds);
            var generated = c.GeneratedFiles.Any(g => g.Path == c.Target.File);
            Assert.True(generated || File.Exists(Path.Combine(c.FixtureDirectory, c.Target.File)) || File.Exists(Path.Combine(c.FixtureDirectory, c.Target.File + ".eval")), $"{c.Id}: {c.Target.File}");
        }
    }

    [Fact]
    public async Task Committed_fixtures_contain_no_secret_values_and_no_live_project_files()
    {
        var scanner = (RegexRuleScanner)Sp.GetRequiredService<IFindingScanner>();
        var hits = (await scanner.ScanAsync(Path.Combine(GoldenRoot, "cases"), default)).Where(h => h.RuleId.StartsWith("secret-")).ToList();
        Assert.Empty(hits);   // secrets are generated at run time from {{secret:NAME}} placeholders
        var live = Directory.GetFiles(Path.Combine(GoldenRoot, "cases"), "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".csproj") || f.EndsWith(".slnx") || f.EndsWith(".sln") || f.EndsWith(".dll")).ToList();
        Assert.Empty(live);   // project files carry the .eval suffix so Dependabot / IDEs / the repo build never pick them up
    }

    [Fact]
    public void Baseline_lists_every_case()
    {
        var b = Sp.GetRequiredService<SecAgent.Eval.Scoring.IBaselineStore>().Load(Path.Combine(GoldenRoot, "baseline.json"));
        Assert.NotNull(b);
        Assert.Equal("replay", b!.Mode);
        Assert.Equal(All.Select(c => c.Id).Order(StringComparer.Ordinal), b.Cases.Keys);
    }

    [Fact]
    public void Case_filter_matches_id_category_and_prefix()
    {
        var src = Sp.GetRequiredService<ICaseSource>();
        Assert.Single(src.Load(["sqli-concat"]));
        Assert.All(src.Load(["sql_injection"]), c => Assert.Equal("sql_injection", c.Category));
        Assert.All(src.Load(["secret-*"]), c => Assert.StartsWith("secret-", c.Id));
        Assert.Empty(src.Load(["no-such-case"]));
    }
}
