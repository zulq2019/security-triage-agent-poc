using SecAgent.Agents.Fixers;
using SecAgent.Agents.Llm;
using SecAgent.Agents.Policy;
using SecAgent.Core;
using Xunit;

namespace SecAgent.Tests;

/// <summary>The pure policy and edit functions shared by the pipeline and the evaluation harness (extracted from TriageExecutor and the fixers).</summary>
public class TriagePolicyTests
{
    static Finding Secret(string path, string sev, bool testPrefix) => new()
    {
        IssueType = IssueTypes.Secret, FilePath = path, SeverityScanner = sev, Attributes = new() { ["test_key_prefix"] = testPrefix ? "true" : "false" },
    };

    static TriageVerdict Apply(Finding f, string proposed, string sev, double conf = 0.9)
    {
        var rp = TestEnv.Cfg.RulePackFor(f.IssueType);
        return TriagePolicy.Apply(f, rp, proposed, sev, conf, TriagePolicy.SuppressionHints(f, rp), TestEnv.Cfg.Policies);
    }

    [Fact]
    public void Suppression_rule_needs_path_and_attribute()
    {
        var rp = TestEnv.Cfg.RulePackFor(IssueTypes.Secret);
        Assert.Single(TriagePolicy.SuppressionHints(Secret("tests/A.Tests/Fixtures/s.json", "medium", true), rp));
        Assert.Empty(TriagePolicy.SuppressionHints(Secret("src/App/appsettings.json", "medium", true), rp));
        Assert.Empty(TriagePolicy.SuppressionHints(Secret("tests/A.Tests/Fixtures/s.json", "medium", false), rp));
        Assert.Equal(TriagePolicy.NoRuleMatched, TriagePolicy.HintsText([]));
    }

    [Fact]
    public void Matched_rule_suppresses_at_medium_and_needs_AppSec_at_high()
    {
        Assert.Equal("suppress", Apply(Secret("tests/A.Tests/Fixtures/s.json", "medium", true), "suppress", "medium").Decision);
        Assert.Equal("suppress", Apply(Secret("tests/A.Tests/Fixtures/s.json", "medium", true), "fix", "medium").Decision);   // rule evidence decides
        Assert.Equal("suppress_pending", Apply(Secret("tests/A.Tests/Fixtures/s.json", "high", true), "suppress", "high").Decision);
    }

    [Fact]
    public void Suppress_without_evidence_low_confidence_and_escalation_go_to_a_human()
    {
        var sqli = new Finding { IssueType = IssueTypes.UnsafeCode, FilePath = "src/A.cs", SeverityScanner = "medium" };
        Assert.Equal("needs_human", Apply(sqli, "suppress", "low").Decision);
        Assert.Equal("needs_human", Apply(sqli, "fix", "high", conf: 0.45).Decision);
        Assert.Equal("needs_human", Apply(sqli, "escalate", "high").Decision);
        Assert.Equal("accept_pending", Apply(sqli, "accept", "medium").Decision);
        Assert.Equal("fix", Apply(sqli, "fix", "high").Decision);
    }

    [Fact]
    public void Secret_severity_is_never_lowered()
    {
        var v = Apply(Secret("src/App/Client.cs", "high", false), "fix", "medium");
        Assert.Equal("high", v.SeverityEffective);
        Assert.Contains(v.Notes, n => n.Contains("not lowered"));
    }

    [Fact]
    public void Status_and_bucket_follow_the_decision()
    {
        var rp = TestEnv.Cfg.RulePackFor(IssueTypes.Secret);
        Assert.Equal(Status.SuppressPending, TriagePolicy.StatusFor("suppress_pending"));
        Assert.Null(TriagePolicy.StatusFor("fix"));
        Assert.Equal(Buckets.Suppress, TriagePolicy.BucketFor("suppress", "medium", rp));
        Assert.Equal(Buckets.FixNow, TriagePolicy.BucketFor("fix", "high", rp));
        Assert.Contains("test-fixture-test-key", TriagePolicy.RulePackText(Secret("x", "high", false), rp));
    }
}

public class FixEditsTests
{
    [Fact]
    public void Library_edits_bump_only_the_named_package()
    {
        var csproj = "<PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.3\" />\n<PackageReference Include=\"Newtonsoft.Json.Bson\" Version=\"1.0.2\" />";
        var bumped = FixEdits.BumpPackageVersion(csproj, "Newtonsoft.Json", "13.0.1");
        Assert.Contains("Include=\"Newtonsoft.Json\" Version=\"13.0.1\"", bumped);
        Assert.Contains("Include=\"Newtonsoft.Json.Bson\" Version=\"1.0.2\"", bumped);
        Assert.Equal("13.0.1", FixEdits.MinimumSafeVersion([new Finding { FixedVersion = "12.0.4" }, new Finding { FixedVersion = "13.0.1" }]));
        Assert.Equal("AutoMapper", FixEdits.PackageName(new Finding { ComponentName = "nuget/AutoMapper" }));
    }

    [Fact]
    public void Framework_component_has_no_manifest_to_bump()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"fixedits-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "App.csproj"), "<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup></Project>");
        Assert.Throws<InvalidOperationException>(() => FixEdits.FindManifest(dir, "Microsoft.NETCore.App"));
    }

    [Fact]
    public void Json_secret_is_located_by_hmac_even_with_comments_and_trailing_commas()
    {
        var json = "{\n  // storage\n  \"Storage\": { \"Key\": \"value-123\", },\n}";
        var found = FixEdits.LocateJsonSecret(json, Hashing.Hmac("value-123"));
        Assert.Equal(("Storage:Key", "value-123"), found);
        Assert.Null(FixEdits.LocateJsonSecret(json, Hashing.Hmac("other")));
        var reference = FixEdits.KeyVaultReference("kv", FixEdits.KeyVaultSecretName("bad name!", "Storage:AccessKey"));
        Assert.Equal("@Microsoft.KeyVault(VaultName=kv;SecretName=storage-access-key)", reference);
        Assert.Contains($"\"{reference}\"", FixEdits.ReplaceSecretLiteral(json, "value-123", reference));
    }

    [Fact]
    public void Method_replacement_keeps_the_rest_of_the_file_and_rejects_foreign_output()
    {
        var lines = "namespace N;\npublic class C\n{\n    public int A()\n    {\n        return 1;\n    }\n\n    public int B() { return 2; }\n}".Split('\n');
        var site = FixEdits.FindMethod(lines, 6);
        Assert.Equal(("A", 4, 7, "C", "N"), (site.Symbol, site.Start, site.End, site.ClassName, site.Namespace));
        var updated = FixEdits.ReplaceMethod(lines, site, "public int A()\n{\n    // secagent: marker\n    return 42;\n}");
        Assert.Contains("        return 42;", updated);
        Assert.DoesNotContain("secagent:", updated);
        Assert.Contains("public int B() { return 2; }", updated);
        Assert.Throws<InvalidOperationException>(() => FixEdits.ReplaceMethod(lines, site, "public int Other() { return 0; }"));
        // a non-C# file (e.g. Razor) has no enclosing method: the fixer must refuse rather than edit
        var razor = FixEdits.FindMethod(["<p>", "@Html.Raw(Model.Bio)", "</p>"], 2);
        Assert.Equal("<file>", razor.Symbol);
        Assert.Throws<InvalidOperationException>(() => FixEdits.ReplaceMethod(["<p>", "@Html.Raw(Model.Bio)", "</p>"], razor, "<p>@Model.Bio</p>"));
    }

    [Fact]
    public void Test_file_uses_existing_test_usings_and_namespace()
    {
        var site = new MethodSite("Find", 1, 3, "Repo", "App.Data", []);
        var text = FixEdits.ComposeTestFile("using App.Data;\nusing Xunit;\n\nnamespace App.Tests;\n", site, "CWE-89", "[Fact]\npublic void T() { }");
        Assert.Contains("using App.Data;", text);
        Assert.Contains("namespace App.Tests;", text);
        Assert.Contains("public class RepoFindInjectionTests", text);
        Assert.EndsWith(Path.Combine("Security", "RepoFindInjectionTests.cs"), FixEdits.TestFilePath("/t", site));
    }

    [Fact]
    public void Provider_rules_pick_the_files_database_library_and_flag_foreign_types()
    {
        var rp = TestEnv.Cfg.RulePacks["unsafe_code"];
        var p = FixEdits.ProviderFor(rp, ["using Microsoft.Data.Sqlite;"]);
        Assert.Equal("Microsoft.Data.Sqlite", p.Key);
        Assert.Equal("SqlParameter", FixEdits.ForbiddenToken(p.Value, "new SqlParameter(\"@a\", 1)", ""));
        Assert.Null(FixEdits.ForbiddenToken(p.Value, "cmd.Parameters.AddWithValue(\"$a\", 1)", ""));
    }

    [Fact]
    public void Binary_and_licence_helpers()
    {
        Assert.Equal("lib/*.dll", FixEdits.BinaryIgnorePattern("lib/Legacy.Pdf.dll"));
        var gi = FixEdits.AppendIgnoreRule("bin/\n", "lib/*.dll");
        Assert.EndsWith("lib/*.dll\n", gi);
        Assert.Equal(gi, FixEdits.AppendIgnoreRule(gi, "lib/*.dll"));
        var lp = TestEnv.Cfg.RulePacks["licence"];
        Assert.Equal("denied", FixEdits.LicenceVerdict(lp, "GPL-3.0"));
        Assert.Equal("allowed", FixEdits.LicenceVerdict(lp, "MIT"));
        Assert.Equal("unknown", FixEdits.LicenceVerdict(lp, null));
    }
}

public class TriageSnippetTests
{
    [Fact]
    public void Secret_snippet_is_masked()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"snip-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        const string value = "synthetic-snippet-value-0002";
        File.WriteAllText(Path.Combine(dir, "a.json"), $"{{\n  \"Key\": \"{value}\"\n}}");
        var masker = new SecretMasker();
        masker.Register(value);
        var s = TriageSnippets.Build(new Finding { IssueType = IssueTypes.Secret, FilePath = "a.json", LineStart = 2 }, dir, masker);
        Assert.DoesNotContain(value, s);
        Assert.Contains("\"Key\"", s);
    }
}
