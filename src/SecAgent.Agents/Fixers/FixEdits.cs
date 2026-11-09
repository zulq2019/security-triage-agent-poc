using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecAgent.Agents.Scanners;
using SecAgent.Core;

namespace SecAgent.Agents.Fixers;

/// <summary>The C# method a SAST finding sits in, and the file context the unsafe-code fixer needs.</summary>
public sealed record MethodSite(string Symbol, int Start, int End, string ClassName, string Namespace, List<string> Usings)
{
    public string MethodText(string[] lines) => string.Join('\n', lines[(Start - 1)..End]);
}

/// <summary>The deterministic edits the fixers make, as pure functions (no tools, no store, no model). The pipeline's fixers call them
/// inside their allow-listed tools; the evaluation harness calls the same functions, so it scores the code that ships.</summary>
public static class FixEdits
{
    // ------------------------------------------------ library ------------------------------------------------
    public static string PackageName(Finding f) => f.Attributes.GetValueOrDefault("package") ?? f.ComponentName!.Split('/').Last();

    /// <summary>The highest fixed version across the group's findings (the minimum version that fixes all of them).</summary>
    public static string MinimumSafeVersion(IEnumerable<Finding> findings) =>
        findings.Select(x => x.FixedVersion).Where(v => v != null).OrderByDescending(v => System.Version.Parse(v!)).FirstOrDefault()
        ?? throw new InvalidOperationException("no fixed version known");

    /// <summary>The project file with a PackageReference to the package (a framework/runtime component has none: the fixer cannot bump it).</summary>
    public static string FindManifest(string worktree, string package) =>
        Directory.GetFiles(worktree, "*.csproj", SearchOption.AllDirectories).FirstOrDefault(p => File.ReadAllText(p).Contains($"Include=\"{package}\""))
        ?? throw new InvalidOperationException($"no project file has a PackageReference to {package}");

    public static string ManifestLine(string csprojText, string package) => csprojText.Split('\n').First(l => l.Contains($"Include=\"{package}\"")).Trim();

    public static string BumpPackageVersion(string csprojText, string package, string target) =>
        Regex.Replace(csprojText, $"(Include=\"{Regex.Escape(package)}\"\\s+Version=\")[^\"]+(\")", $"${{1}}{target}${{2}}");

    // ------------------------------------------------ secrets ------------------------------------------------
    /// <summary>Finds the leaked literal in a JSON config file by its HMAC (the value itself is never stored). Null when not found.</summary>
    public static (string ConfigPath, string Literal)? LocateJsonSecret(string jsonText, string? secretHash)
    {
        (string, string)? found = null;
        void Walk(JsonNode? n, string p)
        {
            if (n is JsonObject o) foreach (var kv in o) Walk(kv.Value, p.Length == 0 ? kv.Key : p + ":" + kv.Key);
            else if (n is JsonValue v && v.TryGetValue<string>(out var str) && Hashing.Hmac(str) == secretHash) found = (p, str);
        }
        Walk(JsonNode.Parse(jsonText, documentOptions: new System.Text.Json.JsonDocumentOptions { CommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true }), "");
        return found;
    }

    /// <summary>The model's proposed Key Vault secret name when valid, else one derived from the config path (Export:AccessKey → export-access-key).</summary>
    public static string KeyVaultSecretName(string proposed, string configPath) =>
        Regex.IsMatch(proposed, "^[0-9a-zA-Z-]{1,127}$") ? proposed : Regex.Replace(configPath.Replace(":", "-"), "([a-z])([A-Z])", "$1-$2").ToLowerInvariant();

    public static string KeyVaultReference(string vaultName, string secretName) => $"@Microsoft.KeyVault(VaultName={vaultName};SecretName={secretName})";

    public static string ReplaceSecretLiteral(string text, string literal, string reference) => text.Replace("\"" + literal + "\"", "\"" + reference + "\"");

    // ------------------------------------------------ unsafe code ------------------------------------------------
    public static MethodSite FindMethod(string[] lines, int line)
    {
        var (symbol, start, end) = CodeNav.EnclosingMethod(lines, line);
        var all = string.Join('\n', lines);
        return new MethodSite(symbol, start, end, Regex.Match(all, @"class\s+(\w+)").Groups[1].Value, Regex.Match(all, @"namespace\s+([\w\.]+)").Groups[1].Value,
            lines.Where(l => l.StartsWith("using ")).ToList());
    }

    /// <summary>Public API lines in the source tree (types and method signatures), given to the model as context for the test.</summary>
    public static List<string> PublicApi(IEnumerable<string> sourceFiles) =>
        sourceFiles.SelectMany(File.ReadAllLines).Where(l => Regex.IsMatch(l, @"^\s*public (static |sealed )?(class|record|[\w<>\?]+ \w+\()")).Select(l => l.Trim()).Distinct().Take(25).ToList();

    /// <summary>The database-provider rule of the rule pack that matches the file's usings (default when none).</summary>
    public static KeyValuePair<string, ProviderRule> ProviderFor(RulePack rp, IEnumerable<string> usings) =>
        rp.Providers.FirstOrDefault(kv => usings.Any(u => u.Contains(kv.Key)));

    /// <summary>Rules-as-code pre-build check: the first type from another database provider that the model output uses, or null.</summary>
    public static string? ForbiddenToken(ProviderRule? provider, string methodCode, string testCode) =>
        provider?.Forbid.FirstOrDefault(t => (methodCode + testCode).Contains(t));

    /// <summary>Replaces lines Start..End with the model's method (marker lines dropped, re-indented). Throws when the output does not define the method.</summary>
    public static string ReplaceMethod(string[] lines, MethodSite site, string methodCode)
    {
        var newMethod = string.Join('\n', methodCode.Replace("\r", "").Split('\n').Where(l => !l.Contains("secagent:")));
        if (!newMethod.Contains(site.Symbol)) throw new InvalidOperationException($"model output does not define {site.Symbol}");
        var first = lines[site.Start - 1];
        var reindented = Reindent(newMethod, first[..(first.Length - first.TrimStart().Length)]);
        return string.Join('\n', lines[..(site.Start - 1)].Concat(reindented.Split('\n')).Concat(lines[site.End..])) + "\n";
    }

    public static string TestFilePath(string testDir, MethodSite site) => Path.Combine(testDir, "Security", $"{site.ClassName}{site.Symbol}InjectionTests.cs");

    /// <summary>The new regression test file: usings and namespace of an existing test, the model's [Fact] wrapped in a class.</summary>
    public static string ComposeTestFile(string existingTest, MethodSite site, string? cwe, string testCode)
    {
        var testUsings = Regex.Matches(existingTest, @"^using [^;]+;", RegexOptions.Multiline).Select(m => m.Value).Append("using Xunit;").Distinct();
        var testNs = Regex.Match(existingTest, @"namespace\s+([\w\.]+)").Groups[1].Value;
        return $"{string.Join('\n', testUsings)}\n\nnamespace {(testNs.Length > 0 ? testNs : "Tests")};\n\n// Added by Security Triage & Fix Agent (unsafe-code-fixer): regression test for {cwe} in {site.ClassName}.{site.Symbol}\npublic class {site.ClassName}{site.Symbol}InjectionTests\n{{\n{Reindent(testCode.Replace("\r", ""), "    ")}\n}}\n";
    }

    public static string Reindent(string code, string indent)
    {
        var ls = code.Trim('\n').Split('\n');
        var min = ls.Where(l => l.Trim().Length > 0).Select(l => l.Length - l.TrimStart().Length).DefaultIfEmpty(0).Min();
        return string.Join('\n', ls.Select(l => l.Trim().Length == 0 ? "" : indent + l[Math.Min(min, l.Length - l.TrimStart().Length)..]));
    }

    public static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "\n…(truncated)";

    // ------------------------------------------------ binary / licence ------------------------------------------------
    /// <summary>Ignore rule for a removed binary: its folder + extension (lib/x.dll → lib/*.dll).</summary>
    public static string BinaryIgnorePattern(string relPath) => $"{Path.GetDirectoryName(relPath)!.Replace('\\', '/')}/*{Path.GetExtension(relPath)}".TrimStart('/');

    /// <summary>.gitignore text with the rule appended (unchanged when already present).</summary>
    public static string AppendIgnoreRule(string existing, string pattern) =>
        existing.Contains(pattern) ? existing : existing.TrimEnd('\n') + $"\n\n# secagent: binaries come from the artefact feed (e.g. Azure Artifacts), not source control\n{pattern}\n";

    /// <summary>Licence policy verdict for an SPDX id from the licence rule pack: denied | review | allowed | unknown.</summary>
    public static string LicenceVerdict(RulePack licencePack, string? spdx) =>
        licencePack.GetList(licencePack.Policy, "denied").Contains(spdx ?? "") ? "denied"
        : licencePack.GetList(licencePack.Policy, "review").Contains(spdx ?? "") ? "review"
        : licencePack.GetList(licencePack.Policy, "allowed").Contains(spdx ?? "") ? "allowed" : "unknown";
}
