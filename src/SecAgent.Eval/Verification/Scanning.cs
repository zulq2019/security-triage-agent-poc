using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecAgent.Eval.Composition;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecAgent.Eval.Verification;

/// <summary>One scanner hit. No matched text is kept (it could be a secret).</summary>
public sealed record ScanHit(string RuleId, string File, int Line);

/// <summary>Deterministic rescan used for "target gone" and "no new findings". A port: semgrep/gitleaks/Trivy adapters can implement it later.</summary>
public interface IFindingScanner
{
    Task<IReadOnlyList<ScanHit>> ScanAsync(string root, CancellationToken ct);
}

public sealed class ScannerRuleSet
{
    public List<ScannerRule> Rules { get; set; } = [];
}

public sealed class ScannerRule
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>regex (per line, files matching globs) | absent (file matches <see cref="When"/> but nowhere matches <see cref="Pattern"/>; hit on the
    /// first When line) | dependency (PackageReference below a version) | binary (extension + magic bytes).</summary>
    public string Kind { get; set; } = "regex";
    public List<string> Globs { get; set; } = [];
    public string Pattern { get; set; } = "";
    public bool IgnoreCase { get; set; }
    /// <summary>absent rules only: the line pattern that makes a file in scope (e.g. a state-changing HTTP endpoint).</summary>
    public string When { get; set; } = "";
    public List<VulnerablePackage> Packages { get; set; } = [];
    public List<string> Extensions { get; set; } = [];
}

public sealed class VulnerablePackage { public string Package { get; set; } = ""; public string Below { get; set; } = ""; }

/// <summary>Rules from eval/golden/scanner-rules.yaml (regex, dependency and binary rules). Deliberately simple and dependency-free so CI needs
/// no scanner installs; it stands in for the pipeline's gitleaks/Trivy/Semgrep rescan in the evaluation only.</summary>
public sealed class RegexRuleScanner : IFindingScanner
{
    readonly List<(ScannerRule Rule, Regex? Rx, Regex? When, List<Regex> Globs)> _rules;

    public RegexRuleScanner(IOptions<EvalOptions> options)
    {
        var path = options.Value.ScannerRulesPath;
        var set = File.Exists(path)
            ? new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build().Deserialize<ScannerRuleSet>(File.ReadAllText(path)) ?? new()
            : throw new FileNotFoundException("scanner rules not found", path);
        Regex Rx(string p, ScannerRule r) => new(p, RegexOptions.Compiled | (r.IgnoreCase ? RegexOptions.IgnoreCase : 0));
        _rules = set.Rules.Select(r => (r, r.Kind is "regex" or "absent" ? Rx(r.Pattern, r) : null, r.Kind == "absent" ? Rx(r.When, r) : null,
            r.Globs.Select(GlobRegex).ToList())).ToList();
    }

    public IReadOnlyList<string> RuleIds => _rules.Select(r => r.Rule.Id).ToList();

    public Task<IReadOnlyList<ScanHit>> ScanAsync(string root, CancellationToken ct)
    {
        var hits = new List<ScanHit>();
        var files = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Select(f => (Abs: f, Rel: Path.GetRelativePath(root, f).Replace('\\', '/')))
            .Where(f => !f.Rel.Split('/').Any(s => s is ".git" or "bin" or "obj" or "TestResults" or ".secagent-test")).OrderBy(f => f.Rel, StringComparer.Ordinal).ToList();
        foreach (var (rule, rx, when, globs) in _rules)
        {
            ct.ThrowIfCancellationRequested();
            switch (rule.Kind)
            {
                case "regex":
                    foreach (var f in files.Where(f => globs.Count == 0 || globs.Any(g => g.IsMatch(f.Rel))))
                    {
                        var lines = File.ReadAllLines(f.Abs);
                        for (int i = 0; i < lines.Length; i++) if (rx!.IsMatch(lines[i])) hits.Add(new(rule.Id, f.Rel, i + 1));
                    }
                    break;
                case "absent":
                    foreach (var f in files.Where(f => globs.Count == 0 || globs.Any(g => g.IsMatch(f.Rel))))
                    {
                        var lines = File.ReadAllLines(f.Abs);
                        var first = Array.FindIndex(lines, l => when!.IsMatch(l));
                        if (first >= 0 && !lines.Any(l => rx!.IsMatch(l))) hits.Add(new(rule.Id, f.Rel, first + 1));
                    }
                    break;
                case "dependency":
                    foreach (var f in files.Where(f => f.Rel.EndsWith(".csproj", StringComparison.Ordinal)))
                    {
                        var lines = File.ReadAllLines(f.Abs);
                        for (int i = 0; i < lines.Length; i++)
                        {
                            var m = Regex.Match(lines[i], "Include=\"([^\"]+)\"\\s+Version=\"([^\"]+)\"");
                            if (!m.Success) continue;
                            var pkg = rule.Packages.FirstOrDefault(p => p.Package.Equals(m.Groups[1].Value, StringComparison.OrdinalIgnoreCase));
                            if (pkg != null && Versions.Compare(m.Groups[2].Value, pkg.Below) < 0) hits.Add(new(rule.Id, f.Rel, i + 1));
                        }
                    }
                    break;
                case "binary":
                    foreach (var f in files.Where(f => rule.Extensions.Contains(Path.GetExtension(f.Rel))))
                    {
                        var head = new byte[2];
                        using (var s = File.OpenRead(f.Abs)) if (s.Read(head, 0, 2) < 2) continue;
                        if (head[0] == 0x4D && head[1] == 0x5A) hits.Add(new(rule.Id, f.Rel, 1));
                    }
                    break;
                default: throw new InvalidDataException($"scanner rule {rule.Id}: unknown kind '{rule.Kind}'");
            }
        }
        return Task.FromResult<IReadOnlyList<ScanHit>>(hits);
    }

    static Regex GlobRegex(string glob) =>
        new("^" + Regex.Escape(glob).Replace(@"\*\*/", "(.*/)?").Replace(@"\*\*", ".*").Replace(@"\*", "[^/]*") + "$", RegexOptions.Compiled);

    /// <summary>Hits in <paramref name="after"/> beyond what <paramref name="before"/> had for the same rule and file (line moves are not new findings).</summary>
    public static IReadOnlyList<ScanHit> Introduced(IReadOnlyList<ScanHit> before, IReadOnlyList<ScanHit> after)
    {
        var counts = before.GroupBy(h => (h.RuleId, h.File)).ToDictionary(g => g.Key, g => g.Count());
        return after.GroupBy(h => (h.RuleId, h.File)).SelectMany(g => g.Skip(counts.GetValueOrDefault(g.Key))).ToList();
    }
}

/// <summary>Numeric version comparison for NuGet-style versions (pre-release suffixes ignored).</summary>
public static class Versions
{
    public static int Compare(string a, string b)
    {
        static int[] P(string v) => v.Split('-', '+')[0].Split('.').Select(x => int.TryParse(x, out var n) ? n : 0).Concat(Enumerable.Repeat(0, 4)).Take(4).ToArray();
        var (x, y) = (P(a), P(b));
        for (int i = 0; i < 4; i++) if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        return 0;
    }
}
