using System.Text;
using SecAgent.Core;

namespace SecAgent.Agents.Llm;

/// <summary>The code_snippet component for a triage context pack: the evidence a reviewer would look at for each issue type
/// (enclosing method, masked secret line, manifest entry, licence header, binary metadata). Pure function over a checked-out tree,
/// shared by the pipeline's TriageExecutor and the evaluation harness.</summary>
public static class TriageSnippets
{
    public static string Build(Finding f, string headDir, SecretMasker masker)
    {
        string Numbered(string rel, int from, int to)
        {
            var path = Path.Combine(headDir, rel);
            if (!File.Exists(path)) return "";
            var lines = File.ReadAllLines(path);
            from = Math.Max(1, from); to = Math.Min(lines.Length, to);
            return string.Join('\n', Enumerable.Range(from, Math.Max(0, to - from + 1)).Select(n => $"{n,4}: {lines[n - 1]}"));
        }
        switch (f.IssueType)
        {
            case IssueTypes.UnsafeCode:
                int.TryParse(f.Attributes.GetValueOrDefault("function_start"), out var a); int.TryParse(f.Attributes.GetValueOrDefault("function_end"), out var b);
                return $"// {f.FilePath}\n" + Numbered(f.FilePath!, a > 0 ? a : (f.LineStart ?? 1) - 6, b > 0 ? b : (f.LineStart ?? 1) + 6);
            case IssueTypes.Secret:
                return $"// {f.FilePath}\n" + masker.Mask(Numbered(f.FilePath!, (f.LineStart ?? 1) - 2, (f.LineStart ?? 1) + 2), false);
            case IssueTypes.VulnerableDependency:
            {
                var pkg = f.Attributes.GetValueOrDefault("package") ?? "";
                var sb = new StringBuilder();
                foreach (var proj in Directory.GetFiles(headDir, "*.csproj", SearchOption.AllDirectories))
                    foreach (var l in File.ReadAllLines(proj).Where(l => l.Contains($"\"{pkg}\"")))
                        sb.AppendLine($"{Path.GetRelativePath(headDir, proj)}: {l.Trim()}");
                sb.AppendLine($"lock file: {f.FilePath} · {f.DirectOrTransitive} dependency · fixed in {f.FixedVersion}");
                return sb.ToString();
            }
            case IssueTypes.Licence:
            {
                var dir = Path.Combine(headDir, f.ComponentName!.Replace("file:", ""));
                var sb = new StringBuilder();
                if (Directory.Exists(dir))
                    foreach (var file in Directory.GetFiles(dir).Order())
                        sb.AppendLine(Numbered(Path.GetRelativePath(headDir, file), 1, 8));
                var users = Directory.GetFiles(headDir, "*.cs", SearchOption.AllDirectories).Where(p => !p.StartsWith(dir) && !p.Replace('\\', '/').Contains("/obj/") && File.ReadAllText(p).Contains("CsvEscaper"))
                    .Select(p => Path.GetRelativePath(headDir, p)).ToList();
                sb.AppendLine("used by: " + (users.Count > 0 ? string.Join(", ", users) : "none"));
                return sb.ToString();
            }
            default:
            {
                var refs = Directory.GetFiles(headDir, "*.csproj", SearchOption.AllDirectories).Where(p => File.ReadAllText(p).Contains(Path.GetFileName(f.FilePath!))).ToList();
                return $"file {f.FilePath} · {f.Attributes.GetValueOrDefault("size")} bytes · sha256 {f.Attributes.GetValueOrDefault("sha256")?[..16]}… · referenced by project files: {(refs.Count > 0 ? string.Join(", ", refs) : "none")}";
            }
        }
    }
}
