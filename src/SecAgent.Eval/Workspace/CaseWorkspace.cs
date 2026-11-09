using System.Text.Json;
using System.Text.RegularExpressions;
using SecAgent.Core;
using SecAgent.Eval.Cases;

namespace SecAgent.Eval.Workspace;

/// <summary>A materialised case: a throw-away git repository with the fixture at its baseline commit, plus the case's canonical finding.</summary>
public sealed class CaseWorkspace(string root, Finding finding, IReadOnlyDictionary<string, string> secrets)
{
    public string Root { get; } = root;
    public Finding Finding { get; } = finding;
    /// <summary>Synthetic secret values by placeholder name (registered with the masker; never written to reports).</summary>
    public IReadOnlyDictionary<string, string> Secrets { get; } = secrets;
}

/// <summary>Creates the workspace for a case.</summary>
public interface ICaseWorkspaceFactory
{
    Task<CaseWorkspace> CreateAsync(GoldenCase c, string runRoot, CancellationToken ct);
}

/// <summary>What changed in a workspace since its baseline commit.</summary>
public interface IGitDiff
{
    Task<IReadOnlyList<string>> ChangedFilesAsync(string root, CancellationToken ct);
}

/// <summary>Copies the fixture into {runRoot}/{caseId}, strips the ".eval" suffix that keeps fixture project files out of the repo's dependency
/// graph and IDE (App.csproj.eval → App.csproj), fills synthetic-secret placeholders, generates binary stubs, and commits a baseline.</summary>
public sealed partial class GitCaseWorkspaceFactory(IProcessRunner proc, ISyntheticSecretGenerator secrets, SecretMasker masker) : ICaseWorkspaceFactory
{
    public const string FixtureSuffix = ".eval";
    static readonly HashSet<string> TextExtensions = [".cs", ".json", ".csproj", ".slnx", ".sln", ".cshtml", ".md", ".txt", ".props", ".targets", ".yaml", ".yml", ".config", ".xml", ".gitignore", ".razor", ""];

    [GeneratedRegex(@"\{\{(secret|hmac|masked):([A-Z0-9_]+)\}\}")]
    private static partial Regex Placeholder();

    public async Task<CaseWorkspace> CreateAsync(GoldenCase c, string runRoot, CancellationToken ct)
    {
        var root = Path.Combine(runRoot, c.Id);
        if (Directory.Exists(root)) Directory.Delete(root, true);
        Directory.CreateDirectory(root);
        var values = c.SyntheticSecrets.ToDictionary(kv => kv.Key, kv => secrets.Generate(c.Id, kv.Key, kv.Value));
        foreach (var v in values.Values) masker.Register(v);

        foreach (var src in Directory.GetFiles(c.FixtureDirectory, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 }))
        {
            var rel = Path.GetRelativePath(c.FixtureDirectory, src);
            if (rel.EndsWith(FixtureSuffix, StringComparison.Ordinal)) rel = rel[..^FixtureSuffix.Length];
            var dst = Path.Combine(root, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            if (TextExtensions.Contains(Path.GetExtension(rel))) await File.WriteAllTextAsync(dst, Fill(await File.ReadAllTextAsync(src, ct), values, c.Id), ct);
            else File.Copy(src, dst);
        }
        foreach (var g in c.GeneratedFiles)
        {
            var dst = Path.Combine(root, g.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            await File.WriteAllBytesAsync(dst, g.Kind switch
            {
                "pe_stub" => [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, .. "synthetic eval stub, not executable"u8.ToArray()],
                _ => throw new InvalidOperationException($"{c.Id}: unknown generated file kind '{g.Kind}'"),
            }, ct);
        }
        // Stop MSBuild from walking up into whatever folder holds the work root.
        var props = Path.Combine(root, "Directory.Build.props");
        if (!File.Exists(props)) await File.WriteAllTextAsync(props, "<Project>\n  <!-- secagent-eval: isolates the fixture from parent folders -->\n</Project>\n", ct);

        await Git(root, ct, "init", "-q", "-b", "main");
        await File.WriteAllTextAsync(Path.Combine(root, ".git", "info", "exclude"), "bin/\nobj/\nTestResults/\n.secagent-test/\n", ct);
        await Git(root, ct, "add", "-A");
        await Git(root, ct, "-c", "user.name=secagent-eval", "-c", "user.email=eval@localhost", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "baseline");

        var findingJson = Fill(await File.ReadAllTextAsync(c.FindingTemplatePath, ct), values, c.Id);
        var finding = JsonSerializer.Deserialize<Finding>(findingJson, Schema.Json) ?? throw new InvalidDataException($"{c.Id}: empty finding.json");
        return new CaseWorkspace(root, finding, values);
    }

    static string Fill(string text, IReadOnlyDictionary<string, string> values, string caseId) => Placeholder().Replace(text, m =>
    {
        if (!values.TryGetValue(m.Groups[2].Value, out var v)) throw new InvalidDataException($"{caseId}: placeholder {m.Value} has no synthetic_secrets entry");
        return m.Groups[1].Value switch { "secret" => v, "hmac" => Hashing.Hmac(v), _ => SecretMasker.MaskOf(v) };
    });

    async Task Git(string root, CancellationToken ct, params string[] args)
    {
        var r = await proc.RunAsync("git", args, root, ct, 120);
        if (r.ExitCode != 0) throw new InvalidOperationException($"git {args[0]} failed: {r.StdErr.Trim()}");
    }
}

/// <summary>Changed, added and deleted files relative to the baseline commit (uses git so deletions and new files are included).</summary>
public sealed class GitDiff(IProcessRunner proc) : IGitDiff
{
    public async Task<IReadOnlyList<string>> ChangedFilesAsync(string root, CancellationToken ct)
    {
        await proc.RunAsync("git", ["add", "-A"], root, ct, 120);
        var r = await proc.RunAsync("git", ["diff", "--cached", "--name-only", "--no-renames", "HEAD"], root, ct, 120);
        if (r.ExitCode != 0) throw new InvalidOperationException("git diff failed: " + r.StdErr.Trim());
        return r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(p => !IsBuildOutput(p)).Order(StringComparer.Ordinal).ToList();
    }

    /// <summary>Build and test outputs are not part of a fix.</summary>
    public static bool IsBuildOutput(string path) =>
        path.Split('/').Any(seg => seg is "bin" or "obj" or "TestResults" or ".secagent-test");
}
