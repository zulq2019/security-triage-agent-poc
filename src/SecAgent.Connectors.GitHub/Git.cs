using System.Diagnostics;
using System.Text.RegularExpressions;
using SecAgent.Connectors.Secrets;

namespace SecAgent.Connectors.GitHub;

public sealed record GitResult(int ExitCode, string StdOut, string StdErr);

/// <summary>Runs git in a working directory (seam for tests).</summary>
public interface IGitCommandRunner
{
    Task<GitResult> RunAsync(string workingDirectory, IReadOnlyList<string> args, CancellationToken ct);
}

public sealed class ProcessGitCommandRunner : IGitCommandRunner
{
    public Task<GitResult> RunAsync(string workingDirectory, IReadOnlyList<string> args, CancellationToken ct) => ProcessRunner.RunAsync("git", args, workingDirectory, ct);
}

internal static class ProcessRunner
{
    public static async Task<GitResult> RunAsync(string file, IReadOnlyList<string> args, string? cwd, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = cwd ?? Environment.CurrentDirectory };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        using var p = Process.Start(psi) ?? throw new ConnectorException($"cannot start {file}");
        var so = p.StandardOutput.ReadToEndAsync(ct);
        var se = p.StandardError.ReadToEndAsync(ct);
        try { await p.WaitForExitAsync(ct); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch { } throw; }
        return new GitResult(p.ExitCode, await so, await se);
    }
}

/// <summary>Local development only: "gh-cli:token" resolves to the token of the signed-in GitHub CLI (`gh auth token`), so a laptop run needs
/// no extra secret. Rejected in MultiTenant mode (process-wide credential); Azure uses "kv:" references.</summary>
public sealed partial class GhCliTokenSecretSource : ISecretSource
{
    [GeneratedRegex(@"^[A-Za-z0-9_]+$")] private static partial Regex TokenShape();
    public string Scheme => "gh-cli";

    public async ValueTask<string?> TryGetAsync(string name, CancellationToken ct)
    {
        var gh = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "gh"), "/usr/local/bin/gh", "/usr/bin/gh" }
            .FirstOrDefault(File.Exists) ?? "gh";
        try
        {
            var r = await ProcessRunner.RunAsync(gh, ["auth", "token"], null, ct);
            var token = r.StdOut.Trim();
            return r.ExitCode == 0 && token.Length > 0 && TokenShape().IsMatch(token) ? token : null;
        }
        catch (System.ComponentModel.Win32Exception) { return null; }   // gh not installed
    }
}
