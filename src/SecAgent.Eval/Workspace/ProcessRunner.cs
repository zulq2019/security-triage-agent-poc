using SecAgent.Core;

namespace SecAgent.Eval.Workspace;

/// <summary>Runs external commands (git, dotnet). A port so tests can replace builds with a fake.</summary>
public interface IProcessRunner
{
    Task<Proc.Result> RunAsync(string tool, IReadOnlyList<string> args, string cwd, CancellationToken ct, int timeoutSeconds = 600);
}

public sealed class ProcessRunner : IProcessRunner
{
    public Task<Proc.Result> RunAsync(string tool, IReadOnlyList<string> args, string cwd, CancellationToken ct, int timeoutSeconds = 600) =>
        Proc.RunAsync(tool == "dotnet" ? Proc.Which("dotnet") : tool, args, cwd, ct, timeoutSeconds: timeoutSeconds);
}
