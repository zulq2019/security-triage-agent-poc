using System.Text.Json.Nodes;
using SecAgent.Connectors;
using SecAgent.Core;

namespace SecAgent.Agents.Repo;

/// <param name="HeadRepo">Repository the head branch lives in (head.repo.full_name). Differs from <paramref name="Repo"/> for PRs
/// opened from forks; null when unknown or when the fork was deleted.</param>
public sealed record PrInfo(string Repo, int Number, string Title, string HeadRef, string BaseRef, string HeadSha, string BaseSha, int FilesChanged, int Additions, int Deletions, string Url, string? HeadRepo = null)
{
    public bool IsFork => HeadRepo != null && !string.Equals(HeadRepo, Repo, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Local git workspace for a run: a clone at the PR head, a base worktree, and one worktree per fix branch.
/// Only local git work happens here; every call to GitHub (read the PR, push, open PRs) goes through the source control connector.</summary>
public sealed class GitWorkspace(string workRoot, Func<string, string>? cloneUrl = null)
{
    // The clone URL comes from the source control connector (IRepositoryLocator); tests point it at a local bare repository.
    readonly Func<string, string> _cloneUrl = cloneUrl ?? (repo => $"https://github.com/{repo}.git");

    const string AgentName = "Security Triage Agent (POC)";
    const string AgentEmail = "secagent-poc@users.noreply.github.com";

    static async Task<string> Git(string cwd, CancellationToken ct, params string[] args)
    {
        var r = await Proc.RunAsync("git", args, cwd, ct);
        if (r.ExitCode != 0) throw new InvalidOperationException($"git {string.Join(' ', args)} failed: {r.StdErr.Trim()}");
        return r.StdOut;
    }

    /// <summary>Maps the source control connector's PR to the pipeline's view of it.</summary>
    public static PrInfo ToPrInfo(PullRequestInfo p) =>
        new(p.Repo, p.Number, p.Title, p.HeadRef, p.BaseRef, p.HeadSha, p.BaseSha, p.FilesChanged, p.Additions, p.Deletions, p.Url, p.HeadRepo);

    public string RunDir(Guid runId) => Path.Combine(workRoot, runId.ToString("N")[..12]);
    public string HeadDir(Guid runId) => Path.Combine(RunDir(runId), "head");

    public async Task<(string Head, string Base)> PrepareAsync(Guid runId, PrInfo pr, CancellationToken ct)
    {
        var dir = RunDir(runId);
        Directory.CreateDirectory(dir);
        var head = HeadDir(runId);
        if (!Directory.Exists(Path.Combine(head, ".git")))
            await Git(dir, ct, "clone", "--quiet", _cloneUrl(pr.Repo), "head");
        // Fetch the head through the base repository's pull ref, not pr.HeadRef: for PRs from forks the head branch only
        // exists in the contributor's fork, so "fetch origin <HeadRef>" fails. refs/pull/<n>/head works for both.
        var pullRef = $"refs/remotes/origin/pr/{pr.Number}";
        await Git(head, ct, "fetch", "--quiet", "origin", $"+refs/pull/{pr.Number}/head:{pullRef}", $"+refs/heads/{pr.BaseRef}:refs/remotes/origin/{pr.BaseRef}");
        var fetched = (await Git(head, ct, "rev-parse", pullRef)).Trim();
        if (!string.Equals(fetched, pr.HeadSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"PR #{pr.Number} head moved: GitHub API reported {pr.HeadSha[..Math.Min(12, pr.HeadSha.Length)]} but refs/pull/{pr.Number}/head is {fetched[..Math.Min(12, fetched.Length)]}; re-run against the new head");
        await Git(head, ct, "checkout", "--quiet", "--detach", pr.HeadSha);
        var baseDir = Path.Combine(dir, "base");
        if (!Directory.Exists(baseDir)) await Git(head, ct, "worktree", "add", "--quiet", "--detach", baseDir, pr.BaseSha);
        return (head, baseDir);
    }

    public async Task<string> CreateFixWorktreeAsync(Guid runId, string branch, string fromSha, int attempt, CancellationToken ct)
    {
        var head = HeadDir(runId);
        var wt = Path.Combine(RunDir(runId), "wt-" + branch.Replace('/', '-') + "-a" + attempt);
        if (Directory.Exists(wt)) await Git(head, ct, "worktree", "remove", "--force", wt);
        // A retry re-creates the branch from the PR head: release it from the previous attempt's worktree first.
        var list = await Git(head, ct, "worktree", "list", "--porcelain");
        string? path = null;
        foreach (var line in list.Split('\n'))
        {
            if (line.StartsWith("worktree ")) path = line[9..].Trim();
            else if (line.Trim() == $"branch refs/heads/{branch}" && path != null) await Git(head, ct, "worktree", "remove", "--force", path);
        }
        await Git(head, ct, "worktree", "add", "--quiet", "-B", branch, wt, fromSha);
        return wt;
    }

    public static async Task<string> CommitAllAsync(string wt, string message, CancellationToken ct)
    {
        await Git(wt, ct, "add", "-A");
        await Git(wt, ct, "-c", $"user.name={AgentName}", "-c", $"user.email={AgentEmail}", "commit", "--quiet", "-m", message);
        return (await Git(wt, ct, "rev-parse", "HEAD")).Trim();
    }

    public static async Task<(int Add, int Del, int Files, List<string> Paths)> DiffStatAsync(string wt, string fromSha, CancellationToken ct)
    {
        var o = await Git(wt, ct, "diff", "--numstat", fromSha, "HEAD");
        int a = 0, d = 0; var paths = new List<string>();
        foreach (var l in o.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = l.Split('\t');
            if (int.TryParse(p[0], out var x)) a += x;
            if (int.TryParse(p[1], out var y)) d += y;
            paths.Add(p[2]);
        }
        return (a, d, paths.Count, paths);
    }

    public static Task<string> DiffAsync(string wt, string fromSha, CancellationToken ct, params string[] paths) =>
        Git(wt, ct, ["diff", "--unified=1", fromSha, "HEAD", "--", .. paths]);
}

/// <summary>Decides whether an existing fix PR (from the idempotency ledger or found by branch) may be reused for the current
/// run: it must still exist in the same repository, be OPEN, and target the scanned PR's current head branch.</summary>
public static class PrReuse
{
    public sealed record Decision(bool Reuse, string Reason);

    public static Decision Decide(PullRequestSummary? pr, string repo, string targetRef)
    {
        if (pr == null) return new(false, "PR no longer exists");
        if (!FixKeys.PrUrlInRepo(pr.Url, repo)) return new(false, $"PR #{pr.Number} is in another repository");
        if (pr.State == PullRequestState.Merged) return new(false, $"PR #{pr.Number} was merged");
        if (pr.State != PullRequestState.Open) return new(false, $"PR #{pr.Number} is {pr.State.ToString().ToLowerInvariant()}");
        if (!string.Equals(pr.BaseRef, targetRef, StringComparison.Ordinal)) return new(false, $"PR #{pr.Number} targets {pr.BaseRef}, not the current PR head {targetRef}");
        return new(true, $"PR #{pr.Number} is open against {targetRef}");
    }
}
