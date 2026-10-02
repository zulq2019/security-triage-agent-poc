using System.Text.Json.Nodes;
using SecAgent.Core;

namespace SecAgent.Agents.Repo;

/// <param name="HeadRepo">Repository the head branch lives in (head.repo.full_name). Differs from <paramref name="Repo"/> for PRs
/// opened from forks; null when unknown or when the fork was deleted.</param>
public sealed record PrInfo(string Repo, int Number, string Title, string HeadRef, string BaseRef, string HeadSha, string BaseSha, int FilesChanged, int Additions, int Deletions, string Url, string? HeadRepo = null)
{
    public bool IsFork => HeadRepo != null && !string.Equals(HeadRepo, Repo, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Local git workspace for a run: a clone at the PR head, a base worktree, and one worktree per fix branch.</summary>
public sealed class GitWorkspace(string workRoot, Func<string, string>? cloneUrl = null)
{
    // Injectable so tests can point at a local bare repository instead of github.com.
    readonly Func<string, string> _cloneUrl = cloneUrl ?? (repo => $"https://github.com/{repo}.git");

    const string AgentName = "Security Triage Agent (POC)";
    const string AgentEmail = "secagent-poc@users.noreply.github.com";

    static async Task<string> Git(string cwd, CancellationToken ct, params string[] args)
    {
        var r = await Proc.RunAsync("git", args, cwd, ct);
        if (r.ExitCode != 0) throw new InvalidOperationException($"git {string.Join(' ', args)} failed: {r.StdErr.Trim()}");
        return r.StdOut;
    }

    public static async Task<PrInfo> GetPrAsync(string repo, int pr, CancellationToken ct)
    {
        var r = await Proc.RunAsync(Proc.Which("gh"), ["api", $"repos/{repo}/pulls/{pr}"], ct: ct);
        if (r.ExitCode != 0) throw new InvalidOperationException("gh api pulls failed: " + r.StdErr);
        var j = JsonNode.Parse(r.StdOut)!;
        return new PrInfo(repo, pr, j["title"]!.GetValue<string>(), j["head"]!["ref"]!.GetValue<string>(), j["base"]!["ref"]!.GetValue<string>(),
            j["head"]!["sha"]!.GetValue<string>(), j["base"]!["sha"]!.GetValue<string>(), j["changed_files"]!.GetValue<int>(),
            j["additions"]!.GetValue<int>(), j["deletions"]!.GetValue<int>(), j["html_url"]!.GetValue<string>(),
            j["head"]?["repo"]?["full_name"]?.GetValue<string>());
    }

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

    public static async Task<bool> RemoteBranchExistsAsync(string wt, string branch, CancellationToken ct) =>
        (await Git(wt, ct, "ls-remote", "--heads", "origin", branch)).Trim().Length > 0;

    /// <summary>Plain push of a new branch. Never force-pushes.</summary>
    public static Task<string> PushAsync(string wt, string branch, CancellationToken ct, string? remoteBranch = null) =>
        Git(wt, ct, "push", "--quiet", "origin", $"HEAD:refs/heads/{remoteBranch ?? branch}");
}

/// <summary>GitHub operations available to agents: find and create PRs. There is intentionally no merge, approve or
/// branch-protection method in this class (FR-17); merges are a human action on GitHub.</summary>
public static class GitHubPrs
{
    public sealed record Pr(int Number, string Url, string State, string Title);

    public static async Task<Pr?> FindByHeadAsync(string repo, string head, CancellationToken ct)
    {
        var r = await Proc.RunAsync(Proc.Which("gh"), ["pr", "list", "-R", repo, "--head", head, "--state", "all", "--json", "number,url,state,title"], ct: ct);
        if (r.ExitCode != 0) throw new InvalidOperationException("gh pr list failed: " + r.StdErr);
        var arr = JsonNode.Parse(r.StdOut)!.AsArray();
        var j = arr.FirstOrDefault(x => x!["state"]!.GetValue<string>() == "OPEN") ?? arr.FirstOrDefault();
        return j == null ? null : new Pr(j["number"]!.GetValue<int>(), j["url"]!.GetValue<string>(), j["state"]!.GetValue<string>(), j["title"]!.GetValue<string>());
    }

    public static async Task<Pr> CreateAsync(string repo, string baseBranch, string head, string title, string body, CancellationToken ct)
    {
        var bodyFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(bodyFile, body, ct);
        var r = await Proc.RunAsync(Proc.Which("gh"), ["pr", "create", "-R", repo, "--base", baseBranch, "--head", head, "--title", title, "--body-file", bodyFile], ct: ct);
        File.Delete(bodyFile);
        if (r.ExitCode != 0) throw new InvalidOperationException("gh pr create failed: " + r.StdErr);
        var url = r.StdOut.Trim().Split('\n').Last().Trim();
        return new Pr(int.Parse(url.Split('/').Last()), url, "OPEN", title);
    }
}
