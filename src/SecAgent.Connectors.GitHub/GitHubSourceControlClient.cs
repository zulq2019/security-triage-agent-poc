using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.GitHub;

/// <summary>GitHub REST implementation of <see cref="ISourceControlClient"/> (API version 2022-11-28). Replaces the POC's `gh` CLI calls
/// (GitWorkspace.GetPrAsync, GitHubPrs.*). Contains no merge, approve or branch-protection call; branch writes refuse the default branch.</summary>
public sealed class GitHubSourceControlClient(HttpClient http, ConnectionSettings connection, ISecretProvider secrets, IGitCommandRunner git)
    : ConnectorRestClient(http, connection, GitHubConnector.Id), ISourceControlClient
{
    readonly ConcurrentDictionary<string, string> _defaultBranch = new(StringComparer.OrdinalIgnoreCase);

    protected override async ValueTask AuthorizeAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Bearer(request, await secrets.GetSecretAsync(Connection.RequireSecret(), ct));
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        request.Headers.UserAgent.ParseAdd("secagent-poc/0.1");
    }

    static string R(string repo) => "repos/" + string.Join('/', repo.Split('/').Select(Uri.EscapeDataString));
    static string B(string branch) => string.Join('/', branch.Split('/').Select(Uri.EscapeDataString));

    public async Task<PullRequestInfo?> GetPullRequestAsync(string repo, int number, CancellationToken ct)
    {
        var j = await GetAsync($"{R(repo)}/pulls/{number}", ct, notFoundIsNull: true);
        if (j == null) return null;
        return new PullRequestInfo(repo, Int(j, "number"), Str(j, "title"), Str(j["head"], "ref"), Str(j["base"], "ref"), Str(j["head"], "sha"), Str(j["base"], "sha"),
            Int(j, "changed_files"), Int(j, "additions"), Int(j, "deletions"), Str(j, "html_url"), State(j), StrOrNull(j["head"]?["repo"], "full_name"));
    }

    public async Task<IReadOnlyList<ChangedFile>> ListChangedFilesAsync(string repo, int number, CancellationToken ct)
    {
        var files = new List<ChangedFile>();
        for (var page = 1; page <= 30; page++)   // GitHub returns at most 3000 files
        {
            var arr = (await GetAsync($"{R(repo)}/pulls/{number}/files?per_page=100&page={page}", ct))?.AsArray() ?? [];
            files.AddRange(arr.Select(f => new ChangedFile(Str(f, "filename"), Str(f, "status"), Int(f, "additions"), Int(f, "deletions"), StrOrNull(f, "previous_filename"))));
            if (arr.Count < 100) break;
        }
        return files;
    }

    public async Task<PullRequestSummary?> FindPullRequestByHeadAsync(string repo, string headRef, CancellationToken ct)
    {
        var owner = repo.Split('/')[0];
        var arr = (await GetAsync($"{R(repo)}/pulls?state=all&per_page=100&head={Uri.EscapeDataString(owner + ":" + headRef)}", ct))?.AsArray() ?? [];
        var all = arr.Select(Summary).ToList();
        return all.FirstOrDefault(p => p.State == PullRequestState.Open) ?? all.FirstOrDefault();
    }

    public async Task<PullRequestSummary> CreatePullRequestAsync(string repo, NewPullRequest request, CancellationToken ct)
    {
        await RefuseDefaultBranchAsync(repo, request.HeadRef, "open a PR from", ct);
        var body = new JsonObject { ["title"] = request.Title, ["head"] = request.HeadRef, ["base"] = request.BaseRef, ["body"] = request.Body, ["draft"] = request.Draft };
        return Summary(await SendAsync(HttpMethod.Post, $"{R(repo)}/pulls", body, ct));
    }

    public async Task<CommentRef> AddCommentAsync(string repo, int number, string body, CancellationToken ct)
    {
        var j = await SendAsync(HttpMethod.Post, $"{R(repo)}/issues/{number}/comments", new JsonObject { ["body"] = body }, ct);
        return new CommentRef(j?["id"]?.GetValue<long>() ?? 0, Str(j, "html_url"));
    }

    public async Task<bool> BranchExistsAsync(string repo, string branch, CancellationToken ct) =>
        await GetAsync($"{R(repo)}/branches/{B(branch)}", ct, notFoundIsNull: true) != null;

    public async Task CreateBranchAsync(string repo, string branch, string fromSha, CancellationToken ct)
    {
        await RefuseDefaultBranchAsync(repo, branch, "create", ct);
        await SendAsync(HttpMethod.Post, $"{R(repo)}/git/refs", new JsonObject { ["ref"] = "refs/heads/" + branch, ["sha"] = fromSha }, ct);
    }

    /// <summary>Git Data API: tree on top of the branch head, commit, then a fast-forward ref update (force = false).</summary>
    public async Task<CommitResult> CommitAsync(string repo, CommitRequest request, CancellationToken ct)
    {
        await RefuseDefaultBranchAsync(repo, request.Branch, "commit to", ct);
        var head = await GetAsync($"{R(repo)}/git/ref/heads/{B(request.Branch)}", ct, notFoundIsNull: true)
                   ?? throw new ConnectorException($"github: branch '{request.Branch}' does not exist in {repo}; create it first");
        var parent = Str(head["object"], "sha");
        if (request.ExpectedHeadSha is { } expected && !expected.Equals(parent, StringComparison.OrdinalIgnoreCase))
            throw new ConnectorException($"github: branch '{request.Branch}' moved (expected {Short(expected)}, found {Short(parent)}); not committing");
        var baseTree = Str((await GetAsync($"{R(repo)}/git/commits/{parent}", ct))?["tree"], "sha");
        var entries = new JsonArray();
        foreach (var c in request.Changes)
        {
            var e = new JsonObject { ["path"] = c.Path, ["mode"] = "100644", ["type"] = "blob" };
            if (c.Content is null) e["sha"] = null; else e["content"] = c.Content;
            entries.Add(e);
        }
        var tree = Str(await SendAsync(HttpMethod.Post, $"{R(repo)}/git/trees", new JsonObject { ["base_tree"] = baseTree, ["tree"] = entries }, ct), "sha");
        var commit = Str(await SendAsync(HttpMethod.Post, $"{R(repo)}/git/commits",
            new JsonObject { ["message"] = request.Message, ["tree"] = tree, ["parents"] = new JsonArray(parent) }, ct), "sha");
        await SendAsync(HttpMethod.Patch, $"{R(repo)}/git/refs/heads/{B(request.Branch)}", new JsonObject { ["sha"] = commit, ["force"] = false }, ct);
        return new CommitResult(request.Branch, commit);
    }

    public async Task<IReadOnlyList<CheckRunInfo>> ListCheckRunsAsync(string repo, string sha, CancellationToken ct)
    {
        var j = await GetAsync($"{R(repo)}/commits/{Uri.EscapeDataString(sha)}/check-runs?per_page=100", ct);
        return (j?["check_runs"]?.AsArray() ?? []).Select(c => new CheckRunInfo(Str(c, "name"), Str(c, "status"), StrOrNull(c, "conclusion"), StrOrNull(c, "details_url"))).ToList();
    }

    /// <summary>Plain push of the worktree HEAD to a new remote branch. Never forced, never the default branch.</summary>
    public async Task<BranchPublishResult> PublishBranchAsync(BranchPublishRequest request, CancellationToken ct)
    {
        await RefuseDefaultBranchAsync(request.Repo, request.RemoteBranch, "push to", ct);
        var push = await git.RunAsync(request.WorktreePath, ["push", "--quiet", "origin", $"HEAD:refs/heads/{request.RemoteBranch}"], ct);
        if (push.ExitCode != 0) throw new ConnectorException($"github: git push of {request.RemoteBranch} failed: {FirstLine(push.StdErr)}", push.StdErr.Contains("Could not resolve host"));
        var sha = await git.RunAsync(request.WorktreePath, ["rev-parse", "HEAD"], ct);
        return new BranchPublishResult(request.Repo, request.RemoteBranch, sha.ExitCode == 0 ? sha.StdOut.Trim() : null);
    }

    public string CloneUrl(string repo) => (Connection.Get("CloneBaseUrl") ?? "https://github.com/").TrimEnd('/') + "/" + repo + ".git";

    internal async Task<int> RateLimitRemainingAsync(CancellationToken ct) => Int((await GetAsync("rate_limit", ct))?["resources"]?["core"], "remaining");

    async Task RefuseDefaultBranchAsync(string repo, string branch, string action, CancellationToken ct)
    {
        if (!_defaultBranch.TryGetValue(repo, out var def))
        {
            def = Str(await GetAsync(R(repo), ct), "default_branch");
            if (def.Length > 0) _defaultBranch[repo] = def;
        }
        if (string.Equals(def, branch, StringComparison.Ordinal))
            throw new ForbiddenConnectorOperationException($"github: refusing to {action} the default branch '{branch}' of {repo}");
    }

    static PullRequestState State(JsonNode? j) =>
        j?["merged_at"] is JsonValue v && v.TryGetValue<string>(out var m) && m.Length > 0 || j?["merged"] is JsonValue mv && mv.TryGetValue<bool>(out var b) && b
            ? PullRequestState.Merged
            : Str(j, "state") == "open" ? PullRequestState.Open : PullRequestState.Closed;

    static PullRequestSummary Summary(JsonNode? j) =>
        new(Int(j, "number"), Str(j, "html_url"), State(j), Str(j, "title"), Str(j?["base"], "ref"), Str(j?["head"], "ref"));

    static string Short(string s) => s.Length > 12 ? s[..12] : s;
    static string FirstLine(string s) => s.Trim().Split('\n').FirstOrDefault()?.Trim() ?? "";
}
