namespace SecAgent.Connectors.Fakes;

public sealed class FakePullRequest
{
    public required int Number { get; init; }
    public required string Title { get; set; }
    public required string HeadRef { get; init; }
    public required string BaseRef { get; init; }
    public string HeadSha { get; set; } = "";
    public string BaseSha { get; set; } = "";
    public string Body { get; set; } = "";
    public PullRequestState State { get; set; } = PullRequestState.Open;
    public string? HeadRepo { get; set; }
    public bool Draft { get; set; }
    public List<ChangedFile> Files { get; } = [];
    public required string Url { get; init; }
}

public sealed record FakeCommit(string Sha, string Branch, string Message, IReadOnlyList<FileChange> Changes, string Parent);
public sealed record FakeComment(long Id, int PullRequest, string Body, string Url);

public sealed class FakeRepository(string name, string defaultBranch)
{
    public string Name { get; } = name;
    public string DefaultBranch { get; set; } = defaultBranch;
    /// <summary>Where the pipeline clones from (a local bare repository in end-to-end tests).</summary>
    public string? CloneUrl { get; set; }
    public Dictionary<string, string> Branches { get; } = new(StringComparer.Ordinal);
    public List<FakePullRequest> PullRequests { get; } = [];
    public List<FakeComment> Comments { get; } = [];
    public List<FakeCommit> Commits { get; } = [];
    public List<BranchPublishResult> Pushes { get; } = [];
    public Dictionary<string, List<CheckRunInfo>> CheckRuns { get; } = new(StringComparer.OrdinalIgnoreCase);

    public FakePullRequest AddPullRequest(int number, string title, string headRef, string baseRef, string headSha, string baseSha, string? headRepo = null, params ChangedFile[] files)
    {
        var pr = new FakePullRequest { Number = number, Title = title, HeadRef = headRef, BaseRef = baseRef, HeadSha = headSha, BaseSha = baseSha, HeadRepo = headRepo ?? Name, Url = FakeSourceControlState.PrUrl(Name, number) };
        pr.Files.AddRange(files);
        PullRequests.Add(pr);
        Branches.TryAdd(baseRef, baseSha);
        if (headRepo == null || headRepo.Equals(Name, StringComparison.OrdinalIgnoreCase)) Branches.TryAdd(headRef, headSha);
        return pr;
    }
}

/// <summary>Per-tenant in-memory GitHub. Tenants never see each other's repositories.</summary>
public sealed class FakeSourceControlState
{
    internal readonly object Lock = new();
    readonly Dictionary<string, Dictionary<string, FakeRepository>> _tenants = new(StringComparer.OrdinalIgnoreCase);

    public static string PrUrl(string repo, int number) => $"https://scm.fake.invalid/{repo}/pull/{number}";

    public FakeRepository AddRepository(string tenantId, string repo, string defaultBranch = "main")
    {
        lock (Lock)
        {
            if (!_tenants.TryGetValue(tenantId, out var repos)) _tenants[tenantId] = repos = new(StringComparer.OrdinalIgnoreCase);
            if (!repos.TryGetValue(repo, out var r)) repos[repo] = r = new FakeRepository(repo, defaultBranch);
            return r;
        }
    }

    public FakeRepository? Find(string tenantId, string repo)
    {
        lock (Lock) return _tenants.TryGetValue(tenantId, out var repos) ? repos.GetValueOrDefault(repo) : null;
    }
}

public sealed class FakeSourceControlClient(FakeConnectorWorld world, string tenant) : ISourceControlClient
{
    FakeSourceControlState S => world.SourceControl;
    FakeRepository Repo(string repo) => S.Find(tenant, repo) ?? throw new ConnectorException($"fake: repository {repo} not found for tenant {tenant}", false, System.Net.HttpStatusCode.NotFound);

    static PullRequestSummary Summary(FakePullRequest p) => new(p.Number, p.Url, p.State, p.Title, p.BaseRef, p.HeadRef);

    public Task<PullRequestInfo?> GetPullRequestAsync(string repo, int number, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "pull_request.get", ("repo", repo), ("number", number));
        lock (S.Lock)
        {
            var r = S.Find(tenant, repo);
            var p = r?.PullRequests.FirstOrDefault(x => x.Number == number);
            return Task.FromResult(p == null ? null : new PullRequestInfo(repo, p.Number, p.Title, p.HeadRef, p.BaseRef, p.HeadSha, p.BaseSha, p.Files.Count,
                p.Files.Sum(f => f.Additions), p.Files.Sum(f => f.Deletions), p.Url, p.State, p.HeadRepo));
        }
    }

    public Task<IReadOnlyList<ChangedFile>> ListChangedFilesAsync(string repo, int number, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "pull_request.files", ("repo", repo), ("number", number));
        lock (S.Lock)
            return Task.FromResult<IReadOnlyList<ChangedFile>>(Repo(repo).PullRequests.FirstOrDefault(x => x.Number == number)?.Files.ToList()
                ?? throw new ConnectorException($"fake: PR {repo}#{number} not found", false, System.Net.HttpStatusCode.NotFound));
    }

    public Task<PullRequestSummary?> FindPullRequestByHeadAsync(string repo, string headRef, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "pull_request.find_by_head", ("repo", repo), ("head", headRef));
        lock (S.Lock)
        {
            var all = S.Find(tenant, repo)?.PullRequests.Where(p => p.HeadRef == headRef).ToList() ?? [];
            var p = all.FirstOrDefault(x => x.State == PullRequestState.Open) ?? all.FirstOrDefault();
            return Task.FromResult(p == null ? null : Summary(p));
        }
    }

    public Task<PullRequestSummary> CreatePullRequestAsync(string repo, NewPullRequest request, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "pull_request.create", ("repo", repo), ("base", request.BaseRef), ("head", request.HeadRef), ("title", request.Title));
        lock (S.Lock)
        {
            var r = Repo(repo);
            if (request.HeadRef == r.DefaultBranch) throw new ForbiddenConnectorOperationException($"fake: refusing to open a PR from the default branch '{request.HeadRef}'");
            if (!r.Branches.ContainsKey(request.HeadRef)) throw new ConnectorException($"fake: head branch '{request.HeadRef}' does not exist in {repo}", false, System.Net.HttpStatusCode.UnprocessableEntity);
            if (r.PullRequests.Any(p => p.HeadRef == request.HeadRef && p.BaseRef == request.BaseRef && p.State == PullRequestState.Open))
                throw new ConnectorException($"fake: a pull request already exists for {request.HeadRef} → {request.BaseRef}", false, System.Net.HttpStatusCode.UnprocessableEntity);
            var n = r.PullRequests.Count == 0 ? 1 : r.PullRequests.Max(p => p.Number) + 1;
            var pr = new FakePullRequest
            {
                Number = n, Title = request.Title, HeadRef = request.HeadRef, BaseRef = request.BaseRef, Body = request.Body, Draft = request.Draft,
                HeadSha = r.Branches[request.HeadRef], BaseSha = r.Branches.GetValueOrDefault(request.BaseRef, ""), HeadRepo = repo, Url = FakeSourceControlState.PrUrl(repo, n),
            };
            r.PullRequests.Add(pr);
            return Task.FromResult(Summary(pr));
        }
    }

    public Task<CommentRef> AddCommentAsync(string repo, int number, string body, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "pull_request.comment", ("repo", repo), ("number", number));
        lock (S.Lock)
        {
            var r = Repo(repo);
            if (r.PullRequests.All(p => p.Number != number)) throw new ConnectorException($"fake: PR {repo}#{number} not found", false, System.Net.HttpStatusCode.NotFound);
            var id = r.Comments.Count + 1L;
            var c = new FakeComment(id, number, body, $"{FakeSourceControlState.PrUrl(repo, number)}#issuecomment-{id}");
            r.Comments.Add(c);
            return Task.FromResult(new CommentRef(c.Id, c.Url));
        }
    }

    public Task<bool> BranchExistsAsync(string repo, string branch, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "branch.exists", ("repo", repo), ("branch", branch));
        lock (S.Lock) return Task.FromResult(S.Find(tenant, repo)?.Branches.ContainsKey(branch) == true);
    }

    public Task CreateBranchAsync(string repo, string branch, string fromSha, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "branch.create", ("repo", repo), ("branch", branch), ("from", fromSha));
        lock (S.Lock)
        {
            var r = Repo(repo);
            if (branch == r.DefaultBranch) throw new ForbiddenConnectorOperationException($"fake: refusing to create the default branch '{branch}'");
            if (!r.Branches.TryAdd(branch, fromSha)) throw new ConnectorException($"fake: branch '{branch}' already exists", false, System.Net.HttpStatusCode.UnprocessableEntity);
        }
        return Task.CompletedTask;
    }

    public Task<CommitResult> CommitAsync(string repo, CommitRequest request, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "commit.create", ("repo", repo), ("branch", request.Branch), ("files", request.Changes.Count));
        lock (S.Lock)
        {
            var r = Repo(repo);
            if (request.Branch == r.DefaultBranch) throw new ForbiddenConnectorOperationException($"fake: refusing to commit to the default branch '{request.Branch}'");
            if (!r.Branches.TryGetValue(request.Branch, out var parent)) throw new ConnectorException($"fake: branch '{request.Branch}' does not exist in {repo}");
            if (request.ExpectedHeadSha is { } e && e != parent) throw new ConnectorException($"fake: branch '{request.Branch}' moved; not committing");
            var sha = FakeConnectorWorld.Sha(repo, request.Branch, parent, request.Message, string.Join(",", request.Changes.Select(c => c.Path + "=" + (c.Content ?? "<deleted>"))));
            r.Commits.Add(new FakeCommit(sha, request.Branch, request.Message, request.Changes.ToList(), parent));
            r.Branches[request.Branch] = sha;
            return Task.FromResult(new CommitResult(request.Branch, sha));
        }
    }

    public Task<IReadOnlyList<CheckRunInfo>> ListCheckRunsAsync(string repo, string sha, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "check_run.list", ("repo", repo), ("sha", sha));
        lock (S.Lock) return Task.FromResult<IReadOnlyList<CheckRunInfo>>(S.Find(tenant, repo)?.CheckRuns.GetValueOrDefault(sha)?.ToList() ?? []);
    }

    public Task<BranchPublishResult> PublishBranchAsync(BranchPublishRequest request, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.SourceControl, "branch.publish", ("repo", request.Repo), ("branch", request.RemoteBranch), ("worktree", Path.GetFileName(request.WorktreePath)));
        lock (S.Lock)
        {
            var r = Repo(request.Repo);
            if (request.RemoteBranch == r.DefaultBranch) throw new ForbiddenConnectorOperationException($"fake: refusing to push to the default branch '{request.RemoteBranch}'");
            if (r.Branches.ContainsKey(request.RemoteBranch)) throw new ConnectorException($"fake: remote branch '{request.RemoteBranch}' exists; a plain push would be rejected (no force push)");
            var sha = FakeConnectorWorld.Sha("push", request.Repo, request.RemoteBranch, request.WorktreePath);
            r.Branches[request.RemoteBranch] = sha;
            var result = new BranchPublishResult(request.Repo, request.RemoteBranch, sha);
            r.Pushes.Add(result);
            return Task.FromResult(result);
        }
    }

    public string CloneUrl(string repo) => S.Find(tenant, repo)?.CloneUrl ?? $"https://scm.fake.invalid/{repo}.git";
}
