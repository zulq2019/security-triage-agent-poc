namespace SecAgent.Connectors;

// Source control (GitHub today). Small segregated interfaces: a consumer asks for exactly what it uses.
// There is deliberately NO merge, approve, review-approve or branch-protection method on any of them (FR-17): merging is a human
// action on GitHub. Tests enforce this by reflection over every connector assembly.

public enum PullRequestState { Open, Closed, Merged }

/// <param name="HeadRepo">Repository the head branch lives in; differs from <paramref name="Repo"/> for PRs from forks.</param>
public sealed record PullRequestInfo(string Repo, int Number, string Title, string HeadRef, string BaseRef, string HeadSha, string BaseSha,
    int FilesChanged, int Additions, int Deletions, string Url, PullRequestState State, string? HeadRepo);

public sealed record PullRequestSummary(int Number, string Url, PullRequestState State, string Title, string BaseRef, string HeadRef);

public sealed record ChangedFile(string Path, string Status, int Additions, int Deletions, string? PreviousPath = null);

public sealed record NewPullRequest(string BaseRef, string HeadRef, string Title, string Body, bool Draft = false);

/// <param name="Content">New UTF-8 content; null deletes the file.</param>
public sealed record FileChange(string Path, string? Content);

/// <param name="ExpectedHeadSha">Optimistic concurrency: fail instead of committing on top of an unexpected head.</param>
public sealed record CommitRequest(string Branch, string Message, IReadOnlyList<FileChange> Changes, string? ExpectedHeadSha = null);

public sealed record CommitResult(string Branch, string Sha);

public sealed record CommentRef(long Id, string Url);

public sealed record CheckRunInfo(string Name, string Status, string? Conclusion, string? DetailsUrl);

/// <summary>A fix branch built in a local worktree, to be published (plain push, never forced) under <paramref name="RemoteBranch"/>.</summary>
public sealed record BranchPublishRequest(string Repo, string WorktreePath, string RemoteBranch);

public sealed record BranchPublishResult(string Repo, string RemoteBranch, string? Sha);

public interface IPullRequestReader
{
    /// <summary>Null when the PR does not exist (or is not visible to the connection).</summary>
    Task<PullRequestInfo?> GetPullRequestAsync(string repo, int number, CancellationToken ct);
    Task<IReadOnlyList<ChangedFile>> ListChangedFilesAsync(string repo, int number, CancellationToken ct);
    /// <summary>PR whose head is <paramref name="headRef"/> in this repo, any state; an open one is preferred. Null when none.</summary>
    Task<PullRequestSummary?> FindPullRequestByHeadAsync(string repo, string headRef, CancellationToken ct);
}

public interface IPullRequestWriter
{
    Task<PullRequestSummary> CreatePullRequestAsync(string repo, NewPullRequest request, CancellationToken ct);
}

public interface IPullRequestCommenter
{
    Task<CommentRef> AddCommentAsync(string repo, int number, string body, CancellationToken ct);
}

public interface IBranchWriter
{
    Task<bool> BranchExistsAsync(string repo, string branch, CancellationToken ct);
    /// <summary>Creates a new branch at <paramref name="fromSha"/>. Never moves an existing branch and never targets the default branch.</summary>
    Task CreateBranchAsync(string repo, string branch, string fromSha, CancellationToken ct);
}

public interface ICommitWriter
{
    /// <summary>Commits file changes on top of the branch head through the API (fast-forward only; never the default branch).</summary>
    Task<CommitResult> CommitAsync(string repo, CommitRequest request, CancellationToken ct);
}

public interface ICheckRunReader
{
    Task<IReadOnlyList<CheckRunInfo>> ListCheckRunsAsync(string repo, string sha, CancellationToken ct);
}

/// <summary>Publishes a branch that was committed in a local worktree (the pipeline's fixers work on a local clone).</summary>
public interface IBranchPublisher
{
    Task<BranchPublishResult> PublishBranchAsync(BranchPublishRequest request, CancellationToken ct);
}

/// <summary>Where the pipeline clones a repository from (github.com, GitHub Enterprise Server, or a local bare repo for the fake).</summary>
public interface IRepositoryLocator
{
    string CloneUrl(string repo);
}

/// <summary>Everything a source control connector offers. Consumers should depend on the narrow interfaces above.</summary>
public interface ISourceControlClient : IPullRequestReader, IPullRequestWriter, IPullRequestCommenter, IBranchWriter, ICommitWriter,
    ICheckRunReader, IBranchPublisher, IRepositoryLocator;
