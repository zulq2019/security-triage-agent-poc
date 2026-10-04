namespace SecAgent.Connectors;

// Issue tracker (Jira today): human tasks become tickets. No delete and no admin operation exists.

/// <param name="ProjectKey">Project to file in; empty = the connection's default project (setting "ProjectKey"), so callers need no tracker config.</param>
/// <param name="ExternalId">Stable id from SecAgent (e.g. the human task id). Lets create be idempotent: a retry finds the existing issue.</param>
public sealed record NewIssue(string ProjectKey, string Summary, string Description, string IssueType = "Task",
    IReadOnlyList<string>? Labels = null, string? Priority = null, string? ExternalId = null);

/// <summary>Only the non-null members are changed.</summary>
public sealed record IssueUpdate(string? Summary = null, string? Description = null, IReadOnlyList<string>? AddLabels = null, string? Priority = null);

public sealed record IssueRef(string Key, string Url);

public sealed record IssueInfo(string Key, string Url, string Summary, string Status, IReadOnlyList<string> Labels);

public sealed record IssueLink(string Url, string Title);

public interface IIssueReader
{
    Task<IssueInfo?> GetIssueAsync(string key, CancellationToken ct);
    /// <param name="projectKey">Empty = the connection's default project.</param>
    Task<IssueRef?> FindByExternalIdAsync(string projectKey, string externalId, CancellationToken ct);
}

public interface IIssueWriter
{
    /// <summary>Creates the issue, or returns the existing one with the same <see cref="NewIssue.ExternalId"/> (check before act).</summary>
    Task<IssueRef> CreateIssueAsync(NewIssue issue, CancellationToken ct);
    Task UpdateIssueAsync(string key, IssueUpdate update, CancellationToken ct);
}

public interface IIssueTransitioner
{
    /// <summary>Moves the issue to the named status using one of its available transitions. No-op when already there.</summary>
    Task<IssueInfo> TransitionAsync(string key, string toStatus, CancellationToken ct);
}

public interface IIssueLinker
{
    /// <summary>Links a pull request to the issue. Idempotent per URL.</summary>
    Task LinkPullRequestAsync(string key, IssueLink link, CancellationToken ct);
}

public interface IIssueCommenter
{
    Task<string> AddCommentAsync(string key, string body, CancellationToken ct);
}

public interface IIssueTrackerClient : IIssueReader, IIssueWriter, IIssueTransitioner, IIssueLinker, IIssueCommenter;
