using SecAgent.Connectors.Calls;

namespace SecAgent.Connectors.Decorators;

/// <summary>Wraps a plug-in's client so every operation runs through the connection's interceptor chain (auditing, resilience).
/// One forwarding class per client contract; plug-ins stay free of cross-cutting code (Decorator pattern).</summary>
public interface IConnectorClientDecorator<TClient> where TClient : class
{
    TClient Decorate(TClient inner, ConnectorInvoker invoker);
}

public sealed class SourceControlClientDecorator : IConnectorClientDecorator<ISourceControlClient>
{
    public ISourceControlClient Decorate(ISourceControlClient inner, ConnectorInvoker invoker) => new Decorated(inner, invoker);

    sealed class Decorated(ISourceControlClient inner, ConnectorInvoker i) : ISourceControlClient
    {
        public Task<PullRequestInfo?> GetPullRequestAsync(string repo, int number, CancellationToken ct) =>
            i.InvokeAsync(new("pull_request.get", $"{repo}#{number}", true), c => inner.GetPullRequestAsync(repo, number, c), ct);
        public Task<IReadOnlyList<ChangedFile>> ListChangedFilesAsync(string repo, int number, CancellationToken ct) =>
            i.InvokeAsync(new("pull_request.files", $"{repo}#{number}", true), c => inner.ListChangedFilesAsync(repo, number, c), ct);
        public Task<PullRequestSummary?> FindPullRequestByHeadAsync(string repo, string headRef, CancellationToken ct) =>
            i.InvokeAsync(new("pull_request.find_by_head", $"{repo}:{headRef}", true), c => inner.FindPullRequestByHeadAsync(repo, headRef, c), ct);
        public Task<PullRequestSummary> CreatePullRequestAsync(string repo, NewPullRequest request, CancellationToken ct) =>
            i.InvokeAsync(new("pull_request.create", $"{repo}:{request.HeadRef}->{request.BaseRef}", false), c => inner.CreatePullRequestAsync(repo, request, c), ct);
        public Task<CommentRef> AddCommentAsync(string repo, int number, string body, CancellationToken ct) =>
            i.InvokeAsync(new("pull_request.comment", $"{repo}#{number}", false), c => inner.AddCommentAsync(repo, number, body, c), ct);
        public Task<bool> BranchExistsAsync(string repo, string branch, CancellationToken ct) =>
            i.InvokeAsync(new("branch.exists", $"{repo}:{branch}", true), c => inner.BranchExistsAsync(repo, branch, c), ct);
        public Task CreateBranchAsync(string repo, string branch, string fromSha, CancellationToken ct) =>
            i.InvokeAsync(new("branch.create", $"{repo}:{branch}", false), c => inner.CreateBranchAsync(repo, branch, fromSha, c), ct);
        public Task<CommitResult> CommitAsync(string repo, CommitRequest request, CancellationToken ct) =>
            i.InvokeAsync(new("commit.create", $"{repo}:{request.Branch}", false), c => inner.CommitAsync(repo, request, c), ct);
        public Task<IReadOnlyList<CheckRunInfo>> ListCheckRunsAsync(string repo, string sha, CancellationToken ct) =>
            i.InvokeAsync(new("check_run.list", $"{repo}@{(sha.Length > 12 ? sha[..12] : sha)}", true), c => inner.ListCheckRunsAsync(repo, sha, c), ct);
        public Task<BranchPublishResult> PublishBranchAsync(BranchPublishRequest request, CancellationToken ct) =>
            i.InvokeAsync(new("branch.publish", $"{request.Repo}:{request.RemoteBranch}", false), c => inner.PublishBranchAsync(request, c), ct);
        public string CloneUrl(string repo) => inner.CloneUrl(repo);
    }
}

public sealed class IssueTrackerClientDecorator : IConnectorClientDecorator<IIssueTrackerClient>
{
    public IIssueTrackerClient Decorate(IIssueTrackerClient inner, ConnectorInvoker invoker) => new Decorated(inner, invoker);

    sealed class Decorated(IIssueTrackerClient inner, ConnectorInvoker i) : IIssueTrackerClient
    {
        public Task<IssueInfo?> GetIssueAsync(string key, CancellationToken ct) =>
            i.InvokeAsync(new("issue.get", key, true), c => inner.GetIssueAsync(key, c), ct);
        public Task<IssueRef?> FindByExternalIdAsync(string projectKey, string externalId, CancellationToken ct) =>
            i.InvokeAsync(new("issue.find_by_external_id", $"{projectKey}:{externalId}", true), c => inner.FindByExternalIdAsync(projectKey, externalId, c), ct);
        // Create is check-before-act (ExternalId), so it is safe to retry when an ExternalId is given.
        public Task<IssueRef> CreateIssueAsync(NewIssue issue, CancellationToken ct) =>
            i.InvokeAsync(new("issue.create", issue.ProjectKey, issue.ExternalId != null), c => inner.CreateIssueAsync(issue, c), ct);
        public Task UpdateIssueAsync(string key, IssueUpdate update, CancellationToken ct) =>
            i.InvokeAsync(new("issue.update", key, true), c => inner.UpdateIssueAsync(key, update, c), ct);
        public Task<IssueInfo> TransitionAsync(string key, string toStatus, CancellationToken ct) =>
            i.InvokeAsync(new("issue.transition", $"{key}->{toStatus}", true), c => inner.TransitionAsync(key, toStatus, c), ct);
        public Task LinkPullRequestAsync(string key, IssueLink link, CancellationToken ct) =>
            i.InvokeAsync(new("issue.link_pull_request", key, true), c => inner.LinkPullRequestAsync(key, link, c), ct);
        public Task<string> AddCommentAsync(string key, string body, CancellationToken ct) =>
            i.InvokeAsync(new("issue.comment", key, false), c => inner.AddCommentAsync(key, body, c), ct);
    }
}

public sealed class ScannerSourceClientDecorator : IConnectorClientDecorator<IScannerSourceClient>
{
    public IScannerSourceClient Decorate(IScannerSourceClient inner, ConnectorInvoker invoker) => new Decorated(inner, invoker);

    sealed class Decorated(IScannerSourceClient inner, ConnectorInvoker i) : IScannerSourceClient
    {
        public Task<ScannerProjectVersion?> FindProjectVersionAsync(string projectName, string versionName, CancellationToken ct) =>
            i.InvokeAsync(new("project_version.find", $"{projectName}@{versionName}", true), c => inner.FindProjectVersionAsync(projectName, versionName, c), ct);
        public Task<IReadOnlyList<ScannerVulnerability>> ListVulnerabilitiesAsync(ScannerProjectVersion version, CancellationToken ct) =>
            i.InvokeAsync(new("vulnerability.list", $"{version.ProjectName}@{version.VersionName}", true), c => inner.ListVulnerabilitiesAsync(version, c), ct);
        public Task<RemediationGuidance?> GetRemediationGuidanceAsync(ComponentVersionRef component, CancellationToken ct) =>
            i.InvokeAsync(new("remediation.get", $"{component.ComponentName ?? component.ComponentId}@{component.Version ?? component.ComponentVersionId}", true),
                c => inner.GetRemediationGuidanceAsync(component, c), ct);
    }
}

public sealed class ModelProviderClientDecorator : IConnectorClientDecorator<IModelProviderClient>
{
    public IModelProviderClient Decorate(IModelProviderClient inner, ConnectorInvoker invoker) => new Decorated(inner, invoker);

    sealed class Decorated(IModelProviderClient inner, ConnectorInvoker i) : IModelProviderClient
    {
        public string ProviderFamily => inner.ProviderFamily;
        // Not retried here: a completion costs tokens, and the gateway owns failover across deployments.
        public Task<ModelResponse> CompleteAsync(ModelRequest request, CancellationToken ct) =>
            i.InvokeAsync(new("model.complete", request.Model, false), c => inner.CompleteAsync(request, c), ct);
        public Task<IReadOnlyCollection<string>?> ListAvailableModelsAsync(CancellationToken ct) =>
            i.InvokeAsync(new("model.catalog", null, true), c => inner.ListAvailableModelsAsync(c), ct);
    }
}

public sealed class NotifierClientDecorator : IConnectorClientDecorator<INotifierClient>
{
    public INotifierClient Decorate(INotifierClient inner, ConnectorInvoker invoker) => new Decorated(inner, invoker);

    sealed class Decorated(INotifierClient inner, ConnectorInvoker i) : INotifierClient
    {
        public Task NotifyAsync(Notification notification, CancellationToken ct) =>
            i.InvokeAsync(new("notification.send", notification.Level.ToString().ToLowerInvariant(), false), c => inner.NotifyAsync(notification, c), ct);
    }
}
