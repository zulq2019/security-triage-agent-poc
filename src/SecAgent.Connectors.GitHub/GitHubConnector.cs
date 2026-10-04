using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.GitHub;

/// <summary>Plug-in for GitHub (provider id "github"). Setup: BaseUrl (default https://api.github.com/; GHES: https://host/api/v3/),
/// Secret = reference to a token (installation token / fine-grained token; "kv:..." in Azure, "env:GITHUB_TOKEN" or "gh-cli:token" locally),
/// optional Settings:CloneBaseUrl (default https://github.com/).</summary>
public sealed class GitHubConnector(IHttpClientFactory httpFactory, ISecretProvider secrets, IGitCommandRunner git, TimeProvider time)
    : IConnectorClientProvider<ISourceControlClient>
{
    public const string Id = "github";

    public static readonly ConnectorDescriptor Descriptor = new(
        Id, "GitHub", ConnectorKind.SourceControl, "source_control", ConnectorTransport.Http,
        [ConnectorCapabilities.PullRequestRead, ConnectorCapabilities.PullRequestFilesRead, ConnectorCapabilities.PullRequestCreate, ConnectorCapabilities.PullRequestComment,
         ConnectorCapabilities.BranchCreate, ConnectorCapabilities.BranchPublish, ConnectorCapabilities.CommitCreate, ConnectorCapabilities.CheckRunRead],
        [
            new("Contents", "read and write", "Read code; push fix branches. Never the default branch, never a force push."),
            new("Pull requests", "read and write", "Read the scanned PR; open fix PRs and comment on them."),
            new("Checks", "read", "Read check runs of the PR head."),
            new("Metadata", "read", "Required by GitHub for every App."),
        ],
        ["merge", "approve", "admin", "branch_protection", "workflows_write", "push_default_branch", "force_push"],
        [
            new("BaseUrl", "API base URL", false, Example: "https://api.github.com/"),
            new("Secret", "Token reference (GitHub App installation token or fine-grained token)", true, true, "kv:github-token"),
            new("CloneBaseUrl", "Clone base URL", false, Example: "https://github.com/"),
        ],
        SelectionKind.Repositories,
        Notes: "Merging is a human action on GitHub; the connector has no merge method and refuses merge endpoints.");

    public ConnectorDescriptor Describe() => Descriptor;

    public ISourceControlClient CreateClient(ConnectionSettings connection) =>
        new GitHubSourceControlClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), WithDefaults(connection), secrets, git);

    public async Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct)
    {
        try
        {
            var client = new GitHubSourceControlClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), WithDefaults(connection), secrets, git);
            var remaining = await client.RateLimitRemainingAsync(ct);
            return HealthResult.Healthy($"authenticated; {remaining} core requests left this hour", time.GetUtcNow());
        }
        catch (Exception e) when (e is ConnectorException or HttpRequestException)
        {
            return HealthResult.Failing(e.Message, time.GetUtcNow());
        }
    }

    static ConnectionSettings WithDefaults(ConnectionSettings c) => c.BaseUrl is { Length: > 0 } ? c : c with { BaseUrl = "https://api.github.com/" };
}
