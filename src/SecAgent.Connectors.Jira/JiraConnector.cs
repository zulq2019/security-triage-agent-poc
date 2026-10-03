using Microsoft.Extensions.DependencyInjection;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.Jira;

/// <summary>Plug-in for Jira (provider id "jira"). Setup: BaseUrl (https://your-site.atlassian.net), Secret (API token or PAT reference),
/// Settings: AuthMode = basic (Cloud: Email + API token) | bearer (Data Center personal access token), Email (basic only),
/// ApiVersion = 3 (Cloud, rich text as ADF) | 2 (Data Center, plain text), ProjectKey (default project for human tasks).</summary>
public sealed class JiraConnector(IHttpClientFactory httpFactory, ISecretProvider secrets, TimeProvider time) : IConnectorClientProvider<IIssueTrackerClient>
{
    public const string Id = "jira";

    public static readonly ConnectorDescriptor Descriptor = new(
        Id, "Jira", ConnectorKind.IssueTracker, "human_tasks", ConnectorTransport.Http,
        [ConnectorCapabilities.IssueRead, ConnectorCapabilities.IssueCreate, ConnectorCapabilities.IssueUpdate, ConnectorCapabilities.IssueTransition,
         ConnectorCapabilities.IssueLinkPullRequest, ConnectorCapabilities.IssueComment],
        [
            new("Issues", "create and comment", "Turn human tasks into tickets; add the evidence and fix PR links."),
            new("Issues", "read status", "Follow a ticket's status (transition when a fix PR is opened)."),
            new("Projects", "read", "Pick the project for each repository."),
        ],
        ["delete", "admin", "project_admin", "workflow_edit"],
        [
            new("BaseUrl", "Jira site URL", true, Example: "https://your-site.atlassian.net"),
            new("Secret", "API token / PAT reference", true, true, "kv:jira-api-token"),
            new("AuthMode", "basic (Cloud) or bearer (Data Center)", false, Example: "basic"),
            new("Email", "Account email (basic auth)", false, Example: "secagent-bot@example.invalid"),
            new("ApiVersion", "3 (Cloud) or 2 (Data Center)", false, Example: "3"),
            new("ProjectKey", "Default project key", false, Example: "SEC"),
        ],
        SelectionKind.Projects,
        Notes: "ASSUMPTION: built from the public Jira REST v3 docs; not yet verified against a live site.");

    public ConnectorDescriptor Describe() => Descriptor;

    public IIssueTrackerClient CreateClient(ConnectionSettings connection) =>
        new JiraIssueTrackerClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), connection, secrets);

    public async Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct)
    {
        try
        {
            var who = await new JiraIssueTrackerClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), connection, secrets).WhoAmIAsync(ct);
            return HealthResult.Healthy($"authenticated as {who}", time.GetUtcNow());
        }
        catch (ConnectorException e) { return HealthResult.Failing(e.Message, time.GetUtcNow()); }
    }
}

public static class JiraConnectorRegistration
{
    public static ConnectorsBuilder AddJiraConnector(this ConnectorsBuilder builder)
    {
        builder.Services.AddConnectorHttpClient(JiraConnector.Id);
        return builder.AddConnector<JiraConnector, IIssueTrackerClient>();
    }
}
