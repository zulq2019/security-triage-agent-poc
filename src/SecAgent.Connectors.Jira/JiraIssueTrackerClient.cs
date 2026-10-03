using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.Jira;

/// <summary>Jira REST client. Endpoints (Atlassian public docs):
/// POST /rest/api/{v}/issue · PUT /rest/api/{v}/issue/{key} · GET /rest/api/{v}/issue/{key} · GET+POST /rest/api/{v}/issue/{key}/transitions ·
/// POST /rest/api/{v}/issue/{key}/remotelink (upsert by globalId) · POST /rest/api/{v}/issue/{key}/comment · GET /rest/api/{v}/myself ·
/// search: GET /rest/api/3/search/jql (Cloud) or /rest/api/2/search (Data Center).
/// ASSUMPTION (unverified against a live site): ADF bodies for v3, the label used for idempotent create, and the Cloud search endpoint.</summary>
public sealed class JiraIssueTrackerClient(HttpClient http, ConnectionSettings connection, ISecretProvider secrets)
    : ConnectorRestClient(http, connection, JiraConnector.Id), IIssueTrackerClient
{
    string V => Connection.Get("ApiVersion") ?? "3";
    bool Adf => V == "3";
    string Api => $"rest/api/{V}";

    protected override async ValueTask AuthorizeAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var secret = await secrets.GetSecretAsync(Connection.RequireSecret(), ct);
        if ((Connection.Get("AuthMode") ?? "basic").Equals("bearer", StringComparison.OrdinalIgnoreCase)) Bearer(request, secret);
        else request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Connection.Require("Email")}:{secret}")));
        request.Headers.Accept.ParseAdd("application/json");
    }

    /// <summary>Label that carries SecAgent's external id, so create can check before it acts (ASSUMPTION: labels allowed in the project).</summary>
    public static string ExternalIdLabel(string externalId) => "secagent-" + new string(externalId.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray()).ToLowerInvariant();

    string Project(string? key) => string.IsNullOrWhiteSpace(key) ? Connection.Require("ProjectKey") : key;
    string Browse(string key) => Connection.RequireBaseUrl().ToString().TrimEnd('/') + "/browse/" + key;
    static string K(string key) => Uri.EscapeDataString(key);

    public async Task<IssueInfo?> GetIssueAsync(string key, CancellationToken ct)
    {
        var j = await GetAsync($"{Api}/issue/{K(key)}?fields=summary,status,labels", ct, notFoundIsNull: true);
        if (j == null) return null;
        var f = j["fields"];
        return new IssueInfo(Str(j, "key"), Browse(Str(j, "key")), Str(f, "summary"), Str(f?["status"], "name"),
            (f?["labels"]?.AsArray() ?? []).Select(l => l!.GetValue<string>()).ToList());
    }

    public async Task<IssueRef?> FindByExternalIdAsync(string projectKey, string externalId, CancellationToken ct)
    {
        var jql = Uri.EscapeDataString($"project = \"{Project(projectKey)}\" AND labels = \"{ExternalIdLabel(externalId)}\" ORDER BY created ASC");
        var path = V == "3" ? $"{Api}/search/jql?jql={jql}&fields=summary&maxResults=1" : $"{Api}/search?jql={jql}&fields=summary&maxResults=1";
        var first = (await GetAsync(path, ct))?["issues"]?.AsArray().FirstOrDefault();
        return first == null ? null : new IssueRef(Str(first, "key"), Browse(Str(first, "key")));
    }

    public async Task<IssueRef> CreateIssueAsync(NewIssue issue, CancellationToken ct)
    {
        if (issue.ExternalId != null && await FindByExternalIdAsync(issue.ProjectKey, issue.ExternalId, ct) is { } existing) return existing;
        var labels = new JsonArray();
        foreach (var l in (issue.Labels ?? []).Concat(issue.ExternalId != null ? [ExternalIdLabel(issue.ExternalId)] : []).Distinct()) labels.Add(l);
        var fields = new JsonObject
        {
            ["project"] = new JsonObject { ["key"] = Project(issue.ProjectKey) },
            ["summary"] = Trim(issue.Summary, 250),
            ["description"] = Text(issue.Description),
            ["issuetype"] = new JsonObject { ["name"] = issue.IssueType },
            ["labels"] = labels,
        };
        if (issue.Priority != null) fields["priority"] = new JsonObject { ["name"] = issue.Priority };
        var j = await SendAsync(HttpMethod.Post, $"{Api}/issue", new JsonObject { ["fields"] = fields }, ct);
        return new IssueRef(Str(j, "key"), Browse(Str(j, "key")));
    }

    public async Task UpdateIssueAsync(string key, IssueUpdate update, CancellationToken ct)
    {
        var fields = new JsonObject();
        if (update.Summary != null) fields["summary"] = Trim(update.Summary, 250);
        if (update.Description != null) fields["description"] = Text(update.Description);
        if (update.Priority != null) fields["priority"] = new JsonObject { ["name"] = update.Priority };
        var body = new JsonObject { ["fields"] = fields };
        if (update.AddLabels is { Count: > 0 } add)
        {
            var ops = new JsonArray();
            foreach (var l in add) ops.Add(new JsonObject { ["add"] = l });
            body["update"] = new JsonObject { ["labels"] = ops };
        }
        await SendAsync(HttpMethod.Put, $"{Api}/issue/{K(key)}", body, ct);
    }

    public async Task<IssueInfo> TransitionAsync(string key, string toStatus, CancellationToken ct)
    {
        var current = await GetIssueAsync(key, ct) ?? throw new ConnectorException($"jira: issue {key} not found");
        if (current.Status.Equals(toStatus, StringComparison.OrdinalIgnoreCase)) return current;
        var transitions = (await GetAsync($"{Api}/issue/{K(key)}/transitions", ct))?["transitions"]?.AsArray() ?? [];
        var t = transitions.FirstOrDefault(x => Str(x?["to"], "name").Equals(toStatus, StringComparison.OrdinalIgnoreCase))
                ?? transitions.FirstOrDefault(x => Str(x, "name").Equals(toStatus, StringComparison.OrdinalIgnoreCase))
                ?? throw new ConnectorException($"jira: no transition from '{current.Status}' to '{toStatus}' for {key} (available: {string.Join(", ", transitions.Select(x => Str(x?["to"], "name")))})");
        await SendAsync(HttpMethod.Post, $"{Api}/issue/{K(key)}/transitions", new JsonObject { ["transition"] = new JsonObject { ["id"] = Str(t, "id") } }, ct);
        return current with { Status = Str(t?["to"], "name") };
    }

    public async Task LinkPullRequestAsync(string key, IssueLink link, CancellationToken ct) =>
        await SendAsync(HttpMethod.Post, $"{Api}/issue/{K(key)}/remotelink", new JsonObject
        {
            ["globalId"] = link.Url,   // same globalId = update, not a second link (idempotent)
            ["relationship"] = "fix pull request",
            ["object"] = new JsonObject { ["url"] = link.Url, ["title"] = Trim(link.Title, 250) },
        }, ct);

    public async Task<string> AddCommentAsync(string key, string body, CancellationToken ct) =>
        Str(await SendAsync(HttpMethod.Post, $"{Api}/issue/{K(key)}/comment", new JsonObject { ["body"] = Text(body) }, ct), "id");

    internal async Task<string> WhoAmIAsync(CancellationToken ct)
    {
        var j = await GetAsync($"{Api}/myself", ct);
        return StrOrNull(j, "displayName") ?? StrOrNull(j, "name") ?? "unknown";
    }

    /// <summary>v3 takes Atlassian Document Format (one paragraph per line); v2 takes plain text.</summary>
    JsonNode Text(string text)
    {
        if (!Adf) return JsonValue.Create(text)!;
        var content = new JsonArray();
        foreach (var line in text.Replace("\r", "").Split('\n'))
            content.Add(line.Length == 0
                ? new JsonObject { ["type"] = "paragraph" }
                : new JsonObject { ["type"] = "paragraph", ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = line }) });
        return new JsonObject { ["type"] = "doc", ["version"] = 1, ["content"] = content };
    }

    static string Trim(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}
