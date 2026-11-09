using Xunit;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Connectors;
using SecAgent.Connectors.Fakes;
using SecAgent.Connectors.Jira;

namespace SecAgent.Tests.Connectors;

/// <summary>Contract every <see cref="IIssueTrackerClient"/> must honour (fake and Jira run the same assertions).</summary>
public abstract class IssueTrackerContract
{
    protected abstract IIssueTrackerClient CreateClient();
    protected abstract int LinkCount(string key);

    static NewIssue Task1(string project = "SEC") => new(project, "Rotate leaked synthetic token", "Line one\nLine two", Labels: ["secagent"], ExternalId: "task-0001");

    [Fact]
    public async Task Create_is_idempotent_by_external_id()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(Task1(), default);
        Assert.StartsWith("SEC-", a.Key);
        Assert.EndsWith("/browse/" + a.Key, a.Url);
        var again = await c.CreateIssueAsync(Task1(), default);
        Assert.Equal(a.Key, again.Key);
        Assert.Equal(a.Key, (await c.FindByExternalIdAsync("SEC", "task-0001", default))!.Key);
        Assert.Null(await c.FindByExternalIdAsync("SEC", "task-9999", default));
    }

    [Fact]
    public async Task Empty_project_key_uses_the_connection_default_project()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(Task1(project: "") with { ExternalId = "task-0002" }, default);
        Assert.StartsWith("SEC-", a.Key);
        Assert.Equal(a.Key, (await c.FindByExternalIdAsync("", "task-0002", default))!.Key);
    }

    [Fact]
    public async Task Reads_and_updates_an_issue()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(Task1(), default);
        var info = await c.GetIssueAsync(a.Key, default);
        Assert.Equal(("Rotate leaked synthetic token", "To Do"), (info!.Summary, info.Status));
        Assert.Contains("secagent", info.Labels);
        await c.UpdateIssueAsync(a.Key, new IssueUpdate(Summary: "Rotate leaked synthetic token (renamed)", AddLabels: ["needs-owner"]), default);
        info = await c.GetIssueAsync(a.Key, default);
        Assert.Equal("Rotate leaked synthetic token (renamed)", info!.Summary);
        Assert.Contains("needs-owner", info.Labels);
        Assert.Null(await c.GetIssueAsync("SEC-999", default));
    }

    [Fact]
    public async Task Transitions_through_the_workflow_and_rejects_unknown_targets()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(Task1(), default);
        Assert.Equal("In Progress", (await c.TransitionAsync(a.Key, "In Progress", default)).Status);
        Assert.Equal("Done", (await c.TransitionAsync(a.Key, "done", default)).Status);
        Assert.Equal("Done", (await c.TransitionAsync(a.Key, "Done", default)).Status);   // already there: no-op
        await Assert.ThrowsAnyAsync<ConnectorException>(() => c.TransitionAsync(a.Key, "Won't Fix", default));
        Assert.Equal("Done", (await c.GetIssueAsync(a.Key, default))!.Status);
    }

    [Fact]
    public async Task Links_a_pull_request_once_and_comments()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(Task1(), default);
        var link = new IssueLink("https://github.com/acme/payments/pull/8", "acme/payments#8");
        await c.LinkPullRequestAsync(a.Key, link, default);
        await c.LinkPullRequestAsync(a.Key, link, default);
        Assert.Equal(1, LinkCount(a.Key));
        Assert.False(string.IsNullOrEmpty(await c.AddCommentAsync(a.Key, "Fix PR opened (synthetic)", default)));
    }
}

public sealed class FakeIssueTrackerContractTests : IssueTrackerContract
{
    readonly FakeConnectorWorld _world = new();
    protected override IIssueTrackerClient CreateClient() =>
        ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.AddFakeConnectors(_world)).GetRequiredService<IConnectorClientFactory<IIssueTrackerClient>>().ForTenant(ConnectorTestKit.Tenant);
    protected override int LinkCount(string key) => _world.IssueTracker.Issues(ConnectorTestKit.Tenant).Single(i => i.Key == key).Links.Count;
}

/// <summary>In-memory Jira Cloud REST v3 (subset). Field shapes follow Atlassian's public docs; see ASSUMPTION notes on the client.</summary>
public sealed class JiraSimulator : HttpStub
{
    public sealed class Issue { public string Key = ""; public string Project = ""; public string Summary = ""; public JsonNode? Description; public string Status = "To Do";
        public List<string> Labels = []; public Dictionary<string, JsonNode> RemoteLinks = []; public List<JsonNode?> Comments = []; }
    public List<Issue> Issues { get; } = [];
    static readonly Dictionary<string, (string Id, string To)[]> Transitions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["To Do"] = [("11", "In Progress"), ("31", "Done")], ["In Progress"] = [("31", "Done"), ("41", "To Do")], ["Done"] = [("41", "To Do")],
    };

    protected override HttpResponseMessage Handle(SeenRequest r)
    {
        if (r.AuthScheme is not ("Basic" or "Bearer")) return Status(HttpStatusCode.Unauthorized);
        var path = r.Path.TrimStart('/');
        const string api = "rest/api/3/";
        if (!path.StartsWith(api)) return Status(HttpStatusCode.NotFound);
        var rest = path[api.Length..];
        var seg = rest.Split('/');
        var m = r.Method.Method;
        if (rest == "myself") return Json(new JsonObject { ["displayName"] = "SecAgent bot" });
        if (rest == "search/jql" && m == "GET")
        {
            var jql = System.Web.HttpUtility.ParseQueryString(r.PathAndQuery[(r.PathAndQuery.IndexOf('?') + 1)..])["jql"]!;
            var project = Between(jql, "project = \"", "\""); var label = Between(jql, "labels = \"", "\"");
            return Json(new JsonObject { ["issues"] = new JsonArray(Issues.Where(i => i.Project == project && i.Labels.Contains(label)).Select(i => (JsonNode)new JsonObject { ["key"] = i.Key }).ToArray()) });
        }
        if (rest == "issue" && m == "POST")
        {
            var f = r.Json!["fields"]!;
            var project = (string)f["project"]!["key"]!;
            var issue = new Issue { Key = $"{project}-{Issues.Count(i => i.Project == project) + 1}", Project = project, Summary = (string)f["summary"]!, Description = f["description"]?.DeepClone(),
                Labels = f["labels"]!.AsArray().Select(l => (string)l!).ToList() };
            Issues.Add(issue);
            return Json(new JsonObject { ["id"] = "100" + Issues.Count, ["key"] = issue.Key }, HttpStatusCode.Created);
        }
        if (seg[0] == "issue" && seg.Length >= 2)
        {
            var issue = Issues.FirstOrDefault(i => i.Key == seg[1]);
            if (issue == null) return Status(HttpStatusCode.NotFound);
            if (seg.Length == 2 && m == "GET")
                return Json(new JsonObject { ["key"] = issue.Key, ["fields"] = new JsonObject { ["summary"] = issue.Summary, ["status"] = new JsonObject { ["name"] = issue.Status },
                    ["labels"] = new JsonArray(issue.Labels.Select(l => (JsonNode)l).ToArray()) } });
            if (seg.Length == 2 && m == "PUT")
            {
                var j = r.Json!;
                if (j["fields"]?["summary"] is { } s) issue.Summary = (string)s!;
                foreach (var op in j["update"]?["labels"]?.AsArray() ?? []) if ((string?)op!["add"] is { } l && !issue.Labels.Contains(l)) issue.Labels.Add(l);
                return Status(HttpStatusCode.NoContent);
            }
            if (seg.Length == 3 && seg[2] == "transitions" && m == "GET")
                return Json(new JsonObject { ["transitions"] = new JsonArray(Transitions[issue.Status].Select(t => (JsonNode)new JsonObject
                    { ["id"] = t.Id, ["name"] = "Move to " + t.To, ["to"] = new JsonObject { ["name"] = t.To } }).ToArray()) });
            if (seg.Length == 3 && seg[2] == "transitions" && m == "POST")
            {
                var id = (string)r.Json!["transition"]!["id"]!;
                var t = Transitions[issue.Status].FirstOrDefault(x => x.Id == id);
                if (t.Id == null) return Status(HttpStatusCode.BadRequest);
                issue.Status = t.To;
                return Status(HttpStatusCode.NoContent);
            }
            if (seg.Length == 3 && seg[2] == "remotelink" && m == "POST")
            {
                issue.RemoteLinks[(string)r.Json!["globalId"]!] = r.Json!.DeepClone();
                return Json(new JsonObject { ["id"] = issue.RemoteLinks.Count }, HttpStatusCode.Created);
            }
            if (seg.Length == 3 && seg[2] == "comment" && m == "POST")
            {
                issue.Comments.Add(r.Json!["body"]?.DeepClone());
                return Json(new JsonObject { ["id"] = (10000 + issue.Comments.Count).ToString() }, HttpStatusCode.Created);
            }
        }
        return Status(HttpStatusCode.NotFound);
    }

    static string Between(string s, string a, string b) { var i = s.IndexOf(a, StringComparison.Ordinal) + a.Length; return s[i..s.IndexOf(b, i, StringComparison.Ordinal)]; }
}

public sealed class JiraIssueTrackerContractTests : IssueTrackerContract
{
    readonly JiraSimulator _sim = new();

    public static Dictionary<string, string?> Config(string tenant = ConnectorTestKit.Tenant) => new()
    {
        ["Connectors:DeploymentModel"] = "SingleTenant", ["Connectors:DefaultTenant"] = tenant,
        [$"Connectors:Tenants:{tenant}:IssueTracker:Provider"] = "jira",
        [$"Connectors:Tenants:{tenant}:IssueTracker:BaseUrl"] = "https://acme.atlassian.test/",
        [$"Connectors:Tenants:{tenant}:IssueTracker:Secret"] = "memory:jira-token",
        [$"Connectors:Tenants:{tenant}:IssueTracker:Settings:Email"] = "bot@acme.test",
        [$"Connectors:Tenants:{tenant}:IssueTracker:Settings:ProjectKey"] = "SEC",
        ["Connectors:Resilience:PermitsPerSecond"] = "1000",
    };

    protected override IIssueTrackerClient CreateClient()
    {
        var sp = ConnectorTestKit.Services(Config(), b => b.AddFakeConnectors().AddJiraConnector(),
            s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => _sim)));
        sp.GetRequiredService<InMemorySecretSource>().Set("jira-token", "synthetic-jira-api-token");
        return sp.GetRequiredService<IConnectorClientFactory<IIssueTrackerClient>>().ForTenant(ConnectorTestKit.Tenant);
    }

    protected override int LinkCount(string key) => _sim.Issues.Single(i => i.Key == key).RemoteLinks.Count;

    [Fact]
    public async Task Requests_use_basic_auth_adf_bodies_and_the_external_id_label()
    {
        var c = CreateClient();
        var a = await c.CreateIssueAsync(new NewIssue("SEC", "Synthetic", "first\nsecond", ExternalId: "Task-ABC"), default);
        var post = Assert.Single(_sim.Seen, r => r.Method == HttpMethod.Post && r.Path.EndsWith("/rest/api/3/issue"));
        Assert.Equal("Basic", post.AuthScheme);
        Assert.Equal("bot@acme.test:synthetic-jira-api-token", Encoding.UTF8.GetString(Convert.FromBase64String(post.AuthParameter!)));
        var fields = post.Json!["fields"]!;
        Assert.Equal("doc", (string?)fields["description"]!["type"]);
        Assert.Equal(2, fields["description"]!["content"]!.AsArray().Count);
        Assert.Contains("secagent-task-abc", fields["labels"]!.AsArray().Select(l => (string?)l));
        // Check-before-act: the search ran before the create.
        Assert.True(_sim.Seen.ToList().FindIndex(r => r.Path.EndsWith("/search/jql")) < _sim.Seen.ToList().FindIndex(r => r.Method == HttpMethod.Post));
        await c.LinkPullRequestAsync(a.Key, new IssueLink("https://github.com/acme/payments/pull/8", "PR"), default);
        var link = Assert.Single(_sim.Seen, r => r.Path.EndsWith("/remotelink"));
        Assert.Equal("https://github.com/acme/payments/pull/8", (string?)link.Json!["globalId"]);
    }
}
