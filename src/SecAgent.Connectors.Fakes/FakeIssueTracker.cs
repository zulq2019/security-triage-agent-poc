namespace SecAgent.Connectors.Fakes;

public sealed class FakeIssue
{
    public required string Key { get; init; }
    public required string ProjectKey { get; init; }
    public required string Summary { get; set; }
    public string Description { get; set; } = "";
    public string IssueType { get; set; } = "Task";
    public string Status { get; set; } = "To Do";
    public string? Priority { get; set; }
    public string? ExternalId { get; init; }
    public List<string> Labels { get; } = [];
    public List<string> Comments { get; } = [];
    public List<IssueLink> Links { get; } = [];
    public string Url => $"https://issues.fake.invalid/browse/{Key}";
}

/// <summary>Per-tenant in-memory Jira with a fixed workflow: To Do → In Progress → Done (and back to To Do).</summary>
public sealed class FakeIssueTrackerState
{
    internal readonly object Lock = new();
    internal readonly Dictionary<string, List<FakeIssue>> Tenants = new(StringComparer.OrdinalIgnoreCase);

    public static readonly IReadOnlyDictionary<string, string[]> Workflow = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["To Do"] = ["In Progress", "Done"], ["In Progress"] = ["Done", "To Do"], ["Done"] = ["To Do"],
    };

    public IReadOnlyList<FakeIssue> Issues(string tenantId) { lock (Lock) return Tenants.GetValueOrDefault(tenantId)?.ToList() ?? []; }
    internal List<FakeIssue> For(string tenant) => Tenants.TryGetValue(tenant, out var l) ? l : Tenants[tenant] = [];
}

public sealed class FakeIssueTrackerClient(FakeConnectorWorld world, string tenant, string defaultProject = "SEC") : IIssueTrackerClient
{
    string Project(string? key) => string.IsNullOrWhiteSpace(key) ? defaultProject : key;
    FakeIssueTrackerState S => world.IssueTracker;
    FakeIssue Get(string key) => S.For(tenant).FirstOrDefault(i => i.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
                                 ?? throw new ConnectorException($"fake: issue {key} not found", false, System.Net.HttpStatusCode.NotFound);
    static IssueInfo Info(FakeIssue i) => new(i.Key, i.Url, i.Summary, i.Status, i.Labels.ToList());

    public Task<IssueInfo?> GetIssueAsync(string key, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.get", ("key", key));
        lock (S.Lock) return Task.FromResult(S.For(tenant).FirstOrDefault(i => i.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) is { } i ? Info(i) : null);
    }

    public Task<IssueRef?> FindByExternalIdAsync(string projectKey, string externalId, CancellationToken ct)
    {
        projectKey = Project(projectKey);
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.find_by_external_id", ("project", projectKey), ("external_id", externalId));
        lock (S.Lock)
            return Task.FromResult(S.For(tenant).FirstOrDefault(i => i.ProjectKey == projectKey && i.ExternalId == externalId) is { } i ? new IssueRef(i.Key, i.Url) : null);
    }

    public Task<IssueRef> CreateIssueAsync(NewIssue issue, CancellationToken ct)
    {
        issue = issue with { ProjectKey = Project(issue.ProjectKey) };
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.create", ("project", issue.ProjectKey), ("summary", issue.Summary), ("external_id", issue.ExternalId));
        lock (S.Lock)
        {
            var list = S.For(tenant);
            if (issue.ExternalId != null && list.FirstOrDefault(i => i.ProjectKey == issue.ProjectKey && i.ExternalId == issue.ExternalId) is { } existing)
                return Task.FromResult(new IssueRef(existing.Key, existing.Url));
            var n = list.Count(i => i.ProjectKey == issue.ProjectKey) + 1;
            var created = new FakeIssue { Key = $"{issue.ProjectKey}-{n}", ProjectKey = issue.ProjectKey, Summary = issue.Summary, Description = issue.Description,
                IssueType = issue.IssueType, Priority = issue.Priority, ExternalId = issue.ExternalId };
            created.Labels.AddRange(issue.Labels ?? []);
            list.Add(created);
            return Task.FromResult(new IssueRef(created.Key, created.Url));
        }
    }

    public Task UpdateIssueAsync(string key, IssueUpdate update, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.update", ("key", key));
        lock (S.Lock)
        {
            var i = Get(key);
            if (update.Summary != null) i.Summary = update.Summary;
            if (update.Description != null) i.Description = update.Description;
            if (update.Priority != null) i.Priority = update.Priority;
            foreach (var l in update.AddLabels ?? []) if (!i.Labels.Contains(l)) i.Labels.Add(l);
        }
        return Task.CompletedTask;
    }

    public Task<IssueInfo> TransitionAsync(string key, string toStatus, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.transition", ("key", key), ("to", toStatus));
        lock (S.Lock)
        {
            var i = Get(key);
            if (i.Status.Equals(toStatus, StringComparison.OrdinalIgnoreCase)) return Task.FromResult(Info(i));
            var next = FakeIssueTrackerState.Workflow.GetValueOrDefault(i.Status) ?? [];
            var target = next.FirstOrDefault(s => s.Equals(toStatus, StringComparison.OrdinalIgnoreCase))
                         ?? throw new ConnectorException($"fake: no transition from '{i.Status}' to '{toStatus}' for {key} (available: {string.Join(", ", next)})");
            i.Status = target;
            return Task.FromResult(Info(i));
        }
    }

    public Task LinkPullRequestAsync(string key, IssueLink link, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.link_pull_request", ("key", key), ("url", link.Url));
        lock (S.Lock)
        {
            var i = Get(key);
            i.Links.RemoveAll(l => l.Url == link.Url);
            i.Links.Add(link);
        }
        return Task.CompletedTask;
    }

    public Task<string> AddCommentAsync(string key, string body, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.IssueTracker, "issue.comment", ("key", key));
        lock (S.Lock)
        {
            var i = Get(key);
            i.Comments.Add(body);
            return Task.FromResult($"{i.Key}-c{i.Comments.Count}");
        }
    }
}
