namespace SecAgent.Connectors;

/// <summary>What a connector is for. Each kind has its own client contract (see <see cref="ConnectorKinds"/>).</summary>
public enum ConnectorKind { SourceControl, IssueTracker, ScannerSource, ModelProvider, Notifier }

/// <summary>How a connector reaches its system. Decides which resilience layer applies: HTTP connectors get the
/// Microsoft.Extensions.Http.Resilience handler on their HttpClient; SDK / process / in-memory connectors get the call-level decorator.</summary>
public enum ConnectorTransport { Http, Sdk, Process, InMemory }

public enum SelectionKind { None, Repositories, Projects }
public enum Availability { Available, ComingSoon }
public enum HealthState { Healthy, Degraded, Failing }

/// <summary>One permission the connector asks for, with the reason shown on the Connections page (SDD 9.7 step 1).</summary>
public sealed record Scope(string Name, string Access, string Reason);

/// <summary>A non-secret setup value (base URL, Jira site, project key). Secrets are never setup fields: a field may only hold a
/// secret <em>reference</em> (<see cref="IsSecretReference"/>), e.g. "kv:github-token".</summary>
public sealed record SetupField(string Name, string Label, bool Required, bool IsSecretReference = false, string? Example = null);

/// <summary>Capability descriptor of a connector plug-in (SDD 9.8 Describe()). The Connections UI renders the catalogue from these.</summary>
/// <param name="Id">Provider id used in configuration ("github", "jira", "blackduck", "openai-compatible", "teams", "fake").</param>
/// <param name="Capabilities">Operations the connector implements (see <see cref="ConnectorCapabilities"/>).</param>
/// <param name="NeverGranted">Things the connector must never be able to do ("merge", "admin", ...): shown on the page and tested.</param>
/// <param name="IsSimulated">True for in-memory fakes: the page shows them as "simulated", never as connected to a real system.</param>
public sealed record ConnectorDescriptor(
    string Id,
    string DisplayName,
    ConnectorKind Kind,
    string Category,
    ConnectorTransport Transport,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<Scope> ScopesRequested,
    IReadOnlyList<string> NeverGranted,
    IReadOnlyList<SetupField> SetupFields,
    SelectionKind Selection = SelectionKind.None,
    Availability Availability = Availability.Available,
    bool IsSimulated = false,
    string? Notes = null);

public sealed record HealthResult(HealthState State, string Detail, DateTimeOffset CheckedAt)
{
    public static HealthResult Healthy(string detail, DateTimeOffset at) => new(HealthState.Healthy, detail, at);
    public static HealthResult Failing(string detail, DateTimeOffset at) => new(HealthState.Failing, detail, at);
}

/// <summary>Capability names used in descriptors (stable strings, safe to show and to assert in tests). There is deliberately no
/// merge / approve / branch-protection capability.</summary>
public static class ConnectorCapabilities
{
    public const string PullRequestRead = "pull_request.read";
    public const string PullRequestFilesRead = "pull_request.files.read";
    public const string PullRequestCreate = "pull_request.create";
    public const string PullRequestComment = "pull_request.comment";
    public const string BranchCreate = "branch.create";
    public const string BranchPublish = "branch.publish";
    public const string CommitCreate = "commit.create";
    public const string CheckRunRead = "check_run.read";
    public const string IssueRead = "issue.read";
    public const string IssueCreate = "issue.create";
    public const string IssueUpdate = "issue.update";
    public const string IssueTransition = "issue.transition";
    public const string IssueLinkPullRequest = "issue.link_pull_request";
    public const string IssueComment = "issue.comment";
    public const string VulnerabilityBacklogRead = "vulnerability.backlog.read";
    public const string RemediationGuidanceRead = "remediation.guidance.read";
    public const string ChatCompletion = "model.chat_completion";
    public const string StructuredOutput = "model.structured_output";
    public const string TokenUsage = "model.token_usage";
    public const string ModelCatalog = "model.catalog";
    public const string NotificationSend = "notification.send";
}

/// <summary>Maps each kind to its client contract.</summary>
public static class ConnectorKinds
{
    public static Type ClientType(ConnectorKind kind) => kind switch
    {
        ConnectorKind.SourceControl => typeof(ISourceControlClient),
        ConnectorKind.IssueTracker => typeof(IIssueTrackerClient),
        ConnectorKind.ScannerSource => typeof(IScannerSourceClient),
        ConnectorKind.ModelProvider => typeof(IModelProviderClient),
        ConnectorKind.Notifier => typeof(INotifierClient),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static ConnectorKind KindOf(Type clientType)
    {
        foreach (var k in Enum.GetValues<ConnectorKind>()) if (ClientType(k) == clientType) return k;
        throw new ArgumentException($"{clientType.Name} is not a connector client contract", nameof(clientType));
    }
}
