using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SecAgent.Connectors.Fakes;

/// <summary>Base for the fake plug-ins: provider id "fake", in-memory transport, marked simulated so the Connections page never shows
/// them as connected to a real system.</summary>
public abstract class FakeConnectorBase<TClient>(FakeConnectorWorld world, ConnectorKind kind, string displayName, string[] capabilities, string[] neverGranted)
    : IConnectorClientProvider<TClient> where TClient : class
{
    public const string Id = "fake";
    protected FakeConnectorWorld World { get; } = world;

    public ConnectorDescriptor Describe() => new(Id, displayName, kind, "simulated", ConnectorTransport.InMemory, capabilities,
        [new("In-memory", "simulated", "Deterministic fake for tests and demos; no network calls.")], neverGranted, [], IsSimulated: true,
        Notes: "Simulated connector: synthetic data only.");

    public Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct) =>
        Task.FromResult(HealthResult.Healthy("simulated (in-memory fake)", DateTimeOffset.UnixEpoch));

    public abstract TClient CreateClient(ConnectionSettings connection);
}

public sealed class FakeSourceControlConnector(FakeConnectorWorld world) : FakeConnectorBase<ISourceControlClient>(world, ConnectorKind.SourceControl, "Fake source control",
    [ConnectorCapabilities.PullRequestRead, ConnectorCapabilities.PullRequestFilesRead, ConnectorCapabilities.PullRequestCreate, ConnectorCapabilities.PullRequestComment,
     ConnectorCapabilities.BranchCreate, ConnectorCapabilities.BranchPublish, ConnectorCapabilities.CommitCreate, ConnectorCapabilities.CheckRunRead],
    ["merge", "approve", "admin", "branch_protection", "push_default_branch", "force_push"])
{
    public override ISourceControlClient CreateClient(ConnectionSettings connection) => new FakeSourceControlClient(World, connection.TenantId);
}

public sealed class FakeIssueTrackerConnector(FakeConnectorWorld world) : FakeConnectorBase<IIssueTrackerClient>(world, ConnectorKind.IssueTracker, "Fake issue tracker",
    [ConnectorCapabilities.IssueRead, ConnectorCapabilities.IssueCreate, ConnectorCapabilities.IssueUpdate, ConnectorCapabilities.IssueTransition,
     ConnectorCapabilities.IssueLinkPullRequest, ConnectorCapabilities.IssueComment], ["delete", "admin"])
{
    public override IIssueTrackerClient CreateClient(ConnectionSettings connection) => new FakeIssueTrackerClient(World, connection.TenantId, connection.Get("ProjectKey") ?? "SEC");
}

public sealed class FakeScannerSourceConnector(FakeConnectorWorld world) : FakeConnectorBase<IScannerSourceClient>(world, ConnectorKind.ScannerSource, "Fake scanner source",
    [ConnectorCapabilities.VulnerabilityBacklogRead, ConnectorCapabilities.RemediationGuidanceRead], ["policy_change", "ignore_component", "remediation_status_write"])
{
    public override IScannerSourceClient CreateClient(ConnectionSettings connection) => new FakeScannerSourceClient(World, connection.TenantId);
}

public sealed class FakeModelProviderConnector(FakeConnectorWorld world) : FakeConnectorBase<IModelProviderClient>(world, ConnectorKind.ModelProvider, "Fake model provider",
    [ConnectorCapabilities.ChatCompletion, ConnectorCapabilities.StructuredOutput, ConnectorCapabilities.TokenUsage, ConnectorCapabilities.ModelCatalog], ["bypass_gateway"])
{
    public override IModelProviderClient CreateClient(ConnectionSettings connection) => new FakeModelProviderClient(World, connection.TenantId);
}

public sealed class FakeNotifierConnector(FakeConnectorWorld world) : FakeConnectorBase<INotifierClient>(world, ConnectorKind.Notifier, "Fake notifier",
    [ConnectorCapabilities.NotificationSend], ["read_messages"])
{
    public override INotifierClient CreateClient(ConnectionSettings connection) => new FakeNotifierClient(World, connection.TenantId);
}

public static class FakeConnectorRegistration
{
    /// <summary>Registers the five fake plug-ins (provider id "fake"), their shared <see cref="FakeConnectorWorld"/> and the "memory" secret source.</summary>
    public static ConnectorsBuilder AddFakeConnectors(this ConnectorsBuilder builder, FakeConnectorWorld? world = null)
    {
        if (world != null) builder.Services.AddSingleton(world); else builder.Services.TryAddSingleton<FakeConnectorWorld>();
        builder.Services.TryAddSingleton<InMemorySecretSource>();
        builder.Services.AddSingleton<Secrets.ISecretSource>(sp => sp.GetRequiredService<InMemorySecretSource>());
        return builder.AddConnector<FakeSourceControlConnector, ISourceControlClient>()
            .AddConnector<FakeIssueTrackerConnector, IIssueTrackerClient>()
            .AddConnector<FakeScannerSourceConnector, IScannerSourceClient>()
            .AddConnector<FakeModelProviderConnector, IModelProviderClient>()
            .AddConnector<FakeNotifierConnector, INotifierClient>();
    }
}
