using SecAgent.Connectors;

namespace SecAgent.Agents;

/// <summary>The connector ports the pipeline uses, as typed per-tenant client factories (contracts only: the host decides which plug-in
/// serves each tenant, from configuration). Issue tracker, notifier and scanner source are optional (use TryForTenant): a tenant without
/// them simply gets no tickets / cards / scanner backlog. Slice 1 has no stage that reads the scanner source yet (backlog runner and
/// fixer upgrade guidance are the consumers to come); it is exposed here so they depend on the port, not on a plug-in.</summary>
public sealed record PipelineConnectors(
    ITenantResolver Tenants,
    IConnectorClientFactory<ISourceControlClient> SourceControl,
    IConnectorClientFactory<IModelProviderClient> Models,
    IConnectorClientFactory<IIssueTrackerClient> IssueTrackers,
    IConnectorClientFactory<INotifierClient> Notifiers,
    IConnectorClientFactory<IScannerSourceClient> ScannerSources)
{
    /// <summary>Resolves the ports from a container that ran AddSecAgentConnectors (contracts only; no dependency on the runtime).</summary>
    public static PipelineConnectors From(IServiceProvider sp) => new(Get<ITenantResolver>(sp), Get<IConnectorClientFactory<ISourceControlClient>>(sp),
        Get<IConnectorClientFactory<IModelProviderClient>>(sp), Get<IConnectorClientFactory<IIssueTrackerClient>>(sp), Get<IConnectorClientFactory<INotifierClient>>(sp),
        Get<IConnectorClientFactory<IScannerSourceClient>>(sp));

    static T Get<T>(IServiceProvider sp) where T : class =>
        sp.GetService(typeof(T)) as T ?? throw new InvalidOperationException($"{typeof(T).Name} is not registered: call services.AddSecAgentConnectors(configuration) in the composition root");
}
