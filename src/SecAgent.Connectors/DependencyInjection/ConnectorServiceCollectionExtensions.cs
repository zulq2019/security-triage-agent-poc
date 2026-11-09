using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SecAgent.Connectors.Auditing;
using SecAgent.Connectors.Calls;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.Decorators;
using SecAgent.Connectors.Health;
using SecAgent.Connectors.Registry;
using SecAgent.Connectors.Secrets;
using SecAgent.Connectors.Tenancy;

namespace SecAgent.Connectors;

/// <summary>Returned by <see cref="ConnectorServiceCollectionExtensions.AddSecAgentConnectors"/>; plug-in projects add themselves with
/// extension methods on it (AddGitHubConnector, AddJiraConnector, AddFakeConnectors, ...).</summary>
public sealed class ConnectorsBuilder(IServiceCollection services)
{
    public IServiceCollection Services { get; } = services;

    /// <summary>Registers a plug-in: one line per connector (SDD 9.8 AddConnector&lt;T&gt;).</summary>
    public ConnectorsBuilder AddConnector<TConnector, TClient>() where TConnector : class, IConnectorClientProvider<TClient> where TClient : class
    {
        Services.TryAddSingleton<TConnector>();
        Services.AddSingleton<IConnector>(sp => sp.GetRequiredService<TConnector>());
        return this;
    }

    public ConnectorsBuilder AddSecretSource<TSource>() where TSource : class, ISecretSource
    {
        Services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecretSource, TSource>());
        return this;
    }
}

public static class ConnectorServiceCollectionExtensions
{
    /// <summary>Composition root of the connector layer: options (validated on start), tenant resolution, secrets, catalogue, decorators and
    /// one typed client factory per kind. Add plug-ins on the returned builder.</summary>
    public static ConnectorsBuilder AddSecAgentConnectors(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ConnectorOptions>().Bind(configuration.GetSection(ConnectorOptions.SectionName)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ConnectorOptions>, ConnectorOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddHttpClient();

        services.TryAddSingleton<ConfigurationTenantConnectionResolver>();
        services.TryAddSingleton<ITenantConnectionResolver>(sp => sp.GetRequiredService<ConfigurationTenantConnectionResolver>());
        services.TryAddSingleton<ITenantResolver>(sp => sp.GetRequiredService<ConfigurationTenantConnectionResolver>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecretSource, EnvironmentSecretSource>());
        services.TryAddSingleton<ISecretProvider, CompositeSecretProvider>();
        services.TryAddSingleton<IConnectorCatalog, ConnectorCatalog>();

        services.TryAddSingleton<InMemoryConnectorAuditLog>();
        services.AddSingleton<IConnectorAuditSink>(sp => sp.GetRequiredService<InMemoryConnectorAuditLog>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectorAuditSink, LoggingConnectorAuditSink>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectorCallInterceptor, AuditingInterceptor>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectorCallInterceptor, ResilienceInterceptor>());
        services.TryAddSingleton<ConnectorInvokerFactory>();

        services.TryAddSingleton<IConnectorClientDecorator<ISourceControlClient>, SourceControlClientDecorator>();
        services.TryAddSingleton<IConnectorClientDecorator<IIssueTrackerClient>, IssueTrackerClientDecorator>();
        services.TryAddSingleton<IConnectorClientDecorator<IScannerSourceClient>, ScannerSourceClientDecorator>();
        services.TryAddSingleton<IConnectorClientDecorator<IModelProviderClient>, ModelProviderClientDecorator>();
        services.TryAddSingleton<IConnectorClientDecorator<INotifierClient>, NotifierClientDecorator>();
        services.TryAddSingleton(typeof(IConnectorClientFactory<>), typeof(ConnectorClientFactory<>));

        services.TryAddSingleton<IConnectorHealthService, ConnectorHealthService>();
        return new ConnectorsBuilder(services);
    }
}
