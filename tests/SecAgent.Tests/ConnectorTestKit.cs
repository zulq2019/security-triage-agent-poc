using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Agents;
using SecAgent.Connectors;
using SecAgent.Connectors.Fakes;

namespace SecAgent.Tests;

/// <summary>Builds the connector layer the way a host does (AddSecAgentConnectors + plug-ins), with in-memory configuration.</summary>
public static class ConnectorTestKit
{
    public const string Tenant = "t1";

    /// <summary>Single-tenant configuration where every kind is served by the fake plug-in.</summary>
    public static Dictionary<string, string?> AllFakes(string tenant = Tenant)
    {
        var d = new Dictionary<string, string?> { ["Connectors:DeploymentModel"] = "SingleTenant", ["Connectors:DefaultTenant"] = tenant };
        foreach (var kind in Enum.GetNames<ConnectorKind>()) d[$"Connectors:Tenants:{tenant}:{kind}:Provider"] = "fake";
        return d;
    }

    public static ServiceProvider Services(IDictionary<string, string?> config, Action<ConnectorsBuilder>? plugins = null, Action<IServiceCollection>? extra = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(config).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddSecAgentConnectors(configuration);
        (plugins ?? (b => b.AddFakeConnectors()))(builder);
        extra?.Invoke(services);
        return services.BuildServiceProvider();
    }

    public static (ServiceProvider Sp, FakeConnectorWorld World, PipelineConnectors Ports) Fakes(string tenant = Tenant)
    {
        var world = new FakeConnectorWorld();
        var sp = Services(AllFakes(tenant), b => b.AddFakeConnectors(world));
        return (sp, world, PipelineConnectors.From(sp));
    }
}
