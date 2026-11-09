using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Agents;
using SecAgent.Agents.Hosting;
using SecAgent.Connectors.BlackDuck;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.Fakes;
using SecAgent.Connectors.GitHub;
using SecAgent.Connectors.Jira;
using SecAgent.Connectors.KeyVault;
using SecAgent.Connectors.OpenAI;
using SecAgent.Connectors.Teams;
using SecAgent.Core;

namespace SecAgent.Connectors.Hosting;

/// <summary>Connector composition shared by every host that runs the pipeline (dashboard and the worker's orchestrator role).</summary>
public static class ConnectorPluginsServiceCollectionExtensions
{
    /// <summary>Connector plug-ins + the pipeline (<see cref="PipelineServiceCollectionExtensions.AddSecAgentPipeline"/>) with one rules
    /// snapshot, so the default model connection and the pipeline read the same ModelProvider settings.</summary>
    /// <param name="shareQueue">See <see cref="PipelineServiceCollectionExtensions.AddSecAgentPipeline"/>.</param>
    public static IServiceCollection AddSecAgentPipelineWithConnectors(this IServiceCollection services, IConfiguration configuration, string repoRoot,
        string dataRoot, string sql, bool shareQueue = true)
    {
        var cfg = AgentServices.LoadConfig(repoRoot);
        return services.AddSecAgentConnectorPlugins(configuration, cfg.Gateway).AddSecAgentPipeline(cfg, repoRoot, dataRoot, sql, shareQueue);
    }

    /// <summary>Connector layer: runtime (options, tenant resolution, secrets, registry, auditing + resilience decorators) and every plug-in.
    /// Which plug-in serves which tenant is configuration ("Connectors" section, docs/connectors.md); nothing here picks one.</summary>
    public static IServiceCollection AddSecAgentConnectorPlugins(this IServiceCollection services, IConfiguration configuration, GatewayConfig gateway)
    {
        services.AddSecAgentConnectors(configuration)
            .AddGitHubConnector()
            .AddJiraConnector()
            .AddBlackDuckConnector()
            .AddOpenAICompatibleModelConnector()
            .AddTeamsNotifier()
            .AddKeyVaultSecrets(configuration)
            .AddFakeConnectors();
        // Backwards compatible: the existing ModelProvider switch (ollama | openai | azureopenai) becomes the shared default model connection
        // unless "Connectors" configures one explicitly.
        services.PostConfigure<ConnectorOptions>(o => o.Defaults.ModelProvider ??= ModelConnectionFrom(gateway));
        services.AddSingleton(PipelineConnectors.From);
        return services;
    }

    /// <summary>The model provider switch (appsettings ModelProvider / SECAGENT_MODEL_PROVIDER) as a connection: the key stays an env var reference.</summary>
    public static ConnectionOptions ModelConnectionFrom(GatewayConfig g)
    {
        var flavor = UsageMath.ProviderOf(g);
        var c = new ConnectionOptions { Provider = OpenAICompatibleModelConnector.Id, BaseUrl = g.Endpoint, Secret = string.IsNullOrEmpty(g.ApiKeyEnv) ? null : "env:" + g.ApiKeyEnv };
        c.Settings["Flavor"] = flavor;
        c.Settings["RequestTimeoutSeconds"] = g.RequestTimeoutSeconds.ToString();
        if (!string.IsNullOrEmpty(g.HealthUrl)) c.Settings["HealthUrl"] = g.HealthUrl;
        return c;
    }
}
