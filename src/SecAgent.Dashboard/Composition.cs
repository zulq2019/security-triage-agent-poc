using SecAgent.Abstractions;
using SecAgent.Agents;
using SecAgent.Agents.Workflow;
using SecAgent.Connectors;
using SecAgent.Connectors.BlackDuck;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.Fakes;
using SecAgent.Connectors.GitHub;
using SecAgent.Connectors.Jira;
using SecAgent.Connectors.KeyVault;
using SecAgent.Connectors.OpenAI;
using SecAgent.Connectors.Teams;
using SecAgent.Core;

// Dashboard composition root: registers the pipeline (legacy AgentServices container) and the adapters for the ports the intake needs.
// The intake itself is registered by services.AddSecAgentIntake(configuration) (SecAgent.Intake) and never sees these concrete types.

/// <summary>Adapter: <see cref="IPrRunLauncher"/> over the pipeline's RunService (exactly what POST /api/runs does).</summary>
/// The expected head SHA is checked by RunService on the same PR snapshot the run uses, so there is no window between check and start.
sealed class RunServicePrRunLauncher(RunService runner) : IPrRunLauncher
{
    public async Task<PrRunStart> StartPrRunAsync(string repo, int prNumber, string? expectedHeadSha, CancellationToken ct)
    {
        try
        {
            var h = await runner.StartAsync(repo, prNumber, fresh: false, blockForReview: true, expectedHeadSha);
            return PrRunStart.Run(h.State.Run.RunId, h.State.Pr.HeadSha);
        }
        catch (PrHeadMovedException e) { return PrRunStart.Superseded(e.CurrentHeadSha); }
    }
}

/// <summary>Adapter: <see cref="IRunAdmission"/> = kill switch off and no run active (the dashboard's one-run-at-a-time rule).</summary>
sealed class PipelineRunAdmission(AgentServices svc) : IRunAdmission
{
    public bool CanStartRun => !svc.Kill.IsOn && !RunService.AnyActive;
}

static class DashboardComposition
{
    /// <summary>Pipeline services + pipeline-side adapters for the intake ports. Call before AddSecAgentIntake so the intake shares the
    /// pipeline's SecretMasker and message queue (its TryAdd registrations then keep these).</summary>
    public static IServiceCollection AddSecAgentPipeline(this IServiceCollection services, IConfiguration configuration, string repoRoot, string dataRoot, string sql)
    {
        var cfg = AgentServices.LoadConfig(repoRoot);
        services.AddSingleton(cfg);
        services.AddSecAgentConnectorPlugins(configuration, cfg.Gateway);
        services.AddSingleton(sp => AgentServices.Create(repoRoot, dataRoot, sql, sp.GetRequiredService<PipelineConnectors>(),
            sp.GetService<IExternalFindingSource>(), cfg));
        services.AddSingleton<RunService>();
        services.AddSingleton(sp => sp.GetRequiredService<AgentServices>().Masker);
        services.AddSingleton<IMessageQueue>(sp => sp.GetRequiredService<AgentServices>().Queue);
        services.AddSingleton<IFindingSchemaValidator>(sp => sp.GetRequiredService<AgentServices>().Validator);
        services.AddSingleton<IPrRunLauncher, RunServicePrRunLauncher>();
        services.AddSingleton<IRunAdmission, PipelineRunAdmission>();
        return services;
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

    /// <summary>Container for the CLI commands (run / export): same configuration and connector wiring as the dashboard, no web host.</summary>
    public static ServiceProvider BuildCliServices(string repoRoot, string dataRoot, string sql)
    {
        var config = new ConfigurationManager();
        config.AddSecAgentConfiguration(repoRoot, dataRoot);
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Warning));
        services.AddSingleton<IConfiguration>(config);
        services.AddSecAgentPipeline(config, repoRoot, dataRoot, sql);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = false });
    }

    /// <summary>Adds the dashboard's appsettings files (they live next to the source, not the content root), the data root for the intake's
    /// local adapters, and the legacy SECAGENT_INTAKE_* switches. Environment variables (Intake__X) keep the highest precedence.</summary>
    public static ConfigurationManager AddSecAgentConfiguration(this ConfigurationManager config, string repoRoot, string dataRoot)
    {
        var dir = Path.Combine(repoRoot, "src", "SecAgent.Dashboard");
        config.AddJsonFile(Path.Combine(dir, "appsettings.json"), optional: true, reloadOnChange: false)
              .AddJsonFile(Path.Combine(dir, "appsettings.Local.json"), optional: true, reloadOnChange: false);
        var overrides = new Dictionary<string, string?> { ["Intake:StorageRoot"] = dataRoot };
        if (Environment.GetEnvironmentVariable("SECAGENT_INTAKE_ENABLED") is { Length: > 0 } en) overrides["Intake:Enabled"] = (en is "1" or "true").ToString();
        if (Environment.GetEnvironmentVariable("SECAGENT_INTAKE_DROP_WATCHER") is { Length: > 0 } dw) overrides["Intake:DropWatcherEnabled"] = (dw is "1" or "true").ToString();
        config.AddInMemoryCollection(overrides);
        config.AddEnvironmentVariables();
        return config;
    }
}
