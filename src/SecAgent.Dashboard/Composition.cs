using SecAgent.Abstractions;
using SecAgent.Agents;
using SecAgent.Agents.Workflow;
using SecAgent.Core;

// Dashboard composition root: registers the pipeline (legacy AgentServices container) and the adapters for the ports the intake needs.
// The intake itself is registered by services.AddSecAgentIntake(configuration) (SecAgent.Intake) and never sees these concrete types.

/// <summary>Adapter: <see cref="IPrRunLauncher"/> over the pipeline's RunService (exactly what POST /api/runs does).</summary>
sealed class RunServicePrRunLauncher(RunService runner) : IPrRunLauncher
{
    public async Task<Guid> StartPrRunAsync(string repo, int prNumber, CancellationToken ct) =>
        (await runner.StartAsync(repo, prNumber, fresh: false, blockForReview: true)).State.Run.RunId;
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
    public static IServiceCollection AddSecAgentPipeline(this IServiceCollection services, string repoRoot, string dataRoot, string sql)
    {
        services.AddSingleton(sp => AgentServices.Create(repoRoot, dataRoot, sql, sp.GetRequiredService<IExternalFindingSource>()));
        services.AddSingleton<RunService>();
        services.AddSingleton(sp => sp.GetRequiredService<AgentServices>().Masker);
        services.AddSingleton<IMessageQueue>(sp => sp.GetRequiredService<AgentServices>().Queue);
        services.AddSingleton<IFindingSchemaValidator>(sp => sp.GetRequiredService<AgentServices>().Validator);
        services.AddSingleton<IPrRunLauncher, RunServicePrRunLauncher>();
        services.AddSingleton<IRunAdmission, PipelineRunAdmission>();
        return services;
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
