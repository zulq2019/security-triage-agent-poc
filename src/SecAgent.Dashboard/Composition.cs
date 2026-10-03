// Dashboard composition root. The pipeline (legacy AgentServices container + the adapters for the ports the intake needs) is registered by
// services.AddSecAgentPipeline(...) from SecAgent.Agents.Hosting, shared with the per-agent worker host (src/SecAgent.Worker).
// The intake itself is registered by services.AddSecAgentIntake(configuration) (SecAgent.Intake) and never sees these concrete types.

static class DashboardComposition
{
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
