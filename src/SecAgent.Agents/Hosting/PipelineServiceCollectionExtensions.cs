using Microsoft.Extensions.DependencyInjection;
using SecAgent.Abstractions;
using SecAgent.Agents.Workflow;
using SecAgent.Core;

namespace SecAgent.Agents.Hosting;

/// <summary>Adapter: <see cref="IPrRunLauncher"/> over the pipeline's RunService (exactly what POST /api/runs does).</summary>
public sealed class RunServicePrRunLauncher(RunService runner) : IPrRunLauncher
{
    public async Task<Guid> StartPrRunAsync(string repo, int prNumber, CancellationToken ct) =>
        (await runner.StartAsync(repo, prNumber, fresh: false, blockForReview: true)).State.Run.RunId;
}

/// <summary>Adapter: <see cref="IRunAdmission"/> = kill switch off and no run active (one run at a time per process).</summary>
public sealed class PipelineRunAdmission(AgentServices svc) : IRunAdmission
{
    public bool CanStartRun => !svc.Kill.IsOn && !RunService.AnyActive;
}

/// <summary>Pipeline composition shared by every host that runs the Agent Framework workflow: the dashboard (single-process dev mode)
/// and the orchestrator role of the per-agent worker host (containers). Moved here from the dashboard so both hosts register the
/// pipeline the same way.</summary>
public static class PipelineServiceCollectionExtensions
{
    /// <summary>Pipeline services + pipeline-side adapters for the intake ports. Call before AddSecAgentIntake so the intake shares the
    /// pipeline's SecretMasker and schema validator (its TryAdd registrations then keep these).</summary>
    /// <param name="shareQueue">True (dashboard): the intake uses the pipeline's in-process queue. False (worker host): the host has
    /// already registered a transport-specific <see cref="IMessageQueue"/> (for example the shared file queue) and keeps it.</param>
    public static IServiceCollection AddSecAgentPipeline(this IServiceCollection services, string repoRoot, string dataRoot, string sql, bool shareQueue = true)
    {
        services.AddSingleton(sp => AgentServices.Create(repoRoot, dataRoot, sql, sp.GetRequiredService<IExternalFindingSource>()));
        services.AddSingleton<RunService>();
        services.AddSingleton(sp => sp.GetRequiredService<AgentServices>().Masker);
        if (shareQueue) services.AddSingleton<IMessageQueue>(sp => sp.GetRequiredService<AgentServices>().Queue);
        services.AddSingleton<IFindingSchemaValidator>(sp => sp.GetRequiredService<AgentServices>().Validator);
        services.AddSingleton<IPrRunLauncher, RunServicePrRunLauncher>();
        services.AddSingleton<IRunAdmission, PipelineRunAdmission>();
        return services;
    }
}
