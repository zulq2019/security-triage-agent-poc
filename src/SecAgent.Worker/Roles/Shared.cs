using Microsoft.Extensions.DependencyInjection.Extensions;
using SecAgent.Abstractions;
using SecAgent.Agents;
using SecAgent.Core;
using SecAgent.Hosting;

namespace SecAgent.Worker.Roles;

/// <summary>Registrations several roles share.</summary>
static class RoleServices
{
    /// <summary>Rules-as-code snapshot (rules/ under the content root) and the canonical finding schema validator. No model provider:
    /// roles that do not call a model must not need model settings or keys.</summary>
    public static IServiceCollection AddRulesAndSchema(this IServiceCollection services, AgentRoleContext ctx)
    {
        services.TryAddSingleton(_ => ConfigSnapshot.Load(Path.Combine(ctx.ContentRoot, "rules")));
        services.TryAddSingleton<JsonSchemaCache>();
        services.TryAddSingleton<SchemaValidator>();
        services.TryAddSingleton<IFindingSchemaValidator>(sp => sp.GetRequiredService<SchemaValidator>());
        return services;
    }

    /// <summary>Write-once local blob store under the data root (raw / evidence containers). Azure Blob for workers is an open item.</summary>
    public static IServiceCollection AddLocalBlobStore(this IServiceCollection services, AgentRoleContext ctx)
    {
        services.TryAddSingleton(_ => new LocalBlobStore(Path.Combine(ctx.DataRoot, "blob")));
        return services;
    }

    public static string RequiredSql(this AgentRoleContext ctx) =>
        ctx.Configuration["SECAGENT_SQL"] is { Length: > 0 } sql ? sql
            : throw new AgentHostConfigurationException($"agent '{ctx.Spec.Name}' needs SECAGENT_SQL (in Azure the Bicep sets a managed-identity connection string)");
}

/// <summary>Null Object for <see cref="IPrRunLauncher"/> in hosts that only accept and enqueue (the intake role): starting a run is the
/// orchestrator's job, so this refuses.</summary>
sealed class RefusingPrRunLauncher : IPrRunLauncher
{
    public Task<PrRunStart> StartPrRunAsync(string repo, int prNumber, string? expectedHeadSha, CancellationToken ct) =>
        throw new InvalidOperationException("this agent does not start runs (the orchestrator consumes the run queue)");
}

/// <summary>Null Object for <see cref="IRunAdmission"/>: never admits (the dispatcher is disabled in this role anyway).</summary>
sealed class ClosedRunAdmission : IRunAdmission
{
    public bool CanStartRun => false;
}
