using SecAgent.Abstractions;
using SecAgent.Hosting;
using SecAgent.Intake;
using SecAgent.Intake.Azure;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Http;

namespace SecAgent.Worker.Roles;

/// <summary>intake: the HMAC-authenticated SARIF / Black Duck endpoint (POST /api/intake/{format}). Accepts, stores the raw file, records the
/// ledger entry and enqueues a run request. It never starts runs itself: the dispatcher is forced off and the run ports are Null Objects.
/// Same composition root as the dashboard (AddSecAgentIntake), so behaviour is identical in both modes.</summary>
public sealed class IntakeRole : IAgentRoleModule, IAgentRoleEndpoints
{
    public string Role => "intake";

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        // Registered before AddSecAgentIntake, so the intake's own defaults (raw store, ledger, drop folder) derive from this StorageRoot.
        services.PostConfigure<IntakeOptions>(o =>
        {
            if (string.IsNullOrWhiteSpace(o.StorageRoot)) o.StorageRoot = context.DataRoot;
            o.DispatcherEnabled = false;
        });
        services.AddRulesAndSchema(context);
        services.AddSingleton<IPrRunLauncher, RefusingPrRunLauncher>();
        services.AddSingleton<IRunAdmission, ClosedRunAdmission>();
        services.AddSecAgentIntake(context.Configuration);
        services.AddSecAgentIntakeAzure(context.Configuration);
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints) => endpoints.MapSecAgentIntake();
}
