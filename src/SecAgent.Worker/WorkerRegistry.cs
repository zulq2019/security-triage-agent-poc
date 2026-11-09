using SecAgent.Hosting;
using SecAgent.Hosting.Azure;
using SecAgent.Worker.Roles;

namespace SecAgent.Worker;

/// <summary>Every role and queue transport this host can run, listed once. The host picks one of each by configuration
/// (SECAGENT_AGENT, SECAGENT_QUEUE). A new agent = an entry in deploy/agents.json + a module class + one line here.
/// agent-api is not here: it is the dashboard host (secagent serve), deploy/agents.json host "dashboard".</summary>
public static class WorkerRegistry
{
    public static AgentHostRegistry Create() => new AgentHostRegistry()
        .AddTransport(new InProcessTransportModule())
        .AddTransport(new FileSystemTransportModule())
        .AddTransport(new ServiceBusTransportModule())
        .AddRole(new IntakeRole())
        .AddRole(new OrchestratorRole())
        .AddRole(new ScannerRole())
        .AddRole(new PipelineStepRole("triage"))
        .AddRole(new PipelineStepRole("fixer-library"))
        .AddRole(new PipelineStepRole("fixer-secret"))
        .AddRole(new PipelineStepRole("fixer-code"))
        .AddRole(new PipelineStepRole("fixer-binary"))
        .AddRole(new PipelineStepRole("verifier"))
        .AddRole(new AuditWriterRole());
}
