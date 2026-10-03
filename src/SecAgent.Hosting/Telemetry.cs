using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace SecAgent.Hosting;

/// <summary>OpenTelemetry for a worker: traces (the pipeline's sources + the consumer spans), metrics (SecAgent.Agent + ASP.NET Core +
/// runtime-free defaults) and logs. Exported over OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set (Container Apps' managed OpenTelemetry agent
/// or a collector forwards to Application Insights); console with SECAGENT_OTEL_CONSOLE=1. service.name = OTEL_SERVICE_NAME (Bicep sets
/// ca-&lt;agent&gt;-&lt;env&gt;) or secagent-&lt;agent&gt;.</summary>
public static class AgentTelemetry
{
    public static readonly string[] TraceSources = [SecAgent.Core.Telemetry.SourceName, "SecAgent.GenAI", "Microsoft.Agents.AI.Workflows", "Experimental.Microsoft.Agents.AI"];

    public static IServiceCollection AddSecAgentAgentTelemetry(this IServiceCollection services, AgentRoleContext context)
    {
        var cfg = context.Configuration;
        var serviceName = cfg["OTEL_SERVICE_NAME"] is { Length: > 0 } n ? n : $"secagent-{context.Spec.Name}";
        var console = cfg["SECAGENT_OTEL_CONSOLE"] == "1";
        var otel = services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(serviceName, serviceNamespace: "secagent")
                .AddAttributes([new("secagent.agent", context.Spec.Name), new("secagent.transport", context.Options.Transport)]))
            .WithTracing(t =>
            {
                t.AddSource(TraceSources);
                if (console) t.AddConsoleExporter();
            })
            .WithMetrics(m => m.AddMeter(AgentMetrics.MeterName, "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Server.Kestrel"))
            .WithLogging();
        if (cfg["OTEL_EXPORTER_OTLP_ENDPOINT"] is { Length: > 0 }) otel.UseOtlpExporter();
        return services;
    }
}
