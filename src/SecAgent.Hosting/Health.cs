using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace SecAgent.Hosting;

public static class AgentHealthTags
{
    public const string Ready = "ready";
}

/// <summary>Readiness: the role resolved and its context built.</summary>
public sealed class AgentRoleHealthCheck(SelectedAgentRole role) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default) =>
        Task.FromResult(HealthCheckResult.Healthy($"role={role.Context.Spec.Name} transport={role.Transport} consumes=[{string.Join(",", role.Context.ConsumedEntities)}]"));
}

/// <summary>Readiness: the queue transport is usable.</summary>
public sealed class AgentTransportHealthCheck(IAgentQueueTransport transport) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var (ok, detail) = await transport.CheckAsync(ct);
        return ok ? HealthCheckResult.Healthy(detail) : HealthCheckResult.Unhealthy(detail);
    }
}

/// <summary>Readiness: the consumer started and is not draining.</summary>
public sealed class AgentConsumerHealthCheck(AgentReadiness readiness) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default) =>
        Task.FromResult(readiness.IsDraining ? HealthCheckResult.Unhealthy("draining (shutdown in progress)")
            : readiness.IsStarted ? HealthCheckResult.Healthy("consuming") : HealthCheckResult.Unhealthy("starting"));
}

public static class AgentHealthEndpoints
{
    /// <summary>/healthz = liveness (the process answers; no dependency checks, so a slow broker never gets a replica killed).
    /// /readyz = readiness (role, transport, consumer). Both return a small JSON body.</summary>
    public static IEndpointRouteBuilder MapSecAgentHealth(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapHealthChecks("/healthz", new HealthCheckOptions { Predicate = _ => false, ResponseWriter = WriteJson });
        endpoints.MapHealthChecks("/readyz", new HealthCheckOptions { Predicate = c => c.Tags.Contains(AgentHealthTags.Ready), ResponseWriter = WriteJson });
        return endpoints;
    }

    static Task WriteJson(HttpContext http, HealthReport report)
    {
        http.Response.ContentType = "application/json";
        return http.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            checks = report.Entries.Select(e => new { name = e.Key, status = e.Value.Status.ToString(), detail = e.Value.Description }),
        }));
    }
}

/// <summary>`secagent-worker probe [url]`: HTTP GET for container HEALTHCHECKs. Chiselled images have no shell or curl, so the worker
/// binary probes itself. Exit 0 = 2xx.</summary>
public static class HealthProbe
{
    public static async Task<int> RunAsync(string? url)
    {
        url ??= $"http://127.0.0.1:{(Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS") ?? "8080").Split(';', ',')[0]}/healthz";
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var res = await http.GetAsync(url);
            return res.IsSuccessStatusCode ? 0 : 1;
        }
        catch { return 1; }
    }
}
