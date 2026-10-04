using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Polly;
using SecAgent.Connectors.Configuration;
using System.Threading.RateLimiting;

namespace SecAgent.Connectors.Http;

/// <summary>Named HttpClients for REST connectors with the Microsoft.Extensions.Http.Resilience handler (a DelegatingHandler decorator):
/// total timeout → token-bucket rate limit → retry (exponential backoff + jitter, honours Retry-After, safe methods only) → circuit breaker
/// → per-attempt timeout. One pipeline instance per tenant + host, so tenants do not share breakers or rate limits.</summary>
public static class ConnectorHttp
{
    public static readonly HttpRequestOptionsKey<string> TenantOption = new("secagent.tenant");

    public static string ClientName(string connectorId) => "secagent.connector." + connectorId;

    public static IHttpClientBuilder AddConnectorHttpClient(this IServiceCollection services, string connectorId)
    {
        var builder = services.AddHttpClient(ClientName(connectorId), c => c.Timeout = Timeout.InfiniteTimeSpan);   // the pipeline owns timeouts
        builder.AddResilienceHandler("secagent-connector", (pipeline, context) =>
        {
            var o = context.ServiceProvider.GetRequiredService<IOptionsMonitor<ConnectorOptions>>().CurrentValue.Resilience;
            pipeline.AddTimeout(o.TotalTimeout);
            pipeline.AddRateLimiter(new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
            {
                TokenLimit = o.PermitsPerSecond, TokensPerPeriod = o.PermitsPerSecond, ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                QueueLimit = o.QueueLimit, QueueProcessingOrder = QueueProcessingOrder.OldestFirst, AutoReplenishment = true,
            }));
            if (o.MaxRetryAttempts > 0)
            {
                var retry = new HttpRetryStrategyOptions
                {
                    MaxRetryAttempts = o.MaxRetryAttempts, Delay = o.BaseDelay, BackoffType = DelayBackoffType.Exponential, UseJitter = o.UseJitter,
                    ShouldRetryAfterHeader = true,
                };
                retry.DisableForUnsafeHttpMethods();   // POST / PATCH / PUT / DELETE are never retried by the transport
                pipeline.AddRetry(retry);
            }
            pipeline.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
            {
                FailureRatio = o.CircuitBreakerFailureRatio, MinimumThroughput = o.CircuitBreakerMinimumThroughput,
                SamplingDuration = o.CircuitBreakerSamplingDuration, BreakDuration = o.CircuitBreakerBreakDuration,
            });
            pipeline.AddTimeout(o.AttemptTimeout);
        }).SelectPipelineBy(_ => request =>
            (request.Options.TryGetValue(TenantOption, out var tenant) ? tenant : "-") + "|" + request.RequestUri?.Authority);
        return builder;
    }
}
