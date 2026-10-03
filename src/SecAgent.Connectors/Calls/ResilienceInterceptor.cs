using System.Net;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using Polly;
using Polly.CircuitBreaker;
using Polly.RateLimiting;
using Polly.Registry;
using Polly.Retry;
using Polly.Timeout;
using SecAgent.Connectors.Configuration;

namespace SecAgent.Connectors.Calls;

/// <summary>Call-level resilience decorator (Polly) for connectors that do not go through HttpClient (model SDK, git CLI, in-memory fakes):
/// token-bucket rate limit, retry with exponential backoff + jitter for idempotent operations only, circuit breaker and per-attempt timeout.
/// One pipeline per tenant + connector, so one tenant's failing system never trips another tenant's breaker.
/// REST connectors get the same policies from the HTTP resilience handler instead (see ConnectorHttp), never both.</summary>
public sealed class ResilienceInterceptor(IOptionsMonitor<ConnectorOptions> options, TimeProvider time) : IConnectorCallInterceptor, IDisposable
{
    static readonly ResiliencePropertyKey<bool> IdempotentKey = new("secagent.connector.idempotent");
    readonly ResiliencePipelineRegistry<string> _registry = new();

    public int Order => 10;
    public bool AppliesTo(ConnectorDescriptor descriptor) => descriptor.Transport != ConnectorTransport.Http;

    public async Task<T> InterceptAsync<T>(ConnectorCallContext context, ConnectorCall call, Func<CancellationToken, Task<T>> next, CancellationToken ct)
    {
        var key = $"{context.Connection.TenantId}|{context.Descriptor.Kind}|{context.Descriptor.Id}";
        var pipeline = _registry.GetOrAddPipeline(key, b => Configure(b, options.CurrentValue.Resilience, context.Descriptor.Kind));
        var rc = ResilienceContextPool.Shared.Get(key, ct);
        rc.Properties.Set(IdempotentKey, call.Idempotent);
        try
        {
            return await pipeline.ExecuteAsync(static async (c, op) => await op(c.CancellationToken).ConfigureAwait(false), rc, next);
        }
        catch (BrokenCircuitException e)
        {
            throw new ConnectorException($"{context.Descriptor.Id}: circuit open for tenant '{context.Connection.TenantId}', calls paused", true, null, e.RetryAfter, e);
        }
        catch (RateLimiterRejectedException e)
        {
            throw new ConnectorException($"{context.Descriptor.Id}: rate limit reached for tenant '{context.Connection.TenantId}'", true, HttpStatusCode.TooManyRequests, e.RetryAfter, e);
        }
        catch (TimeoutRejectedException e)
        {
            throw new ConnectorException($"{context.Descriptor.Id} {call.Operation}: timed out after {e.Timeout.TotalSeconds:0.#}s", true, null, null, e);
        }
        finally { ResilienceContextPool.Shared.Return(rc); }
    }

    void Configure(ResiliencePipelineBuilder b, ConnectorResilienceOptions o, ConnectorKind kind)
    {
        b.TimeProvider = time;
        b.AddRateLimiter(new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = o.PermitsPerSecond, TokensPerPeriod = o.PermitsPerSecond, ReplenishmentPeriod = TimeSpan.FromSeconds(1),
            QueueLimit = o.QueueLimit, QueueProcessingOrder = QueueProcessingOrder.OldestFirst, AutoReplenishment = true,
        }));
        if (o.MaxRetryAttempts > 0)
            b.AddRetry(new RetryStrategyOptions
            {
                MaxRetryAttempts = o.MaxRetryAttempts, Delay = o.BaseDelay, BackoffType = DelayBackoffType.Exponential, UseJitter = o.UseJitter,
                ShouldHandle = a => ValueTask.FromResult(a.Outcome.Exception is { } e && IsTransient(e) && a.Context.Properties.GetValue(IdempotentKey, false)),
                DelayGenerator = a => ValueTask.FromResult(a.Outcome.Exception is ConnectorException { RetryAfter: { } ra } ? (TimeSpan?)ra : null),
            });
        b.AddCircuitBreaker(new CircuitBreakerStrategyOptions
        {
            FailureRatio = o.CircuitBreakerFailureRatio, MinimumThroughput = o.CircuitBreakerMinimumThroughput,
            SamplingDuration = o.CircuitBreakerSamplingDuration, BreakDuration = o.CircuitBreakerBreakDuration,
            ShouldHandle = a => ValueTask.FromResult(a.Outcome.Exception is { } e && IsTransient(e)),
        });
        // A model completion legitimately takes minutes on a local model; other calls get the short attempt timeout.
        b.AddTimeout(kind == ConnectorKind.ModelProvider ? o.ModelAttemptTimeout : o.AttemptTimeout);
    }

    public static bool IsTransient(Exception e) => e switch
    {
        ConnectorException ce => ce.IsTransient,
        HttpRequestException or TimeoutException or TimeoutRejectedException or IOException => true,
        _ => false,
    };

    public void Dispose() => _registry.Dispose();
}
