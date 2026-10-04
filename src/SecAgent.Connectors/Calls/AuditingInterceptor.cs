using System.Diagnostics;

namespace SecAgent.Connectors.Calls;

/// <summary>Outermost decorator: one trace span and one <see cref="ConnectorAuditEvent"/> per call (tenant, connector, operation, target,
/// outcome, duration, model token usage). Records ids and outcomes only, never payloads or secret values.</summary>
public sealed class AuditingInterceptor(IEnumerable<IConnectorAuditSink> sinks, TimeProvider time) : IConnectorCallInterceptor
{
    public static readonly ActivitySource Source = new("SecAgent.Connectors");
    readonly IReadOnlyList<IConnectorAuditSink> _sinks = sinks.ToList();

    public int Order => 0;
    public bool AppliesTo(ConnectorDescriptor descriptor) => true;

    public async Task<T> InterceptAsync<T>(ConnectorCallContext context, ConnectorCall call, Func<CancellationToken, Task<T>> next, CancellationToken ct)
    {
        var d = context.Descriptor;
        using var span = Source.StartActivity($"connector {d.Id} {call.Operation}", ActivityKind.Client);
        span?.SetTag("secagent.tenant", context.Connection.TenantId);
        span?.SetTag("secagent.connector", d.Id);
        span?.SetTag("secagent.connector.kind", d.Kind.ToString());
        span?.SetTag("secagent.connector.operation", call.Operation);
        var start = time.GetTimestamp();
        try
        {
            var result = await next(ct);
            IReadOnlyDictionary<string, long>? metrics = null;
            if (result is ModelResponse m)
            {
                metrics = new Dictionary<string, long> { ["tokens_in"] = m.Usage.InputTokens, ["tokens_out"] = m.Usage.OutputTokens };
                span?.SetTag("gen_ai.usage.input_tokens", m.Usage.InputTokens);
                span?.SetTag("gen_ai.usage.output_tokens", m.Usage.OutputTokens);
            }
            Record(context, call, "ok", start, null, metrics);
            return result;
        }
        catch (Exception e)
        {
            var outcome = e is ForbiddenConnectorOperationException ? "rejected" : e is OperationCanceledException ? "cancelled" : "failed";
            span?.SetStatus(ActivityStatusCode.Error, e.GetType().Name);
            Record(context, call, outcome, start, $"{e.GetType().Name}: {Truncate(e.Message, 300)}", null);
            throw;
        }
    }

    void Record(ConnectorCallContext c, ConnectorCall call, string outcome, long start, string? error, IReadOnlyDictionary<string, long>? metrics)
    {
        var evt = new ConnectorAuditEvent(time.GetUtcNow(), c.Connection.TenantId, c.Descriptor.Kind, c.Descriptor.Id, call.Operation, call.Target, outcome,
            (long)time.GetElapsedTime(start).TotalMilliseconds, error, Activity.Current?.TraceId.ToString(), metrics);
        foreach (var sink in _sinks)
        {
            try { sink.Record(evt); } catch { /* auditing never fails the call */ }
        }
    }

    static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
