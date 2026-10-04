namespace SecAgent.Connectors;

/// <summary>One connector call, as written by the auditing decorator (SDD 9.8 "Audited": the runtime, not the plug-in, writes it).
/// Holds operation names and target ids only: never payloads, tokens or secret references' values.</summary>
public sealed record ConnectorAuditEvent(
    DateTimeOffset At,
    string TenantId,
    ConnectorKind Kind,
    string ConnectorId,
    string Operation,
    string? Target,
    string Outcome,            // ok | failed | rejected
    long DurationMs,
    string? Error = null,
    string? TraceId = null,
    IReadOnlyDictionary<string, long>? Metrics = null);   // e.g. tokens_in / tokens_out for model calls

public interface IConnectorAuditSink
{
    void Record(ConnectorAuditEvent evt);
}
