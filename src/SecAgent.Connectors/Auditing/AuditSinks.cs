using Microsoft.Extensions.Logging;

namespace SecAgent.Connectors.Auditing;

/// <summary>Structured log line per connector call (Application Insights / Log Analytics in Azure).</summary>
public sealed class LoggingConnectorAuditSink(ILogger<LoggingConnectorAuditSink> log) : IConnectorAuditSink
{
    public void Record(ConnectorAuditEvent e)
    {
        var level = e.Outcome == "ok" ? LogLevel.Information : LogLevel.Warning;
        log.Log(level, "connector {Connector} {Operation} tenant={Tenant} target={Target} outcome={Outcome} {DurationMs}ms {Error}",
            e.ConnectorId, e.Operation, e.TenantId, e.Target, e.Outcome, e.DurationMs, e.Error);
    }
}

/// <summary>Bounded in-memory audit trail (newest last): the dashboard's connector activity view and test assertions.
/// The target design writes ConnectorAuditEvent rows to SQL per tenant (SDD 9.7); that is a further sink, no other change.</summary>
public sealed class InMemoryConnectorAuditLog(int capacity = 2000) : IConnectorAuditSink
{
    readonly LinkedList<ConnectorAuditEvent> _events = new();

    public void Record(ConnectorAuditEvent e)
    {
        lock (_events)
        {
            _events.AddLast(e);
            while (_events.Count > capacity) _events.RemoveFirst();
        }
    }

    public IReadOnlyList<ConnectorAuditEvent> Snapshot(string? tenantId = null)
    {
        lock (_events) return _events.Where(e => tenantId == null || e.TenantId.Equals(tenantId, StringComparison.OrdinalIgnoreCase)).ToList();
    }
}
