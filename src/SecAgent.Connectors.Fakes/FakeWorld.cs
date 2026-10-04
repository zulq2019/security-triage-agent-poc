using System.Security.Cryptography;
using System.Text;
using SecAgent.Connectors.Secrets;

namespace SecAgent.Connectors.Fakes;

/// <summary>One recorded call to a fake: what was asked, by which tenant, in which order.</summary>
public sealed record RecordedInteraction(long Sequence, string TenantId, ConnectorKind Kind, string Operation, IReadOnlyDictionary<string, string?> Args);

/// <summary>Shared state of all fakes (singleton): per-tenant data, the interaction log and scheduled faults. Tests seed it, run the code under
/// test, then assert on <see cref="Interactions"/> and on the state. Deterministic: sequential ids, SHA-1 of the inputs, no clock reads.</summary>
public sealed class FakeConnectorWorld
{
    long _seq;
    readonly List<RecordedInteraction> _log = [];
    readonly Dictionary<string, Queue<Exception>> _faults = new(StringComparer.Ordinal);

    public FakeSourceControlState SourceControl { get; }
    public FakeIssueTrackerState IssueTracker { get; } = new();
    public FakeScannerSourceState ScannerSource { get; } = new();
    public FakeModelState Models { get; } = new();
    public FakeNotifierState Notifier { get; } = new();

    public FakeConnectorWorld() => SourceControl = new FakeSourceControlState();

    public IReadOnlyList<RecordedInteraction> Interactions { get { lock (_log) return _log.ToList(); } }

    public IReadOnlyList<RecordedInteraction> InteractionsFor(ConnectorKind kind, string? operation = null, string? tenantId = null) =>
        Interactions.Where(i => i.Kind == kind && (operation == null || i.Operation == operation) && (tenantId == null || i.TenantId.Equals(tenantId, StringComparison.OrdinalIgnoreCase))).ToList();

    /// <summary>The next <paramref name="times"/> calls of <paramref name="operation"/> (e.g. "pull_request.get") throw <paramref name="error"/>.</summary>
    public void FailNext(string operation, Exception error, int times = 1)
    {
        lock (_faults)
        {
            if (!_faults.TryGetValue(operation, out var q)) _faults[operation] = q = new();
            for (var i = 0; i < times; i++) q.Enqueue(error);
        }
    }

    internal void Record(string tenant, ConnectorKind kind, string operation, params (string Key, object? Value)[] args)
    {
        lock (_faults)
            if (_faults.TryGetValue(operation, out var q) && q.Count > 0)
            {
                var e = q.Dequeue();
                lock (_log) _log.Add(new(++_seq, tenant, kind, operation + ":fault", args.ToDictionary(a => a.Key, a => a.Value?.ToString())));
                throw e;
            }
        lock (_log) _log.Add(new(++_seq, tenant, kind, operation, args.ToDictionary(a => a.Key, a => a.Value?.ToString())));
    }

    public void ClearInteractions() { lock (_log) _log.Clear(); }

    internal static string Sha(params object?[] parts) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(string.Join("|", parts)))).ToLowerInvariant();
}

/// <summary>Secret scheme "memory": values set by tests (never real secrets).</summary>
public sealed class InMemorySecretSource : ISecretSource
{
    readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    public string Scheme => "memory";
    public void Set(string name, string value) { lock (_values) _values[name] = value; }
    public ValueTask<string?> TryGetAsync(string name, CancellationToken ct) { lock (_values) return ValueTask.FromResult(_values.GetValueOrDefault(name)); }
}
