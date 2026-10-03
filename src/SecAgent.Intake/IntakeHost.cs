using SecAgent.Agents;
using SecAgent.Intake.Blob;
using SecAgent.Intake.Parsers;
using SecAgent.Intake.Runs;
using SecAgent.Intake.Storage;

namespace SecAgent.Intake;

/// <summary>Composition root for the intake (used by the dashboard process). Everything is behind an interface so the cloud
/// versions slot in: IRawFindingStore → Blob, IIntakeLedger → SQL/Table, IRunStarter's queue → Service Bus, IIntakeAuthenticator → OIDC.</summary>
public sealed class IntakeHost
{
    public required IntakeOptions Options { get; init; }
    public required IntakeService Service { get; init; }
    public required IIntakeAuthenticator Authenticator { get; init; }
    public required IIntakeLedger Ledger { get; init; }
    public required IExternalFindingSource ExternalFindings { get; init; }
    public required IntakeRunDispatcher Dispatcher { get; init; }
    public LocalFileDropWatcher? DropWatcher { get; init; }

    /// <param name="startPrRun">Starts a PR run exactly like POST /api/runs; returns the run id.</param>
    /// <param name="canStart">False while a run is active or the kill switch is on.</param>
    public static IntakeHost Create(IntakeOptions o, AgentServices s, Func<IntakeRunRequest, CancellationToken, Task<Guid>> startPrRun, Func<bool> canStart, Action<string>? log = null)
    {
        var ledger = new FileIntakeLedger(Path.Combine(s.DataRoot, "intake", "ledger"));
        var raw = new LocalRawFindingStore(s.Blob);
        var parsers = new IFindingParser[] { new SarifParser(o, s.Masker), new BlackDuckRapidScanParser(o, s.Masker) };
        var service = new IntakeService(o, parsers, raw, ledger, new QueueRunStarter(s.Queue), s.Validator, log);
        return new IntakeHost
        {
            Options = o, Service = service, Ledger = ledger,
            Authenticator = new HmacIntakeAuthenticator(() => o.HmacSecret, o.TimestampToleranceSeconds),
            ExternalFindings = new IntakeExternalFindingSource(ledger, raw),
            Dispatcher = new IntakeRunDispatcher(s.Queue, ledger, startPrRun, canStart, log),
            DropWatcher = o.DropWatcherEnabled ? new LocalFileDropWatcher(o.DropFolder, reader => new IntakeFromBlobHandler(service, reader), log) : null,
        };
    }
}
