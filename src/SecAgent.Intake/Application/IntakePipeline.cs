using Microsoft.Extensions.Logging;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Application;

/// <summary>Accepts an authenticated payload with validated metadata. Shared by the webhook and the Blob path.</summary>
public interface IIntakeAcceptor
{
    Task<IntakeResult> AcceptAsync(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via, CancellationToken ct);
}

/// <summary>State passed along the chain of <see cref="IIntakeStep"/>s for one payload.</summary>
public sealed class IntakeContext(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via)
{
    public IntakeMetadata Meta { get; } = meta;
    public ReadOnlyMemory<byte> Body { get; } = body;
    public string Via { get; } = via;
    public string Key => Meta.IdempotencyKey;
    public string BodySha256 { get; set; } = "";
    public IFindingParser? Parser { get; set; }
    public ParseOutcome? Parsed { get; set; }
    public IntakeRecord? Record { get; set; }
    public RawRef? Raw { get; set; }
    public RunTicket? Ticket { get; set; }

    public T Require<T>(T? value, string what) where T : class => value ?? throw new InvalidOperationException($"intake pipeline: {what} not set by an earlier step");
}

/// <summary>Chain of responsibility: one step of the accept pipeline. Return null to continue, or a result to stop (duplicate, accepted).
/// Throw <see cref="IntakeRejectedException"/> to reject. Steps run in ascending <see cref="Order"/>; add a step (e.g. malware scan)
/// by registering another implementation.</summary>
public interface IIntakeStep
{
    int Order { get; }
    Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct);
}

/// <summary>Runs the registered steps in order: limits → duplicate fast path → parse → claim key → store raw → canonical findings → enqueue.
/// Turns rejections into results (and logs them, masked). Nothing is stored for a payload rejected before the claim.
/// If anything fails after the claim and before a run was requested (rejection, storage or queue error, cancellation), the claim is
/// marked <see cref="IntakeStatus.Failed"/>, so the producer's retry takes it over at once instead of being told "duplicate".</summary>
public sealed class IntakePipeline(IEnumerable<IIntakeStep> steps, IIntakeLedger ledger, SecretMasker masker, ILogger<IntakePipeline> log) : IIntakeAcceptor
{
    readonly IIntakeStep[] _steps = steps.OrderBy(s => s.Order).ToArray();

    public async Task<IntakeResult> AcceptAsync(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via, CancellationToken ct)
    {
        var ctx = new IntakeContext(meta, body, via);
        try
        {
            foreach (var step in _steps)
                if (await step.ExecuteAsync(ctx, ct) is { } result) return result;
            throw new InvalidOperationException("intake pipeline ended without a result (no step produced one)");
        }
        catch (IntakeRejectedException e)
        {
            log.LogWarning("intake rejected ({Status}) {Repo}@{Sha} {Scanner} run {RunId}: {Reason}",
                e.StatusCode, meta.Repo, meta.HeadSha[..7], meta.Scanner, meta.RunId, masker.Mask(e.Message, false));
            ReleaseClaim(ctx, $"rejected ({e.StatusCode}): {e.Message}");
            return IntakeResult.Rejected(e.StatusCode, e.Message);
        }
        catch (Exception e)
        {
            ReleaseClaim(ctx, e is OperationCanceledException ? "delivery cancelled" : $"processing failed: {e.GetType().Name}");
            throw;
        }
    }

    /// <summary>Marks this delivery's claim failed (only while it is still an unfinished claim; a queued record is left alone).</summary>
    void ReleaseClaim(IntakeContext ctx, string reason)
    {
        if (ctx.Record is not { Status: IntakeStatus.Claimed } record) return;
        try
        {
            record.Status = IntakeStatus.Failed;
            record.Detail = masker.Mask(reason.Length <= 300 ? reason : reason[..300], false);
            ledger.Update(record);
        }
        catch (Exception e) { log.LogError("intake {IntakeId}: could not release the claim (it frees up after the lease): {Error}", record.IntakeId, masker.Mask(e.Message, false)); }
    }
}
