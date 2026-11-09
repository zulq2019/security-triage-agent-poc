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
    /// <summary>The claim token this delivery holds (set by the claim step). Every ledger write after the claim is fenced with it
    /// (<see cref="IIntakeLedger.TryUpdate"/>); a write that reports anything but Updated means the claim was taken over: stop.</summary>
    public string? ClaimToken { get; set; }
    /// <summary>True while this delivery holds an unfinished claim (claimed, run not yet requested).</summary>
    public bool HoldsClaim => ClaimToken != null && Record is { Status: IntakeStatus.Claimed };
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
/// marked <see cref="IntakeStatus.Failed"/>, so the producer's retry takes it over at once instead of being told "duplicate".
/// <para>Fencing: while this delivery holds the claim, the pipeline renews it (a compare-and-set on the claim token, which also extends
/// the lease) before every further step, and every step writes the record only through the same compare-and-set. When the claim was
/// taken over (this delivery was slower than Intake:ClaimLeaseSeconds), the delivery stops with no further side effects (nothing stored,
/// enqueued or written) and answers 503 + Retry-After; the producer's retry sees the new owner's result.</para></summary>
public sealed class IntakePipeline(IEnumerable<IIntakeStep> steps, IIntakeLedger ledger, SecretMasker masker, ILogger<IntakePipeline> log) : IIntakeAcceptor
{
    readonly IIntakeStep[] _steps = steps.OrderBy(s => s.Order).ToArray();

    public async Task<IntakeResult> AcceptAsync(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via, CancellationToken ct)
    {
        var ctx = new IntakeContext(meta, body, via);
        try
        {
            foreach (var step in _steps)
            {
                if (ctx.HoldsClaim && !Renew(ctx)) return IntakeResult.ClaimLost(ctx.Record!);
                if (await step.ExecuteAsync(ctx, ct) is { } result) return result;
            }
            throw new InvalidOperationException("intake pipeline ended without a result (no step produced one)");
        }
        catch (IntakeRejectedException e)
        {
            log.LogWarning("intake rejected ({Status}) {Repo}@{Sha} {Scanner} run {RunId}: {Reason}",
                e.StatusCode, meta.Repo, meta.HeadSha[..7], meta.Scanner, meta.RunId, masker.Mask(e.Message, false));
            return ReleaseClaim(ctx, $"rejected ({e.StatusCode}): {e.Message}") ? IntakeResult.Rejected(e.StatusCode, e.Message) : IntakeResult.ClaimLost(ctx.Record!);
        }
        catch (Exception e)
        {
            var cancelled = e is OperationCanceledException;
            if (!ReleaseClaim(ctx, cancelled ? "delivery cancelled" : $"processing failed: {e.GetType().Name}") && !cancelled) return IntakeResult.ClaimLost(ctx.Record!);
            throw;
        }
    }

    /// <summary>Fenced heartbeat: rewrites the record with this delivery's claim token (and a fresh UpdatedAt, which extends the lease).</summary>
    bool Renew(IntakeContext ctx)
    {
        if (ledger.TryUpdate(ctx.Record!, ctx.ClaimToken!) == LedgerWriteResult.Updated) return true;
        LogClaimLost(ctx);
        return false;
    }

    /// <summary>Marks this delivery's claim failed (only while it is still an unfinished claim; a queued record is left alone). Fenced:
    /// a delivery whose claim was taken over writes nothing. Returns false when the claim was lost (the caller answers 503).</summary>
    bool ReleaseClaim(IntakeContext ctx, string reason)
    {
        if (!ctx.HoldsClaim) return true;
        var record = ctx.Record!;
        try
        {
            record.Status = IntakeStatus.Failed;
            record.Detail = masker.Mask(reason.Length <= 300 ? reason : reason[..300], false);
            if (ledger.TryUpdate(record, ctx.ClaimToken!) == LedgerWriteResult.Updated) return true;
            LogClaimLost(ctx);
            return false;
        }
        catch (Exception e)
        {
            log.LogError("intake {IntakeId}: could not release the claim (it frees up after the lease): {Error}", record.IntakeId, masker.Mask(e.Message, false));
            return true;
        }
    }

    void LogClaimLost(IntakeContext ctx) =>
        log.LogWarning("intake {IntakeId}: claim was taken over by another delivery (lease expired); this delivery stopped without further writes",
            ctx.Record!.IntakeId);
}
