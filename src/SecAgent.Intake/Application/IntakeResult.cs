using SecAgent.Abstractions.Intake;

namespace SecAgent.Intake.Application;

/// <summary>Outcome of an intake request: the HTTP status the webhook returns and the JSON body (also used by the Blob path).</summary>
/// <param name="RetryAfterSeconds">Set on retryable answers (503 in progress): the webhook sends it as Retry-After.</param>
public sealed record IntakeResult(int StatusCode, object Body, int? RetryAfterSeconds = null)
{
    public bool IsSuccess => StatusCode is 200 or 202;
    /// <summary>Nothing went wrong with the payload; try the same delivery again later (in progress, temporarily unavailable).</summary>
    public bool IsRetryable => StatusCode == 503;

    public static IntakeResult Rejected(int code, string error) => new(code, new { status = "rejected", error });

    /// <summary>Another delivery of the same payload holds the claim and has not finished: 503 + Retry-After, never "duplicate" (that
    /// delivery may still fail, and the producer must not stop retrying until a run was really requested).</summary>
    public static IntakeResult InProgress(IntakeRecord existing, int retryAfterSeconds) => new(503, new
    {
        status = "in_progress", intake_id = existing.IntakeId, idempotency_key = existing.Key, retry_after_seconds = retryAfterSeconds,
        error = "the same payload is being processed by another delivery; retry after the given delay",
    }, retryAfterSeconds);

    /// <summary>This delivery's claim was taken over by another delivery after the lease (fencing): it stopped without further side effects.
    /// 503 + Retry-After, so the producer retries and sees the new owner's result (in progress, accepted, or failed).</summary>
    public static IntakeResult ClaimLost(IntakeRecord record) => new(503, new
    {
        status = "in_progress", intake_id = record.IntakeId, idempotency_key = record.Key, retry_after_seconds = 1,
        error = "this delivery's claim was taken over by another delivery after Intake:ClaimLeaseSeconds; retry to get its result",
    }, 1);

    /// <summary>The key used up Intake:MaxClaimTakeovers and was marked failed for good: 409 (not retryable), send a new run id.</summary>
    public static IntakeResult TakeoversExhausted(IntakeRecord record) => new(409, new
    {
        status = "failed", intake_id = record.IntakeId, idempotency_key = record.Key, error = record.Detail,
    });

    /// <summary>Same key seen before: 200 duplicate when the body is identical (a retry), else 409 conflict.</summary>
    public static IntakeResult Duplicate(IntakeRecord existing, string bodySha) => existing.BodySha256 == bodySha
        ? new IntakeResult(200, new { status = "duplicate", intake_id = existing.IntakeId, idempotency_key = existing.Key, previous_status = existing.Status, run_ticket = existing.RunTicket })
        : Rejected(409, "a different payload was already accepted for this repo + head SHA + scanner + run id; send a new run id (include github.run_attempt)");
}
