using SecAgent.Abstractions.Intake;

namespace SecAgent.Intake.Application;

/// <summary>Outcome of an intake request: the HTTP status the webhook returns and the JSON body (also used by the Blob path).</summary>
public sealed record IntakeResult(int StatusCode, object Body)
{
    public bool IsSuccess => StatusCode is 200 or 202;

    public static IntakeResult Rejected(int code, string error) => new(code, new { status = "rejected", error });

    /// <summary>Same key seen before: 200 duplicate when the body is identical (a retry), else 409 conflict.</summary>
    public static IntakeResult Duplicate(IntakeRecord existing, string bodySha) => existing.BodySha256 == bodySha
        ? new IntakeResult(200, new { status = "duplicate", intake_id = existing.IntakeId, idempotency_key = existing.Key, previous_status = existing.Status, run_ticket = existing.RunTicket })
        : Rejected(409, "a different payload was already accepted for this repo + head SHA + scanner + run id; send a new run id (include github.run_attempt)");
}
