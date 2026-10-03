using SecAgent.Core;

namespace SecAgent.Intake.Runs;

/// <summary>Enqueues accepted intakes on the "intake-runs" queue of the pipeline's <see cref="IMessageQueue"/> (InProcessQueue locally,
/// Azure Service Bus in the cloud). MessageId = idempotency key, so the broker's duplicate detection drops a second copy.</summary>
public sealed class QueueRunStarter(IMessageQueue queue) : IRunStarter
{
    public const string QueueName = "intake-runs";
    public Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct)
    {
        var fresh = queue.Publish(QueueName, request.IdempotencyKey, request);
        return Task.FromResult(new RunTicket($"{QueueName}/{request.IdempotencyKey[..16]}", fresh));
    }
}
