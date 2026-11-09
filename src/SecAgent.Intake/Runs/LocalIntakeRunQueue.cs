using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Runs;

/// <summary>Local adapter for both sides of the run queue over the pipeline's <see cref="IMessageQueue"/> (InProcessQueue), queue <see cref="RunQueueConvention.QueueName"/> ("runs", the same name as in Service Bus).
/// MessageId = idempotency key, so duplicate detection drops a second copy (as Service Bus does with duplicate detection on).</summary>
public sealed class LocalIntakeRunQueue(IMessageQueue queue) : IRunStarter, IIntakeRunSource
{
    public const string QueueName = RunQueueConvention.QueueName;

    public Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct)
    {
        var fresh = queue.Publish(QueueName, request.IdempotencyKey, request);
        return Task.FromResult(new RunTicket($"{QueueName}/{request.IdempotencyKey[..16]}", fresh));
    }

    public Task<IntakeRunDelivery?> ReceiveAsync(CancellationToken ct) =>
        Task.FromResult(queue.TryReceive(QueueName, out var m) && m != null ? new IntakeRunDelivery(m.As<IntakeRunRequest>(), m) : null);

    public Task CompleteAsync(IntakeRunDelivery delivery, CancellationToken ct) { queue.Complete((QueueMessage)delivery.Handle); return Task.CompletedTask; }

    public Task AbandonAsync(IntakeRunDelivery delivery, string error, CancellationToken ct) { queue.Abandon((QueueMessage)delivery.Handle, error); return Task.CompletedTask; }
}
