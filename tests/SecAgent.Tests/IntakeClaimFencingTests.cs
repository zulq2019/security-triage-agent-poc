using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Application;
using SecAgent.Intake.Application.Steps;
using SecAgent.Intake.Runs;
using SecAgent.Intake.Storage;
using Xunit;

namespace SecAgent.Tests;

/// <summary>Claim fencing: after a lease takeover, the previous holder of the claim can no longer write the ledger, enqueue or store
/// anything, and a key cannot be taken over forever (Intake:MaxClaimTakeovers). Time is the injected <see cref="ManualClock"/>; the slow
/// delivery is held at a gate, never by sleeping.</summary>
public class IntakeClaimFencingTests
{
    static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);
    static string Status(IntakeResult r) => JsonSerializer.SerializeToElement(r.Body, Schema.Json).GetProperty("status").GetString()!;
    static ManualClock Clock() => new(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));
    static byte[] Body => IntakeKit.Fixture("blackduck-sca.sarif.json");

    /// <summary>Real schema validator, except that its first call blocks until released (the delivery is stuck inside the
    /// canonical-findings step, after it stored the raw file and before it writes the ledger); optionally that call then fails.</summary>
    sealed class GatedValidator(bool failGatedCall = false) : IFindingSchemaValidator
    {
        readonly IFindingSchemaValidator _inner = IntakeKit.NewValidator();
        int _armed = 1;
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public string? ValidateFinding(Finding finding)
        {
            if (Interlocked.Exchange(ref _armed, 0) == 1)
            {
                Entered.Set();
                if (!Release.Wait(Wait)) throw new TimeoutException("test gate never released");
                if (failGatedCall) return "synthetic schema failure (slow delivery)";
            }
            return _inner.ValidateFinding(finding);
        }
    }

    /// <summary>A custom step right after the claim that holds every delivery while <see cref="Hang"/> is set (a stalled worker).</summary>
    sealed class HangingStep : IIntakeStep
    {
        public int Order => IntakeStepOrder.Claim + 50;
        public volatile bool Hang = true;
        public SemaphoreSlim Entered { get; } = new(0);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
        {
            if (!Hang) return null;
            Entered.Release();
            await Release.Task.WaitAsync(Wait, ct);
            return null;
        }
    }

    /// <summary>Decorator over the real ledger that records every compare-and-set write.</summary>
    sealed class RecordingLedger(IIntakeLedger inner) : IIntakeLedger
    {
        public ConcurrentQueue<(string Status, string Expected, string Token, LedgerWriteResult Result)> Writes { get; } = new();
        public bool TryClaim(IntakeRecord record, out IntakeRecord existing) => inner.TryClaim(record, out existing);
        public LedgerWriteResult TryUpdate(IntakeRecord record, string expectedClaimToken)
        {
            var r = inner.TryUpdate(record, expectedClaimToken);
            Writes.Enqueue((record.Status, expectedClaimToken, record.ClaimToken, r));
            return r;
        }
        public IntakeRecord? Get(string key) => inner.Get(key);
    }

    static IntakeKit Kit(ManualClock clock, IFindingSchemaValidator? validator = null, IIntakeStep? step = null, Action<SecAgent.Intake.Configuration.IntakeOptions>? configure = null) =>
        new(configure, services: sc =>
        {
            sc.Replace(ServiceDescriptor.Singleton<TimeProvider>(clock));
            if (validator != null) sc.Replace(ServiceDescriptor.Singleton(validator));
            if (step != null) sc.TryAddEnumerable(ServiceDescriptor.Singleton(step));
        });

    [Fact]
    public async Task A_stale_owner_after_a_takeover_cannot_overwrite_the_new_owner_and_enqueues_nothing()
    {
        var clock = Clock();
        var gate = new GatedValidator();
        using var k = Kit(clock, gate);
        var meta = IntakeKit.Meta();
        var slow = Task.Run(() => k.Acceptor.AcceptAsync(meta, Body, "slow", default));
        Assert.True(gate.Entered.Wait(Wait));                                     // holds the claim, stuck before its ledger write
        var staleToken = k.Ledger.Get(meta.IdempotencyKey)!.ClaimToken;

        clock.Now = clock.Now.AddSeconds(k.Options.ClaimLeaseSeconds + 1);       // lease expired: the retry takes the claim over
        var retry = await k.Acceptor.AcceptAsync(meta, Body, "retry", default);
        Assert.Equal(202, retry.StatusCode);
        var owner = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Queued, 1), (owner.Status, owner.Takeovers));
        Assert.NotEqual(staleToken, owner.ClaimToken);

        clock.Now = clock.Now.AddSeconds(5);
        gate.Release.Set();
        var late = await slow;
        Assert.Equal((503, "in_progress"), (late.StatusCode, Status(late)));     // stopped; the caller retries and sees the new owner's result
        Assert.NotNull(late.RetryAfterSeconds);
        Assert.Single(k.Runs.Requests);                                           // no second enqueue
        var after = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Queued, owner.ClaimToken, owner.RunTicket, owner.UpdatedAt), (after.Status, after.ClaimToken, after.RunTicket, after.UpdatedAt));

        var again = await k.Acceptor.AcceptAsync(meta, Body, "retry", default);
        Assert.Equal((200, "duplicate"), (again.StatusCode, Status(again)));
        Assert.Single(k.Runs.Requests);
    }

    [Fact]
    public async Task Release_claim_by_a_stale_owner_is_a_no_op()
    {
        var clock = Clock();
        var gate = new GatedValidator(failGatedCall: true);                       // the slow delivery then fails → it releases "its" claim
        using var k = Kit(clock, gate);
        var meta = IntakeKit.Meta();
        var slow = Task.Run(() => k.Acceptor.AcceptAsync(meta, Body, "slow", default));
        Assert.True(gate.Entered.Wait(Wait));
        clock.Now = clock.Now.AddSeconds(k.Options.ClaimLeaseSeconds + 1);
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(meta, Body, "retry", default)).StatusCode);
        var owner = k.Ledger.Get(meta.IdempotencyKey)!;

        clock.Now = clock.Now.AddSeconds(5);
        gate.Release.Set();
        var late = await slow;
        Assert.Equal(503, late.StatusCode);                                       // not its 422: the new owner's result stands
        var after = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Queued, owner.ClaimToken, owner.Detail, owner.UpdatedAt), (after.Status, after.ClaimToken, after.Detail, after.UpdatedAt));
        // had the release gone through, the key would be "failed" and this retry would take it over and enqueue a second run
        var again = await k.Acceptor.AcceptAsync(meta, Body, "retry", default);
        Assert.Equal((200, "duplicate"), (again.StatusCode, Status(again)));
        Assert.Single(k.Runs.Requests);
    }

    [Fact]
    public async Task Repeated_lease_takeovers_are_capped_and_the_key_is_failed_for_good()
    {
        var clock = Clock();
        var hang = new HangingStep();
        using var k = Kit(clock, step: hang, configure: o => o.MaxClaimTakeovers = 2);
        var meta = IntakeKit.Meta();
        var stalled = new List<Task<IntakeResult>>();
        for (int i = 0; i <= 2; i++)                                              // first claim + 2 takeovers, each worker stalls
        {
            stalled.Add(Task.Run(() => k.Acceptor.AcceptAsync(meta, Body, "stalled", default)));
            Assert.True(await hang.Entered.WaitAsync(Wait));
            Assert.Equal((IntakeStatus.Claimed, i), (k.Ledger.Get(meta.IdempotencyKey)!.Status, k.Ledger.Get(meta.IdempotencyKey)!.Takeovers));
            clock.Now = clock.Now.AddSeconds(k.Options.ClaimLeaseSeconds + 1);
        }

        hang.Hang = false;                                                        // a further takeover would now get through
        var capped = await k.Acceptor.AcceptAsync(meta, Body, "retry", default);
        Assert.Equal((409, "failed"), (capped.StatusCode, Status(capped)));
        var rec = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Failed, true, 2), (rec.Status, rec.Terminal, rec.Takeovers));
        Assert.Contains("MaxClaimTakeovers", rec.Detail);

        hang.Release.TrySetResult();                                              // the stalled workers wake up: all fenced off
        Assert.All(await Task.WhenAll(stalled), r => Assert.Equal(503, r.StatusCode));
        Assert.Empty(k.Runs.Requests);
        var after = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Failed, true, rec.ClaimToken, rec.UpdatedAt), (after.Status, after.Terminal, after.ClaimToken, after.UpdatedAt));

        clock.Now = clock.Now.AddHours(1);
        Assert.Equal(409, (await k.Acceptor.AcceptAsync(meta, Body, "retry", default)).StatusCode);   // stays failed, never reclaimed
        Assert.Empty(k.Runs.Requests);
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(runId: "1001-2"), Body, "new run", default)).StatusCode);
    }

    [Fact]
    public async Task Single_owner_happy_path_is_unchanged_and_every_write_is_fenced_with_its_claim_token()
    {
        RecordingLedger? recorder = null;
        using var k = new IntakeKit(fakeRunStarter: false, services: sc =>
        {
            sc.Replace(ServiceDescriptor.Singleton(Clock() as TimeProvider));
            sc.Replace(ServiceDescriptor.Singleton<IIntakeLedger>(sp => recorder = new RecordingLedger(sp.GetRequiredKeyedService<FileIntakeLedger>(IntakeAdapterKeys.Local))));
        });
        var ledger = k.Services.GetRequiredKeyedService<FileIntakeLedger>(IntakeAdapterKeys.Local);
        var meta = IntakeKit.Meta(IntakeFormats.BlackDuckRapid);
        var r = await k.Acceptor.AcceptAsync(meta, IntakeKit.Fixture("blackduck-rapid.json"), "test", default);
        Assert.Equal((202, "accepted"), (r.StatusCode, Status(r)));
        var rec = ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.Queued, 0, false), (rec.Status, rec.Takeovers, rec.Terminal));

        var source = k.Services.GetRequiredService<IIntakeRunSource>();
        await k.Services.GetRequiredService<IntakeRunDispatcher>().HandleAsync((await source.ReceiveAsync(default))!, default);
        Assert.Single(k.Launcher.Started);
        Assert.Equal((IntakeStatus.RunStarted, k.Launcher.RunId), (ledger.Get(meta.IdempotencyKey)!.Status, ledger.Get(meta.IdempotencyKey)!.RunId!.Value));
        Assert.Null(await source.ReceiveAsync(default));

        var writes = recorder!.Writes.ToList();
        Assert.Contains(writes, w => w.Status == IntakeStatus.Queued);
        Assert.Equal(IntakeStatus.RunStarted, writes[^1].Status);
        Assert.All(writes, w => Assert.Equal((LedgerWriteResult.Updated, rec.ClaimToken, rec.ClaimToken), (w.Result, w.Expected, w.Token)));
        Assert.Equal(rec.ClaimToken, ledger.Get(meta.IdempotencyKey)!.ClaimToken);   // the token issued at the claim, never replaced
        // the fence is live on the record this path produced: a writer without that token changes nothing
        var forged = ledger.Get(meta.IdempotencyKey)!;
        forged.Status = IntakeStatus.Failed;
        Assert.Equal(LedgerWriteResult.LostOwnership, ledger.TryUpdate(forged, "not-the-claim-token"));
        Assert.Equal(IntakeStatus.RunStarted, ledger.Get(meta.IdempotencyKey)!.Status);
    }
}
