namespace SecAgent.Core;

/// <summary>All run-level limits from policies.yaml budgets (tokens, cost, max_fixes, max_minutes), carried into run state.
/// 0 (or negative) for max_fixes / max_minutes means "no limit".</summary>
public sealed record RunLimits(int Tokens, decimal Cost, int MaxFixes, int MaxMinutes)
{
    public static RunLimits From(BudgetConfig b) => new(b.Tokens, b.Cost, b.MaxFixes, b.MaxMinutes);
    public TimeSpan? TimeLimit => MaxMinutes > 0 ? TimeSpan.FromMinutes(MaxMinutes) : null;

    public const string MaxFixesReason = "budget: max_fixes";
    public const string MaxMinutesReason = "budget: max_minutes";

    /// <summary>Splits fix groups (already in priority order) into those dispatched to fixers and those deferred by max_fixes.</summary>
    public (List<T> Dispatch, List<T> Deferred) SplitFixes<T>(IEnumerable<T> groups)
    {
        var all = groups.ToList();
        return MaxFixes <= 0 || all.Count <= MaxFixes ? (all, []) : (all.Take(MaxFixes).ToList(), all.Skip(MaxFixes).ToList());
    }
}

/// <summary>Run-level wall-clock budget (max_minutes). When the deadline passes, <paramref name="onExpire"/> runs while holding
/// the push gate, so it can never interrupt a push / PR creation half-way; after that, <see cref="TryEnterPushAsync"/> refuses
/// new pushes. The callback is expected to record the stop reason and cancel the run.</summary>
public sealed class RunDeadline : IDisposable
{
    readonly SemaphoreSlim _gate = new(1, 1);
    readonly CancellationTokenSource _dispose = new();
    readonly Func<Task> _onExpire;
    volatile bool _expired;

    public RunDeadline(TimeSpan? limit, Func<Task> onExpire)
    {
        _onExpire = onExpire;
        if (limit is { } l) _ = Task.Delay(l, _dispose.Token).ContinueWith(t => { if (!t.IsCanceled) return ExpireAsync(); return Task.CompletedTask; }).Unwrap();
    }

    public bool Expired => _expired;
    public Task Expiry => _expiry.Task;
    readonly TaskCompletionSource _expiry = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Enter before pushing / creating a PR; false once the time budget is spent (do not push). Call <see cref="ExitPush"/> after.</summary>
    public async Task<bool> TryEnterPushAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        if (!_expired) return true;
        _gate.Release();
        return false;
    }
    public void ExitPush() => _gate.Release();

    async Task ExpireAsync()
    {
        await _gate.WaitAsync();
        try { _expired = true; await _onExpire(); }
        finally { _gate.Release(); _expiry.TrySetResult(); }
    }

    public void Dispose() { _dispose.Cancel(); }
}
