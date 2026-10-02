namespace SecAgent.Core;

/// <summary>Identity of a fix group and of its "fix PR" idempotency-ledger entry.
/// v2 keys are scoped by repository, target PR number and target ref (the PR head branch the fix PR is opened against), so a
/// shared IdempotencyLedger never lets repo B (or another PR of the same repo) reuse repo A's fix PR and skip its fixer.
/// Legacy (v1) keys had no scope; they are only read as a migration fallback (see <see cref="ResolvePrEntry"/>).</summary>
public static class FixKeys
{
    public const string Version = "v2";

    /// <summary>Unscoped v1 group key, kept byte-for-byte for ledger migration.</summary>
    public static string Legacy(Finding f) =>
        f.IssueType == IssueTypes.VulnerableDependency ? Hashing.Sha256($"fix_group|{f.ComponentName}|{f.ComponentVersion}") : f.Fingerprint;

    public static string Group(Finding f, string repo, int prNumber, string targetRef)
    {
        var scope = $"fix_group|{Version}|{repo.ToLowerInvariant()}|pr{prNumber}|{targetRef}";
        return Hashing.Sha256(f.IssueType == IssueTypes.VulnerableDependency
            ? $"{scope}|dep|{f.ComponentName}|{f.ComponentVersion}"
            : $"{scope}|fp|{f.Fingerprint}");
    }

    public static string PrLedger(string groupKey) => $"fix:{groupKey}:pr";

    public static bool PrUrlInRepo(string? url, string repo) =>
        url != null && url.StartsWith($"https://github.com/{repo}/pull/", StringComparison.OrdinalIgnoreCase);

    public static int? PrNumber(string? url) => int.TryParse(url?.TrimEnd('/').Split('/').Last(), out var n) ? n : null;

    /// <summary>Reads the scoped "fix PR" ledger entry. When it does not exist yet, falls back to the legacy unscoped entry,
    /// but only if that entry is completed and its PR is in the same repository; it is then migrated to the scoped key
    /// (the legacy row is left untouched, so other repositories keep ignoring it). Callers still revalidate the PR itself.</summary>
    public static SqlStore.LedgerEntry? ResolvePrEntry(SqlStore store, string scopedKey, string legacyGroupKey, string repo)
    {
        var key = PrLedger(scopedKey);
        var e = store.Ledger(key);
        if (e != null) return e;
        var legacy = store.Ledger(PrLedger(legacyGroupKey));
        if (legacy is not { Status: "completed" } || !PrUrlInRepo(legacy.ResultRef, repo)) return null;
        store.LedgerPut(key, "pr", "completed", legacy.ResultRef);
        return store.Ledger(key);
    }
}
