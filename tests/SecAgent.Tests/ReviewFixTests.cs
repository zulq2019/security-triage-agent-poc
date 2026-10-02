using SecAgent.Agents.Repo;
using SecAgent.Core;
using Xunit;

namespace SecAgent.Tests;

/// <summary>Regression (review P1): PRs from forks. The head branch only exists in the fork, so the workspace must fetch
/// refs/pull/&lt;n&gt;/head from the base repository and verify the head SHA.</summary>
public class ForkPrFetchTests : IDisposable
{
    readonly string _root = Path.Combine(Path.GetTempPath(), "secagent-forktest-" + Guid.NewGuid().ToString("N")[..8]);

    static async Task<string> G(string cwd, params string[] args)
    {
        var r = await Proc.RunAsync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", .. args], cwd);
        Assert.True(r.ExitCode == 0, $"git {string.Join(' ', args)}: {r.StdErr}");
        return r.StdOut.Trim();
    }

    /// <summary>Base repo (bare, "upstream") with main; a separate "fork" with a feature branch whose commit is published in
    /// upstream only as refs/pull/7/head, exactly like GitHub does for fork PRs.</summary>
    async Task<(string BaseSha, string HeadSha)> SetUpAsync()
    {
        Directory.CreateDirectory(_root);
        var upstream = Path.Combine(_root, "upstream.git");
        await G(_root, "init", "--quiet", "--bare", upstream);
        var work = Path.Combine(_root, "maintainer");
        await G(_root, "clone", "--quiet", upstream, work);
        File.WriteAllText(Path.Combine(work, "a.txt"), "base\n");
        await G(work, "add", "-A"); await G(work, "commit", "--quiet", "-m", "base");
        await G(work, "push", "--quiet", "origin", "HEAD:refs/heads/main");
        var baseSha = await G(work, "rev-parse", "HEAD");

        var fork = Path.Combine(_root, "fork");
        await G(_root, "clone", "--quiet", upstream, fork);
        await G(fork, "checkout", "--quiet", "-b", "contrib-feature");
        File.WriteAllText(Path.Combine(fork, "a.txt"), "from the fork\n");
        await G(fork, "commit", "--quiet", "-am", "fork change");
        var headSha = await G(fork, "rev-parse", "HEAD");
        await G(fork, "push", "--quiet", upstream, "HEAD:refs/pull/7/head");   // no branch named contrib-feature upstream
        return (baseSha, headSha);
    }

    PrInfo Pr(string baseSha, string headSha) => new("upstream/repo", 7, "fork PR", "contrib-feature", "main", headSha, baseSha, 1, 1, 1,
        "https://example.invalid/pull/7", HeadRepo: "contributor/repo");

    GitWorkspace Ws() => new(Path.Combine(_root, "work"), _ => Path.Combine(_root, "upstream.git"));

    [Fact]
    public async Task Fork_pr_head_is_fetched_via_pull_ref_and_checked_out()
    {
        var (b, h) = await SetUpAsync();
        var pr = Pr(b, h);
        Assert.True(pr.IsFork);
        var (head, baseDir) = await Ws().PrepareAsync(Guid.NewGuid(), pr, CancellationToken.None);
        Assert.Equal(h, await G(head, "rev-parse", "HEAD"));
        Assert.Equal("from the fork\n", File.ReadAllText(Path.Combine(head, "a.txt")));
        Assert.Equal(b, await G(baseDir, "rev-parse", "HEAD"));
    }

    [Fact]
    public async Task Head_sha_mismatch_fails_before_scanning()
    {
        var (b, _) = await SetUpAsync();
        var stale = Pr(b, new string('a', 40));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => Ws().PrepareAsync(Guid.NewGuid(), stale, CancellationToken.None));
        Assert.Contains("head moved", ex.Message);
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }
}

/// <summary>Regression (review P1): fix group / ledger identity must be scoped by repository and target PR/ref.</summary>
public class ScopedFixKeyTests
{
    static Finding Dep(string repo = "a/one") => new() { IssueType = IssueTypes.VulnerableDependency, ComponentName = "pkg:nuget/Newtonsoft.Json", ComponentVersion = "12.0.1", Repo = repo, Fingerprint = new string('f', 64) };

    [Fact]
    public void Same_dependency_in_two_repos_or_two_prs_gets_different_keys()
    {
        var a = FixKeys.Group(Dep(), "a/one", 1, "feature/x");
        Assert.NotEqual(a, FixKeys.Group(Dep(), "b/two", 1, "feature/x"));   // other repo
        Assert.NotEqual(a, FixKeys.Group(Dep(), "a/one", 2, "feature/x"));   // other PR
        Assert.NotEqual(a, FixKeys.Group(Dep(), "a/one", 1, "feature/y"));   // other target ref
        Assert.Equal(a, FixKeys.Group(Dep(), "A/One", 1, "feature/x"));      // repo names are case-insensitive on GitHub
        Assert.Equal(64, a.Length);                                           // fits fix_group_key NVARCHAR(64)
    }

    [Fact]
    public void Legacy_key_formula_is_unchanged_for_migration()
    {
        Assert.Equal(Hashing.Sha256("fix_group|pkg:nuget/Newtonsoft.Json|12.0.1"), FixKeys.Legacy(Dep()));
        var secret = new Finding { IssueType = IssueTypes.Secret, Fingerprint = new string('e', 64) };
        Assert.Equal(secret.Fingerprint, FixKeys.Legacy(secret));
    }

    [Fact]
    public void Shared_ledger_legacy_entry_is_not_reused_by_another_repo_and_is_migrated_for_its_own()
    {
        var s = TestEnv.Store();
        var legacy = Hashing.Sha256("fix_group|test-scope|" + Guid.NewGuid());
        var keyA = FixKeys.Group(Dep(), "a/one", 1, "feature/x");
        var keyB = FixKeys.Group(Dep(), "b/two", 1, "feature/x");
        try
        {
            s.LedgerPut(FixKeys.PrLedger(legacy), "pr", "completed", "https://github.com/a/one/pull/9");
            Assert.Null(FixKeys.ResolvePrEntry(s, keyB, legacy, "b/two"));            // repo B must run its own fixer
            Assert.Null(s.Ledger(FixKeys.PrLedger(keyB)));
            var a = FixKeys.ResolvePrEntry(s, keyA, legacy, "a/one");                // repo A: migrated to its scoped key
            Assert.Equal("https://github.com/a/one/pull/9", a!.ResultRef);
            Assert.Equal("completed", s.Ledger(FixKeys.PrLedger(keyA))!.Status);
            // A scoped entry written for repo B never shows up for repo A.
            s.LedgerPut(FixKeys.PrLedger(keyB), "pr", "completed", "https://github.com/b/two/pull/3");
            Assert.Equal("https://github.com/a/one/pull/9", FixKeys.ResolvePrEntry(s, keyA, legacy, "a/one")!.ResultRef);
        }
        finally { s.LedgerDelete(FixKeys.PrLedger(legacy)); s.LedgerDelete(FixKeys.PrLedger(keyA)); s.LedgerDelete(FixKeys.PrLedger(keyB)); }
    }
}
