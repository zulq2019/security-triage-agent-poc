using Xunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecAgent.Connectors;
using SecAgent.Connectors.Fakes;
using SecAgent.Connectors.GitHub;
using SecAgent.Core;

namespace SecAgent.Tests.Connectors;

/// <summary>Synthetic repository both implementations are seeded with.</summary>
public static class ScmFixture
{
    public const string Repo = "acme/payments", Main = "main", Head = "feature/x", HeadSha = "aaaa000000000000000000000000000000000001",
        BaseSha = "bbbb000000000000000000000000000000000001", OldSha = "cccc000000000000000000000000000000000001";
    public static readonly ChangedFile[] Files = Enumerable.Range(1, 150).Select(i => new ChangedFile($"src/file{i:D3}.cs", i == 1 ? "added" : "modified", i, i % 3)).ToArray();
    public static readonly CheckRunInfo[] Checks = [new("build", "completed", "success", null), new("lint", "completed", "failure", null)];
}

/// <summary>Contract every <see cref="ISourceControlClient"/> must honour (fake and real run the same assertions). Clients come from the
/// per-tenant factory, so the auditing / resilience decorators are part of what is tested.</summary>
public abstract class SourceControlContract
{
    const string Repo = ScmFixture.Repo;
    protected abstract ISourceControlClient CreateSeededClient();

    [Fact]
    public async Task Reads_a_pull_request_with_refs_shas_and_size()
    {
        var pr = await CreateSeededClient().GetPullRequestAsync(Repo, 7, default);
        Assert.NotNull(pr);
        Assert.Equal((7, "Add payment retries", ScmFixture.Head, ScmFixture.Main, ScmFixture.HeadSha, ScmFixture.BaseSha), (pr!.Number, pr.Title, pr.HeadRef, pr.BaseRef, pr.HeadSha, pr.BaseSha));
        Assert.Equal(PullRequestState.Open, pr.State);
        Assert.Equal(150, pr.FilesChanged);
        Assert.Equal(ScmFixture.Files.Sum(f => f.Additions), pr.Additions);
        Assert.True(FixKeys.PrUrlInRepo(pr.Url, Repo));
        Assert.Equal(Repo, pr.HeadRepo);
    }

    [Fact]
    public async Task Missing_pull_request_is_null() => Assert.Null(await CreateSeededClient().GetPullRequestAsync(Repo, 999, default));

    [Fact]
    public async Task Lists_every_changed_file_across_pages()
    {
        var files = await CreateSeededClient().ListChangedFilesAsync(Repo, 7, default);
        Assert.Equal(150, files.Count);
        Assert.Equal(("src/file001.cs", "added"), (files[0].Path, files[0].Status));
        Assert.Equal("src/file150.cs", files[^1].Path);
    }

    [Fact]
    public async Task Finds_pull_requests_by_head_branch_including_closed_ones()
    {
        var c = CreateSeededClient();
        Assert.Equal((7, PullRequestState.Open), ((await c.FindPullRequestByHeadAsync(Repo, ScmFixture.Head, default))!.Number, PullRequestState.Open));
        var old = await c.FindPullRequestByHeadAsync(Repo, "fix/old", default);
        Assert.Equal((5, PullRequestState.Closed), (old!.Number, old.State));
        Assert.Null(await c.FindPullRequestByHeadAsync(Repo, "fix/none", default));
    }

    [Fact]
    public async Task Creates_a_branch_commits_to_it_and_opens_a_pull_request()
    {
        var c = CreateSeededClient();
        Assert.False(await c.BranchExistsAsync(Repo, "fix/a", default));
        await c.CreateBranchAsync(Repo, "fix/a", ScmFixture.HeadSha, default);
        Assert.True(await c.BranchExistsAsync(Repo, "fix/a", default));
        var commit = await c.CommitAsync(Repo, new CommitRequest("fix/a", "fix: pin version", [new FileChange("deps.txt", "lib==1.2.4\n")], ScmFixture.HeadSha), default);
        Assert.False(string.IsNullOrEmpty(commit.Sha));
        Assert.NotEqual(ScmFixture.HeadSha, commit.Sha);
        var pr = await c.CreatePullRequestAsync(Repo, new NewPullRequest(ScmFixture.Head, "fix/a", "SecAgent fix", "synthetic body"), default);
        Assert.Equal((8, PullRequestState.Open, ScmFixture.Head, "fix/a"), (pr.Number, pr.State, pr.BaseRef, pr.HeadRef));
        Assert.True(FixKeys.PrUrlInRepo(pr.Url, Repo));
        Assert.Equal(8, (await c.FindPullRequestByHeadAsync(Repo, "fix/a", default))!.Number);
        // A second PR for the same head/base is refused (the pipeline reuses the first one instead).
        await Assert.ThrowsAnyAsync<ConnectorException>(() => c.CreatePullRequestAsync(Repo, new NewPullRequest(ScmFixture.Head, "fix/a", "dup", ""), default));
    }

    [Fact]
    public async Task A_commit_on_a_branch_that_moved_is_refused()
    {
        var c = CreateSeededClient();
        await c.CreateBranchAsync(Repo, "fix/b", ScmFixture.HeadSha, default);
        await c.CommitAsync(Repo, new CommitRequest("fix/b", "one", [new FileChange("a.txt", "1")]), default);
        await Assert.ThrowsAnyAsync<ConnectorException>(() => c.CommitAsync(Repo, new CommitRequest("fix/b", "two", [new FileChange("a.txt", "2")], ScmFixture.HeadSha), default));
        await Assert.ThrowsAnyAsync<ConnectorException>(() => c.CommitAsync(Repo, new CommitRequest("fix/missing", "x", [new FileChange("a.txt", "2")]), default));
    }

    [Fact]
    public async Task Never_writes_to_the_default_branch()
    {
        var c = CreateSeededClient();
        await Assert.ThrowsAsync<ForbiddenConnectorOperationException>(() => c.CreateBranchAsync(Repo, ScmFixture.Main, ScmFixture.BaseSha, default));
        await Assert.ThrowsAsync<ForbiddenConnectorOperationException>(() => c.CommitAsync(Repo, new CommitRequest(ScmFixture.Main, "x", [new FileChange("a", "b")]), default));
        await Assert.ThrowsAsync<ForbiddenConnectorOperationException>(() => c.CreatePullRequestAsync(Repo, new NewPullRequest(ScmFixture.Head, ScmFixture.Main, "x", ""), default));
        await Assert.ThrowsAsync<ForbiddenConnectorOperationException>(() => c.PublishBranchAsync(new BranchPublishRequest(Repo, "/tmp/wt", ScmFixture.Main), default));
    }

    [Fact]
    public async Task Publishes_a_new_branch_but_never_overwrites_an_existing_one()
    {
        var c = CreateSeededClient();
        var published = await c.PublishBranchAsync(new BranchPublishRequest(Repo, "/tmp/wt", "secagent/fix-1"), default);
        Assert.Equal("secagent/fix-1", published.RemoteBranch);
        Assert.True(await c.BranchExistsAsync(Repo, "secagent/fix-1", default));
        await Assert.ThrowsAnyAsync<ConnectorException>(() => c.PublishBranchAsync(new BranchPublishRequest(Repo, "/tmp/wt", "secagent/fix-1"), default));
    }

    [Fact]
    public async Task Comments_on_a_pull_request_and_reads_check_runs()
    {
        var c = CreateSeededClient();
        var comment = await c.AddCommentAsync(Repo, 7, "synthetic triage summary", default);
        Assert.True(comment.Id > 0);
        Assert.Contains($"/{Repo}/pull/7", comment.Url);
        var checks = await c.ListCheckRunsAsync(Repo, ScmFixture.HeadSha, default);
        Assert.Equal(["build:success", "lint:failure"], checks.Select(x => $"{x.Name}:{x.Conclusion}"));
        Assert.Empty(await c.ListCheckRunsAsync(Repo, ScmFixture.BaseSha, default));
    }

    [Fact]
    public void Clone_url_points_at_the_repository() => Assert.EndsWith($"/{Repo}.git", CreateSeededClient().CloneUrl(Repo));
}

public sealed class FakeSourceControlContractTests : SourceControlContract
{
    public FakeConnectorWorld World { get; } = new();

    protected override ISourceControlClient CreateSeededClient()
    {
        var r = World.SourceControl.AddRepository(ConnectorTestKit.Tenant, ScmFixture.Repo);
        r.AddPullRequest(7, "Add payment retries", ScmFixture.Head, ScmFixture.Main, ScmFixture.HeadSha, ScmFixture.BaseSha, null, ScmFixture.Files);
        r.AddPullRequest(5, "Old fix", "fix/old", ScmFixture.Main, ScmFixture.OldSha, ScmFixture.BaseSha).State = PullRequestState.Closed;
        r.CheckRuns[ScmFixture.HeadSha] = [.. ScmFixture.Checks];
        var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.AddFakeConnectors(World));
        return sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant(ConnectorTestKit.Tenant);
    }
}

public sealed class GitHubSourceControlContractTests : SourceControlContract
{
    public GitHubSimulator Sim { get; } = new(ScmFixture.Repo) { Token = "ghs_synthetic_test_token" };

    public static Dictionary<string, string?> Config() => new()
    {
        ["Connectors:DeploymentModel"] = "SingleTenant", ["Connectors:DefaultTenant"] = ConnectorTestKit.Tenant,
        ["Connectors:Tenants:t1:SourceControl:Provider"] = "github",
        ["Connectors:Tenants:t1:SourceControl:BaseUrl"] = "https://api.github.test/",
        ["Connectors:Tenants:t1:SourceControl:Secret"] = "memory:github-token",
        ["Connectors:Resilience:PermitsPerSecond"] = "1000", ["Connectors:Resilience:BaseDelay"] = "00:00:00.010",
    };

    public ServiceProvider BuildServices()
    {
        Sim.Branches[ScmFixture.Main] = ScmFixture.BaseSha;
        Sim.Branches[ScmFixture.Head] = ScmFixture.HeadSha;
        Sim.Branches["fix/old"] = ScmFixture.OldSha;
        Sim.Prs.Add(new() { Number = 5, Title = "Old fix", Head = "fix/old", Base = ScmFixture.Main, HeadSha = ScmFixture.OldSha, BaseSha = ScmFixture.BaseSha, State = PullRequestState.Closed });
        Sim.Prs.Add(new() { Number = 7, Title = "Add payment retries", Head = ScmFixture.Head, Base = ScmFixture.Main, HeadSha = ScmFixture.HeadSha, BaseSha = ScmFixture.BaseSha, Files = [.. ScmFixture.Files] });
        Sim.CheckRuns[ScmFixture.HeadSha] = [.. ScmFixture.Checks];
        var sp = ConnectorTestKit.Services(Config(), b => b.AddFakeConnectors().AddGitHubConnector(), s =>
        {
            s.RemoveAll<IGitCommandRunner>();
            s.AddSingleton<IGitCommandRunner>(new SimulatedGitRunner(Sim));
            s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => Sim));
        });
        sp.GetRequiredService<InMemorySecretSource>().Set("github-token", "ghs_synthetic_test_token");
        return sp;
    }

    protected override ISourceControlClient CreateSeededClient() =>
        BuildServices().GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant(ConnectorTestKit.Tenant);

    [Fact]
    public async Task Requests_carry_the_token_api_version_and_no_merge_or_force()
    {
        var c = CreateSeededClient();
        await c.GetPullRequestAsync(ScmFixture.Repo, 7, default);
        await c.CreateBranchAsync(ScmFixture.Repo, "fix/c", ScmFixture.HeadSha, default);
        await c.CommitAsync(ScmFixture.Repo, new CommitRequest("fix/c", "m", [new FileChange("a", "b")]), default);
        await c.CreatePullRequestAsync(ScmFixture.Repo, new NewPullRequest(ScmFixture.Head, "fix/c", "t", "b", Draft: true), default);
        Assert.All(Sim.Seen, r => Assert.Equal(("Bearer", "ghs_synthetic_test_token"), (r.AuthScheme, r.AuthParameter)));
        Assert.All(Sim.Seen, r => Assert.Equal("2022-11-28", r.Headers["X-GitHub-Api-Version"]));
        Assert.DoesNotContain(Sim.Seen, r => r.Path.Contains("merge", StringComparison.OrdinalIgnoreCase) || r.Path.Contains("/reviews"));
        var patch = Assert.Single(Sim.Seen, r => r.Method == HttpMethod.Patch);
        Assert.Equal(false, (bool?)patch.Json!["force"]);
        var create = Assert.Single(Sim.Seen, r => r.Method == HttpMethod.Post && r.Path.EndsWith("/pulls"));
        Assert.Equal(("fix/c", ScmFixture.Head, true), ((string?)create.Json!["head"], (string?)create.Json!["base"], (bool?)create.Json!["draft"]));
    }

    [Fact]
    public async Task Publish_is_a_plain_push_of_HEAD_to_a_new_branch()
    {
        var sp = BuildServices();
        var c = sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant(ConnectorTestKit.Tenant);
        await c.PublishBranchAsync(new BranchPublishRequest(ScmFixture.Repo, "/tmp/wt", "secagent/fix-2"), default);
        var push = Assert.Single(((SimulatedGitRunner)sp.GetRequiredService<IGitCommandRunner>()).Calls, a => a[0] == "push");
        Assert.Equal(["push", "--quiet", "origin", "HEAD:refs/heads/secagent/fix-2"], push);
        Assert.DoesNotContain(push, a => a is "--force" or "-f" or "--force-with-lease" || a.StartsWith('+'));
    }

    [Fact]
    public async Task Unauthorized_is_reported_without_the_token()
    {
        var c = CreateSeededClient();
        Sim.Token = "a-different-token";
        var e = await Assert.ThrowsAnyAsync<ConnectorException>(() => c.GetPullRequestAsync(ScmFixture.Repo, 7, default));
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, e.StatusCode);
        Assert.DoesNotContain("ghs_synthetic_test_token", e.Message);
    }
}
