using Xunit;
using System.Net;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Connectors;
using SecAgent.Connectors.BlackDuck;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.Fakes;
using SecAgent.Connectors.GitHub;
using SecAgent.Connectors.Health;
using SecAgent.Connectors.Auditing;
using Microsoft.Extensions.Configuration;
using SecAgent.Connectors.Jira;
using SecAgent.Connectors.OpenAI;
using SecAgent.Connectors.Teams;

namespace SecAgent.Tests.Connectors;

static class All
{
    /// <summary>Every real plug-in plus the fakes, as the dashboard registers them.</summary>
    public static ConnectorsBuilder Plugins(this ConnectorsBuilder b) =>
        b.AddGitHubConnector().AddJiraConnector().AddBlackDuckConnector().AddOpenAICompatibleModelConnector().AddTeamsNotifier().AddFakeConnectors();

    public static Exception? Validate(Dictionary<string, string?> config)
    {
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins());
        try { _ = sp.GetRequiredService<IOptionsMonitor<ConnectorOptions>>().CurrentValue; return null; }
        catch (OptionsValidationException e) { return e; }
    }

    /// <summary>Two fake-only tenants (multi-tenant model): a owns org-a/*, b owns org-b/*.</summary>
    public static Dictionary<string, string?> TwoFakeTenants()
    {
        var d = new Dictionary<string, string?> { ["Connectors:DeploymentModel"] = "MultiTenant" };
        foreach (var t in new[] { "a", "b" })
        {
            d[$"Connectors:Tenants:{t}:Repositories:0"] = $"org-{t}/*";
            foreach (var kind in Enum.GetNames<ConnectorKind>()) d[$"Connectors:Tenants:{t}:{kind}:Provider"] = "fake";
        }
        return d;
    }

    public static Dictionary<string, string?> MultiTenant() => new()
    {
        ["Connectors:DeploymentModel"] = "MultiTenant",
        ["Connectors:Defaults:ModelProvider:Provider"] = "fake",
        ["Connectors:Tenants:contoso:Repositories:0"] = "contoso/*",
        ["Connectors:Tenants:contoso:SourceControl:Provider"] = "github",
        ["Connectors:Tenants:contoso:SourceControl:Secret"] = "memory:contoso-github-token",   // "kv:..." in Azure (tenant-scoped scheme)
        ["Connectors:Tenants:fabrikam:Repositories:0"] = "fabrikam/payments",
        ["Connectors:Tenants:fabrikam:SourceControl:Provider"] = "fake",
        ["Connectors:Tenants:fabrikam:Notifier:Provider"] = "fake",
        ["Connectors:MultiTenantSecretSchemes:0"] = "kv", ["Connectors:MultiTenantSecretSchemes:1"] = "memory",
    };
}

public class ConnectorOptionsTests
{
    [Fact]
    public void The_dashboard_appsettings_connectors_section_is_valid()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddJsonFile(Path.Combine(TestEnv.RepoRoot, "src", "SecAgent.Dashboard", "appsettings.json")).Build();
        var dict = config.AsEnumerable().Where(kv => kv.Key.StartsWith("Connectors")).ToDictionary(kv => kv.Key, kv => kv.Value);
        using var sp = ConnectorTestKit.Services(dict, b => b.Plugins());
        var o = sp.GetRequiredService<IOptionsMonitor<ConnectorOptions>>().CurrentValue;
        Assert.Equal(DeploymentModel.SingleTenant, o.DeploymentModel);
        Assert.Equal("github", sp.GetRequiredService<ITenantConnectionResolver>().Resolve("local", ConnectorKind.SourceControl)!.Provider);
        Assert.Null(sp.GetRequiredService<ITenantConnectionResolver>().Resolve("local", ConnectorKind.IssueTracker));   // "none"
    }

    [Fact]
    public void A_valid_multi_tenant_configuration_passes() => Assert.Null(All.Validate(All.MultiTenant()));

    [Theory]
    [InlineData("Connectors:Tenants:contoso:SourceControl:Provider", "gitlab", "no registered")]
    [InlineData("Connectors:Tenants:contoso:SourceControl:Secret", "ghp_literal_token_value", "Secret")]
    [InlineData("Connectors:Tenants:contoso:SourceControl:Secret", "env:GITHUB_TOKEN", "tenant-scoped")]
    [InlineData("Connectors:Tenants:contoso:SourceControl:BaseUrl", "not a url", "BaseUrl")]
    [InlineData("Connectors:Tenants:contoso:SourceControl:Settings:Token", "abc", "secret")]
    [InlineData("Connectors:Tenants:fabrikam:Repositories:0", "contoso/app", "more than one tenant")]
    [InlineData("Connectors:Tenants:fabrikam:Repositories:0", "*", "*")]
    [InlineData("Connectors:Tenants:fabrikam:Repositories:0", "contoso/*", "more than one tenant")]
    [InlineData("Connectors:Defaults:SourceControl:Provider", "fake", "cannot share")]
    [InlineData("Connectors:Resilience:MaxRetryAttempts", "99", "Resilience")]
    public void Invalid_configuration_fails_at_startup_with_a_clear_message(string key, string value, string expected)
    {
        var config = All.MultiTenant();
        config[key] = value;
        var e = All.Validate(config);
        Assert.NotNull(e);
        Assert.True(e!.Message.Contains(expected, StringComparison.OrdinalIgnoreCase), e.Message);
        Assert.DoesNotContain("ghp_literal_token_value", e.Message);   // a misplaced secret is never echoed back
    }

    [Fact]
    public void A_tenant_without_repositories_is_rejected_in_multi_tenant_mode()
    {
        var config = All.MultiTenant();
        config.Remove("Connectors:Tenants:fabrikam:Repositories:0");
        Assert.Contains("Repositories", All.Validate(config)!.Message);
    }

    [Fact]
    public void Missing_required_setup_field_is_reported()
    {
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:IssueTracker:Provider"] = "jira";   // no BaseUrl / Secret
        var e = All.Validate(config);
        Assert.NotNull(e);
        Assert.Contains("jira", e!.Message);
    }
}

public class TenantResolutionTests
{
    [Fact]
    public void Single_tenant_maps_every_repository_to_the_constant_tenant()
    {
        using var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes("customer"));
        var t = sp.GetRequiredService<ITenantResolver>();
        Assert.Equal("customer", t.ForRepository("any/repo"));
        Assert.Equal("customer", t.ForRepository(""));
    }

    [Theory]
    [InlineData("org/*", "org/app", true)]
    [InlineData("org/*", "org/*", true)]
    [InlineData("org/app", "ORG/APP", true)]
    [InlineData("org/*", "other/app", false)]
    [InlineData("org/app", "org/web", false)]
    [InlineData("org/*", "org2/*", false)]
    public void Repository_patterns_overlap_when_one_repository_could_match_both(string a, string b, bool overlap)
    {
        Assert.Equal(overlap, SecAgent.Connectors.Tenancy.RepositoryPattern.Overlaps(a, b));
        Assert.Equal(overlap, SecAgent.Connectors.Tenancy.RepositoryPattern.Overlaps(b, a));
    }

    [Fact]
    public void Multi_tenant_maps_repositories_by_pattern_and_never_falls_back()
    {
        using var sp = ConnectorTestKit.Services(All.MultiTenant(), b => b.Plugins());
        var t = sp.GetRequiredService<ITenantResolver>();
        Assert.Equal("contoso", t.ForRepository("contoso/web"));
        Assert.Equal("fabrikam", t.ForRepository("fabrikam/payments"));
        Assert.Throws<UnknownTenantException>(() => t.ForRepository("fabrikam/other"));
        Assert.Throws<UnknownTenantException>(() => t.ForRepository("unknown/repo"));
    }

    [Fact]
    public void Shared_model_provider_and_optional_connectors_resolve_per_tenant()
    {
        using var sp = ConnectorTestKit.Services(All.MultiTenant(), b => b.Plugins());
        var r = sp.GetRequiredService<ITenantConnectionResolver>();
        Assert.Equal("fake", r.Resolve("contoso", ConnectorKind.ModelProvider)!.Provider);      // Defaults (Wipro model gateway)
        Assert.Null(r.Resolve("contoso", ConnectorKind.Notifier));
        var notifiers = sp.GetRequiredService<IConnectorClientFactory<INotifierClient>>();
        Assert.False(notifiers.TryForTenant("contoso", out _));
        Assert.True(notifiers.TryForTenant("fabrikam", out _));
        Assert.Throws<ConnectorNotConfiguredException>(() => notifiers.ForTenant("contoso"));
        Assert.Throws<UnknownTenantException>(() => sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant("nobody"));
    }

    [Fact]
    public async Task Fake_tenants_never_see_each_others_data()
    {
        var world = new FakeConnectorWorld();
        using var sp = ConnectorTestKit.Services(All.TwoFakeTenants(), b => b.AddFakeConnectors(world));
        world.SourceControl.AddRepository("a", "shared/name").AddPullRequest(1, "a's PR", "f", "main", "1", "2");
        var scm = sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>();
        Assert.NotNull(await scm.ForTenant("a").GetPullRequestAsync("shared/name", 1, default));
        Assert.Null(await scm.ForTenant("b").GetPullRequestAsync("shared/name", 1, default));
        await sp.GetRequiredService<IConnectorClientFactory<INotifierClient>>().ForTenant("b").NotifyAsync(new("t", "s", NotificationLevel.Info, []), default);
        Assert.Empty(world.Notifier.Sent("a"));
        Assert.Single(world.Notifier.Sent("b"));
    }
}

public class SecretProviderTests
{
    [Fact]
    public async Task Secrets_resolve_by_scheme_and_errors_name_the_reference_only()
    {
        using var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes());
        var secrets = sp.GetRequiredService<ISecretProvider>();
        sp.GetRequiredService<InMemorySecretSource>().Set("x", "synthetic-value");
        Assert.Equal("synthetic-value", await secrets.GetSecretAsync(new SecretRef("memory:x"), default));
        Environment.SetEnvironmentVariable("SECAGENT_TEST_SYNTHETIC_SECRET", "from-env");
        try { Assert.Equal("from-env", await secrets.GetSecretAsync(new SecretRef("env:SECAGENT_TEST_SYNTHETIC_SECRET"), default)); }
        finally { Environment.SetEnvironmentVariable("SECAGENT_TEST_SYNTHETIC_SECRET", null); }
        var missing = await Assert.ThrowsAsync<ConnectorConfigurationException>(async () => await secrets.GetSecretAsync(new SecretRef("memory:nope"), default));
        Assert.Contains("memory:nope", missing.Message);
        await Assert.ThrowsAsync<ConnectorConfigurationException>(async () => await secrets.GetSecretAsync(new SecretRef("vault9:x"), default));
        await Assert.ThrowsAsync<ConnectorConfigurationException>(async () => await secrets.GetSecretAsync(new SecretRef("no-scheme"), default));
    }

    [Fact]
    public async Task Hosted_model_provider_without_its_env_key_reports_the_variable_name()
    {
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:ModelProvider:Provider"] = "openai-compatible";
        config["Connectors:Tenants:t1:ModelProvider:BaseUrl"] = "https://api.openai.test/v1";
        config["Connectors:Tenants:t1:ModelProvider:Secret"] = "env:SECAGENT_TEST_UNSET_OPENAI_KEY";
        config["Connectors:Tenants:t1:ModelProvider:Settings:Flavor"] = "openai";
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins());
        var model = sp.GetRequiredService<IConnectorClientFactory<IModelProviderClient>>().ForTenant("t1");
        var e = await Assert.ThrowsAsync<ConnectorConfigurationException>(() => model.CompleteAsync(new("m", [new(ModelRole.User, "hi")]), default));
        Assert.Contains("SECAGENT_TEST_UNSET_OPENAI_KEY is not set", e.Message);
    }
}

public class AuditAndResilienceTests
{
    [Fact]
    public async Task Every_call_is_audited_with_outcome_and_model_token_usage_and_no_payload()
    {
        var (sp, world, _) = ConnectorTestKit.Fakes();
        using var _sp = sp;
        world.Models.Respond(_ => "{\"ok\":true}");
        var model = sp.GetRequiredService<IConnectorClientFactory<IModelProviderClient>>().ForTenant("t1");
        await model.CompleteAsync(new("small-model", [new(ModelRole.User, "synthetic prompt text")], AgentName: "triage"), default);
        world.FailNext("notification.send", new ConnectorException("fake outage"));
        await Assert.ThrowsAsync<ConnectorException>(() => sp.GetRequiredService<IConnectorClientFactory<INotifierClient>>().ForTenant("t1").NotifyAsync(new("t", "s", NotificationLevel.Info, []), default));
        var audit = sp.GetRequiredService<InMemoryConnectorAuditLog>().Snapshot("t1");
        var call = Assert.Single(audit, a => a.Operation == "model.complete");
        Assert.Equal(("ok", "fake", ConnectorKind.ModelProvider, "small-model"), (call.Outcome, call.ConnectorId, call.Kind, call.Target));
        Assert.True(call.Metrics!["tokens_in"] > 0);
        Assert.Contains(audit, a => a.Operation == "notification.send" && a.Outcome == "failed");
        Assert.DoesNotContain(audit, a => (a.Error ?? "").Contains("synthetic prompt text") || (a.Target ?? "").Contains("synthetic prompt text"));
    }

    [Fact]
    public async Task Idempotent_calls_are_retried_on_transient_errors_but_writes_are_not()
    {
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Resilience:BaseDelay"] = "00:00:00.001"; config["Connectors:Resilience:UseJitter"] = "false";
        config["Connectors:Resilience:CircuitBreakerMinimumThroughput"] = "100";
        var world = new FakeConnectorWorld();
        using var sp = ConnectorTestKit.Services(config, b => b.AddFakeConnectors(world));
        world.SourceControl.AddRepository("t1", "acme/app").AddPullRequest(1, "t", "f", "main", "1", "2");
        var scm = sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant("t1");
        world.FailNext("pull_request.get", new ConnectorException("503", true, HttpStatusCode.ServiceUnavailable), times: 2);
        Assert.NotNull(await scm.GetPullRequestAsync("acme/app", 1, default));                              // read: retried, then succeeds
        Assert.Equal(2, world.InteractionsFor(ConnectorKind.SourceControl, "pull_request.get:fault").Count);
        world.FailNext("pull_request.create", new ConnectorException("503", true, HttpStatusCode.ServiceUnavailable));
        await Assert.ThrowsAsync<ConnectorException>(() => scm.CreatePullRequestAsync("acme/app", new("main", "f", "t", "b"), default));   // write: not retried
        Assert.Empty(world.InteractionsFor(ConnectorKind.SourceControl, "pull_request.create"));
        world.FailNext("pull_request.get", new ConnectorException("bad request", false, HttpStatusCode.BadRequest));
        await Assert.ThrowsAsync<ConnectorException>(() => scm.GetPullRequestAsync("acme/app", 1, default));   // permanent: not retried
    }

    [Fact]
    public async Task The_circuit_opens_per_tenant_after_repeated_failures()
    {
        var config = All.TwoFakeTenants();
        config["Connectors:Resilience:MaxRetryAttempts"] = "0";
        config["Connectors:Resilience:CircuitBreakerMinimumThroughput"] = "3";
        config["Connectors:Resilience:CircuitBreakerFailureRatio"] = "0.5";
        var world = new FakeConnectorWorld();
        using var sp = ConnectorTestKit.Services(config, b => b.AddFakeConnectors(world));
        var notifiers = sp.GetRequiredService<IConnectorClientFactory<INotifierClient>>();
        var n = new Notification("t", "s", NotificationLevel.Info, []);
        world.FailNext("notification.send", new ConnectorException("webhook down", true), times: 3);
        for (var i = 0; i < 3; i++) await Assert.ThrowsAsync<ConnectorException>(() => notifiers.ForTenant("a").NotifyAsync(n, default));
        var open = await Assert.ThrowsAsync<ConnectorException>(() => notifiers.ForTenant("a").NotifyAsync(n, default));
        Assert.Contains("circuit open", open.Message);
        Assert.True(open.IsTransient);
        await notifiers.ForTenant("b").NotifyAsync(n, default);   // tenant b has its own breaker
        Assert.Single(world.Notifier.Sent("b"));
        Assert.Empty(world.Notifier.Sent("a"));
    }

    [Fact]
    public async Task Http_connectors_retry_GET_on_503_honouring_Retry_After_but_never_POST()
    {
        var stub = new ScriptedStub((r, n) => r.Method == HttpMethod.Get && r.Path.EndsWith("/pulls/1") && n == 1
            ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new(TimeSpan.FromMilliseconds(10)) } }
            : r.Method == HttpMethod.Post ? HttpStub.Status(HttpStatusCode.ServiceUnavailable)
            : r.Path.EndsWith("/pulls/1") ? HttpStub.Json(new { number = 1, title = "t", html_url = "https://github.com/acme/app/pull/1", state = "open", head = new { @ref = "f", sha = "1" }, @base = new { @ref = "main", sha = "2" } })
            : HttpStub.Json(new { default_branch = "main" }));
        var config = GitHubSourceControlContractTests.Config();
        config["Connectors:Resilience:BaseDelay"] = "00:00:00.001";
        using var sp = ConnectorTestKit.Services(config, b => b.AddFakeConnectors().AddGitHubConnector(),
            s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        sp.GetRequiredService<InMemorySecretSource>().Set("github-token", "ghs_synthetic");
        var scm = sp.GetRequiredService<IConnectorClientFactory<ISourceControlClient>>().ForTenant("t1");
        Assert.Equal(1, (await scm.GetPullRequestAsync("acme/app", 1, default))!.Number);
        Assert.Equal(2, stub.Seen.Count(r => r.Path.EndsWith("/pulls/1")));
        var e = await Assert.ThrowsAsync<ConnectorException>(() => scm.CreatePullRequestAsync("acme/app", new("main", "fix/x", "t", "b"), default));
        Assert.True(e.IsTransient);
        Assert.Single(stub.Seen, r => r.Method == HttpMethod.Post);
    }
}

public class NoMergeTests
{
    static readonly Assembly[] ConnectorAssemblies =
    [
        typeof(ISourceControlClient).Assembly, typeof(ConnectorOptions).Assembly, typeof(GitHubConnector).Assembly, typeof(JiraConnector).Assembly,
        typeof(BlackDuckConnector).Assembly, typeof(OpenAICompatibleModelConnector).Assembly, typeof(TeamsNotifierConnector).Assembly, typeof(FakeConnectorWorld).Assembly,
    ];

    [Fact]
    public void No_connector_type_has_a_merge_approve_or_force_method()
    {
        var bad = ConnectorAssemblies.SelectMany(a => a.GetTypes())
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Where(m => !m.IsSpecialName && !t.Name.Contains('<'))
                .Where(m => m.Name.Contains("Merge", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("Approve", StringComparison.OrdinalIgnoreCase)
                            || m.Name.Contains("ForcePush", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("DeleteBranch", StringComparison.OrdinalIgnoreCase))
                .Select(m => $"{t.FullName}.{m.Name}"))
            .ToList();
        Assert.True(bad.Count == 0, string.Join(", ", bad));
    }

    [Fact]
    public void The_source_control_interfaces_expose_no_merge_capability()
    {
        var methods = typeof(ISourceControlClient).GetInterfaces().Append(typeof(ISourceControlClient)).SelectMany(i => i.GetMethods()).Select(m => m.Name).ToList();
        Assert.Contains("CreatePullRequestAsync", methods);
        Assert.DoesNotContain(methods, m => m.Contains("Merge") || m.Contains("Approve") || m.Contains("Delete") || m.Contains("Protect"));
        Assert.Contains("merge", GitHubConnector.Descriptor.NeverGranted);
    }

    [Theory]
    [InlineData("PUT", "/repos/acme/app/pulls/7/merge", true)]
    [InlineData("GET", "/repos/acme/app/pulls/7/merge", true)]
    [InlineData("POST", "/repos/acme/app/merges", true)]
    [InlineData("POST", "/repos/acme/app/merge-upstream", true)]
    [InlineData("POST", "/repos/acme/app/pulls/7/reviews", true)]
    [InlineData("PUT", "/repos/acme/app/branches/main/protection", true)]
    [InlineData("DELETE", "/repos/acme/app/git/refs/heads/main", true)]
    [InlineData("GET", "/repos/acme/app/pulls/7/reviews", false)]
    [InlineData("GET", "/repos/acme/app/pulls/7", false)]
    [InlineData("POST", "/repos/acme/app/pulls", false)]
    [InlineData("PATCH", "/repos/acme/app/git/refs/heads/fix/a", false)]
    public void The_github_http_guard_blocks_merge_and_protection_endpoints(string method, string path, bool forbidden) =>
        Assert.Equal(forbidden, NoMergeGuardHandler.IsForbidden(new HttpMethod(method), new Uri("https://api.github.com" + path)));

    [Fact]
    public async Task The_guard_runs_inside_the_github_http_client()
    {
        var stub = new ScriptedStub((_, _) => HttpStub.Status(HttpStatusCode.OK));
        using var sp = ConnectorTestKit.Services(GitHubSourceControlContractTests.Config(), b => b.AddFakeConnectors().AddGitHubConnector(),
            s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient("secagent.connector.github");
        await Assert.ThrowsAsync<ForbiddenConnectorOperationException>(() => http.PutAsync("https://api.github.test/repos/acme/app/pulls/1/merge", null));
        Assert.Empty(stub.Seen);
    }
}

public class CatalogAndHealthTests
{
    [Fact]
    public void The_catalog_lists_every_plugin_with_capabilities_for_the_connections_page()
    {
        using var sp = ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.Plugins());
        var d = sp.GetRequiredService<IConnectorCatalog>().Descriptors;
        foreach (var (kind, id) in new[] { (ConnectorKind.SourceControl, "github"), (ConnectorKind.IssueTracker, "jira"), (ConnectorKind.ScannerSource, "blackduck"),
                     (ConnectorKind.ModelProvider, "openai-compatible"), (ConnectorKind.Notifier, "teams") })
        {
            var x = Assert.Single(d, c => c.Kind == kind && c.Id == id);
            Assert.False(x.IsSimulated);
            Assert.NotEmpty(x.Capabilities);
            Assert.NotEmpty(x.ScopesRequested);
        }
        Assert.Equal(5, d.Count(c => c.Id == "fake" && c.IsSimulated));
        Assert.Contains(ConnectorCapabilities.VulnerabilityBacklogRead, d.Single(c => c.Id == "blackduck").Capabilities);
        Assert.DoesNotContain(d.Single(c => c.Id == "blackduck").Capabilities, c => c.Contains("write") || c.Contains("create"));
    }

    [Fact]
    public async Task Health_rows_cover_every_kind_and_probes_never_throw()
    {
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:SourceControl:Provider"] = "github";
        config["Connectors:Tenants:t1:SourceControl:BaseUrl"] = "https://api.github.test/";
        config["Connectors:Tenants:t1:SourceControl:Secret"] = "memory:missing";
        config["Connectors:Tenants:t1:Notifier:Provider"] = "none";
        var stub = new ScriptedStub((_, _) => HttpStub.Status(HttpStatusCode.InternalServerError));
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins(), s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        var rows = await sp.GetRequiredService<IConnectorHealthService>().GetStatusAsync("t1", probe: true, default);
        Assert.Equal(5, rows.Count);
        Assert.Equal(HealthState.Failing, rows.Single(r => r.Kind == ConnectorKind.SourceControl).Health!.State);
        Assert.Equal("memory:missing", rows.Single(r => r.Kind == ConnectorKind.SourceControl).SecretRef);   // a reference, never a value
        Assert.False(rows.Single(r => r.Kind == ConnectorKind.Notifier).Configured);
        Assert.Equal(HealthState.Healthy, rows.Single(r => r.Kind == ConnectorKind.IssueTracker).Health!.State);
    }
}

public class ModelAndNotifierConnectorTests
{
    [Fact]
    public async Task OpenAI_compatible_connector_sends_json_schema_output_and_reports_token_usage()
    {
        var stub = new ScriptedStub((r, _) => HttpStub.Json(new
        {
            id = "chatcmpl-synthetic", @object = "chat.completion", created = 1767225600, model = "gpt-test",
            choices = new[] { new { index = 0, message = new { role = "assistant", content = "{\"verdict\":\"true_positive\"}" }, finish_reason = "stop" } },
            usage = new { prompt_tokens = 42, completion_tokens = 7, total_tokens = 49 },
        }));
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:ModelProvider:Provider"] = "openai-compatible";
        config["Connectors:Tenants:t1:ModelProvider:BaseUrl"] = "https://api.openai.test/v1";
        config["Connectors:Tenants:t1:ModelProvider:Secret"] = "memory:openai";
        config["Connectors:Tenants:t1:ModelProvider:Settings:Flavor"] = "openai";
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins(), s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        sp.GetRequiredService<InMemorySecretSource>().Set("openai", "sk-synthetic-test");
        var model = sp.GetRequiredService<IConnectorClientFactory<IModelProviderClient>>().ForTenant("t1");
        var schema = System.Text.Json.JsonDocument.Parse("{\"type\":\"object\",\"properties\":{\"verdict\":{\"type\":\"string\"}},\"required\":[\"verdict\"],\"additionalProperties\":false}").RootElement;
        var resp = await model.CompleteAsync(new("gpt-test", [new(ModelRole.System, "sys"), new(ModelRole.User, "synthetic finding")], new StructuredOutput("triage_output", "SecAgent triage", schema),
            MaxOutputTokens: 256, AgentName: "triage"), default);
        Assert.Equal("{\"verdict\":\"true_positive\"}", resp.Text);
        Assert.Equal((42L, 7L), (resp.Usage.InputTokens, resp.Usage.OutputTokens));
        Assert.Equal("openai", model.ProviderFamily);
        Assert.Null(await model.ListAvailableModelsAsync(default));   // hosted: no catalogue probe
        var req = Assert.Single(stub.Seen);
        Assert.Equal(("Bearer", "sk-synthetic-test"), (req.AuthScheme, req.AuthParameter));
        Assert.EndsWith("/chat/completions", req.Path);
        Assert.Equal("json_schema", (string?)req.Json!["response_format"]!["type"]);
        Assert.Equal("triage_output", (string?)req.Json!["response_format"]!["json_schema"]!["name"]);
        Assert.Equal("gpt-test", (string?)req.Json!["model"]);
    }

    [Fact]
    public async Task OpenAI_compatible_errors_map_to_transient_connector_exceptions()
    {
        var stub = new ScriptedStub((_, _) => HttpStub.Status(HttpStatusCode.TooManyRequests));
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:ModelProvider:Provider"] = "openai-compatible";
        config["Connectors:Tenants:t1:ModelProvider:BaseUrl"] = "http://localhost:11434/v1";
        config["Connectors:Tenants:t1:ModelProvider:Settings:Flavor"] = "ollama";
        config["Connectors:Resilience:MaxRetryAttempts"] = "0";
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins(), s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        var model = sp.GetRequiredService<IConnectorClientFactory<IModelProviderClient>>().ForTenant("t1");
        var e = await Assert.ThrowsAsync<ConnectorException>(() => model.CompleteAsync(new("qwen", [new(ModelRole.User, "x")]), default));
        Assert.True(e.IsTransient);
        Assert.Null(await model.ListAvailableModelsAsync(default));   // no HealthUrl: every configured model is a candidate
    }

    [Fact]
    public async Task Teams_notifier_posts_an_adaptive_card_to_the_webhook_from_the_secret()
    {
        var stub = new ScriptedStub((_, _) => HttpStub.Status(HttpStatusCode.Accepted));
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:Notifier:Provider"] = "teams";
        config["Connectors:Tenants:t1:Notifier:Secret"] = "memory:teams-webhook";
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins(), s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        sp.GetRequiredService<InMemorySecretSource>().Set("teams-webhook", "https://prod.workflows.test/workflows/abc/triggers/manual/paths/invoke?sig=synthetic");
        await sp.GetRequiredService<IConnectorClientFactory<INotifierClient>>().ForTenant("t1")
            .NotifyAsync(new("SecAgent · acme/app #7", "Run awaiting_human_review", NotificationLevel.Warning, [new("Findings", "3")], "https://github.com/acme/app/pull/7", "Open"), default);
        var post = Assert.Single(stub.Seen);
        Assert.Equal(HttpMethod.Post, post.Method);
        Assert.StartsWith("/workflows/abc/", post.Path);
        var card = post.Json!["attachments"]![0]!["content"]!;
        Assert.Equal(("AdaptiveCard", "1.4"), ((string?)card["type"], (string?)card["version"]));
        Assert.Equal("Findings", (string?)card["body"]![2]!["facts"]![0]!["title"]);
        Assert.Equal("Warning", (string?)card["body"]![0]!["color"]);
    }
}

public class RestClientSafetyTests
{
    [Fact]
    public async Task Server_links_to_another_host_are_not_followed_with_tenant_credentials()
    {
        var stub = new ScriptedStub((r, _) => r.Path.EndsWith("/tokens/authenticate") ? HttpStub.Json(new { bearerToken = "b", expiresInMilliseconds = 60000000 })
            : HttpStub.Json(new { totalCount = 1, items = new[] { new { name = "p", _meta = new { href = "https://evil.example/api/projects/p-1" } } } }));
        var config = ConnectorTestKit.AllFakes();
        config["Connectors:Tenants:t1:ScannerSource:Provider"] = "blackduck";
        config["Connectors:Tenants:t1:ScannerSource:BaseUrl"] = BlackDuckSimulator.Base;
        config["Connectors:Tenants:t1:ScannerSource:Secret"] = "memory:bd";
        using var sp = ConnectorTestKit.Services(config, b => b.Plugins(), s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => stub)));
        sp.GetRequiredService<InMemorySecretSource>().Set("bd", "synthetic");
        var e = await Assert.ThrowsAsync<ConnectorException>(() => sp.GetRequiredService<IConnectorClientFactory<IScannerSourceClient>>().ForTenant("t1").FindProjectVersionAsync("p", "1", default));
        Assert.Contains("another host", e.Message);
        Assert.DoesNotContain(stub.Seen, r => r.Path.Contains("p-1"));
    }
}
