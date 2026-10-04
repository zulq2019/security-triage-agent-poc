using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Agents;
using SecAgent.Abstractions.Intake;
using SecAgent.Agents;
using SecAgent.Core;
using SecAgent.Hosting;
using SecAgent.Hosting.Azure;
using SecAgent.Intake.Application;
using SecAgent.Intake.Runs;
using SecAgent.Worker;
using SecAgent.Worker.Roles;
using Xunit;

namespace SecAgent.Tests;

/// <summary>Shared helpers: compose the worker host for a role exactly as Program.cs does, with test configuration.</summary>
static class WorkerKit
{
    public static readonly string[] WorkerRoles =
        ["intake", "orchestrator", "scanner", "triage", "fixer-library", "fixer-secret", "fixer-code", "fixer-binary", "verifier", "audit-writer"];

    public static Dictionary<string, string?> Config(string role, string dataRoot, string transport = AgentTransportKeys.InProcess) => new()
    {
        ["Agent:Role"] = role,
        ["Agent:Transport"] = transport,
        ["Agent:ContentRoot"] = TestEnv.RepoRoot,
        ["Agent:DataRoot"] = dataRoot,
        ["Agent:ReceiveWaitSeconds"] = "1",
        // Composition only: nothing connects until a service is resolved. Synthetic value, not a real server.
        ["SECAGENT_SQL"] = "Server=127.0.0.1,1;Database=none;User Id=none;Password=none;TrustServerCertificate=True",
    };

    public static (ServiceProvider Sp, SelectedAgentRole Selected) Compose(Dictionary<string, string?> config, AgentHostRegistry? registry = null) =>
        ComposeWith(config, registry) is var (sp, selected, _) ? (sp, selected) : default;

    public static (ServiceProvider Sp, SelectedAgentRole Selected, IServiceCollection Services) ComposeWith(Dictionary<string, string?> config, AgentHostRegistry? registry = null)
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(config).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(cfg);
        var selected = services.AddSecAgentAgentHost(cfg, registry ?? WorkerRegistry.Create());
        return (services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true }), selected, services);
    }

    public static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "secagent-worker-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }
}

public class AgentCatalogTests
{
    static AgentCatalog Repo() => AgentCatalog.Load(Path.Combine(TestEnv.RepoRoot, "deploy", "agents.json"));

    [Fact]
    public void Catalog_lists_the_eleven_agents_of_the_target_architecture()
    {
        var c = Repo();
        Assert.Equal(["intake", "agent-api", "orchestrator", "scanner", "triage", "fixer-library", "fixer-secret", "fixer-code", "fixer-binary", "verifier", "audit-writer"],
            c.Agents.Select(a => a.Name));
        Assert.Equal("secagent", c.ImageRepositoryPrefix);
        Assert.All(c.Agents, a => Assert.Contains(a.ImageTarget, AgentCatalog.ImageTargets));
    }

    [Fact]
    public void Every_worker_agent_has_exactly_one_role_module_and_every_module_is_in_the_catalogue()
    {
        var c = Repo();
        var registry = WorkerRegistry.Create();
        var workerAgents = c.Agents.Where(a => a.Host == AgentHosts.Worker).Select(a => a.Name).Order().ToList();
        Assert.Equal(workerAgents, registry.Roles.Keys.Order().ToList());
        Assert.Equal(WorkerKit.WorkerRoles.Order(), workerAgents);
        Assert.Equal("dashboard", c.Find("agent-api")!.Host);
    }

    [Fact]
    public void Dispatcher_may_send_to_every_worker_queue_and_workers_only_to_results()
    {
        var c = Repo();
        Assert.Equal(["fix-binary", "fix-code", "fix-library", "fix-secret", "scan", "triage", "verify"], c.AllowedSends(c.Find("orchestrator")!).Order());
        Assert.Equal(["results"], c.AllowedSends(c.Find("scanner")!));
        Assert.Equal(["run-events/subscriptions/audit"], c.ConsumedEntities(c.Find("audit-writer")!));
    }

    [Theory]
    [InlineData("""{ "agents": [ { "name": "Bad_Name" } ] }""", "lowercase")]
    [InlineData("""{ "agents": [ { "name": "aa" }, { "name": "aa" } ] }""", "duplicate")]
    [InlineData("""{ "agents": [ { "name": "aa", "imageTarget": "fat" } ] }""", "imageTarget")]
    [InlineData("""{ "agents": [ { "name": "aa", "host": "lambda" } ] }""", "host")]
    public void Invalid_catalogue_is_refused(string json, string expected)
    {
        var e = Assert.Throws<AgentHostConfigurationException>(() => AgentCatalog.Parse(json));
        Assert.Contains(expected, e.Message);
    }

    /// <summary>KEDA scale rules, queues and RBAC are derived from infra/agents.bicep (PR #3). Once infra/ is on this branch the two lists must
    /// agree on names, consumed queues and subscriptions. Until then (this PR is stacked on #2, not #3) there is nothing to compare.</summary>
    [Fact]
    public void Catalogue_matches_the_bicep_agent_list_when_infra_is_present()
    {
        var bicep = Path.Combine(TestEnv.RepoRoot, "infra", "agents.bicep");
        if (!File.Exists(bicep)) return;
        var c = Repo();
        var parsed = BicepAgents(File.ReadAllText(bicep));
        Assert.Equal(c.Agents.Select(a => a.Name), parsed.Select(p => p.Name));
        foreach (var (name, consumes, subscribes) in parsed)
        {
            var a = c.Find(name)!;
            Assert.True(consumes.SequenceEqual(a.Consumes), $"{name}: consumes differ (bicep {string.Join(",", consumes)})");
            Assert.True(subscribes.SequenceEqual(a.Subscribes), $"{name}: subscribes differ (bicep {string.Join(",", subscribes)})");
        }
    }

    internal static List<(string Name, string[] Consumes, string[] Subscribes)> BicepAgents(string text)
    {
        static string[] List(string block, string key) =>
            Regex.Match(block, $@"\b{key}:\s*\[([^\]]*)\]") is { Success: true } m
                ? Regex.Matches(m.Groups[1].Value, "'([^']+)'").Select(x => x.Groups[1].Value).ToArray() : [];
        var start = text.IndexOf("defaultAgents", StringComparison.Ordinal);
        var body = text[start..text.IndexOf("\n]", start, StringComparison.Ordinal)];
        return Regex.Split(body, @"\n  \{").Skip(1)
            .Select(block => (Regex.Match(block, @"name:\s*'([^']+)'").Groups[1].Value, List(block, "consumes"), List(block, "subscribes")))
            .ToList();
    }

    [Fact]
    public void Bicep_parser_reads_the_pr3_catalogue_shape()
    {
        var sample = """
            @export()
            var defaultAgents agentSpec[] = [
              {
                name: 'scanner'
                consumes: ['scan']
                sends: ['results']
              }
              {
                name: 'audit-writer'
                subscribes: ['audit']
              }
            ]
            """.Replace("\r", "");
        var parsed = BicepAgents(sample);
        Assert.Equal(["scanner", "audit-writer"], parsed.Select(p => p.Name));
        Assert.Equal(["scan"], parsed[0].Consumes);
        Assert.Equal(["audit"], parsed[1].Subscribes);
    }

    /// <summary>One list: every agent has a compose service and an image target in the Dockerfile; the image workflow reads the catalogue.</summary>
    [Fact]
    public void Dockerfile_compose_and_workflows_are_driven_by_the_catalogue()
    {
        var c = Repo();
        var dockerfile = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "deploy", "Dockerfile"));
        foreach (var target in c.Agents.Select(a => a.ImageTarget).Distinct())
            Assert.Matches($@"(?m)^FROM \S+ AS {target}\s*$", dockerfile);
        var compose = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "docker-compose.yml"));
        foreach (var a in c.Agents) Assert.Matches($@"(?m)^  {Regex.Escape(a.Name)}:\s*$", compose);
        foreach (var a in c.Agents.Where(a => a.Host == AgentHosts.Worker)) Assert.Contains($"SECAGENT_AGENT: {a.Name}", compose);
        var images = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, ".github", "workflows", "build-images.yml"));
        Assert.Contains("deploy/agents.json", images);
        var deploy = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, ".github", "workflows", "deploy.yml"));
        Assert.Contains("deploy/agents.json", deploy);
        foreach (var a in c.Agents) Assert.DoesNotContain($"- {a.Name}\n", images);   // no hard-coded matrix
    }
}

public class AgentRoleRegistrationTests
{
    [Theory]
    [MemberData(nameof(Roles))]
    public void Each_role_composes_and_handles_exactly_the_entities_its_catalogue_entry_consumes(string role)
    {
        var data = WorkerKit.TempDir();
        var (sp, selected, services) = WorkerKit.ComposeWith(WorkerKit.Config(role, data));
        using var _ = sp;
        Assert.Equal(role, selected.Context.Spec.Name);
        Assert.Equal(role, selected.Module.Role);
        var handled = sp.GetServices<AgentHandlerRegistration>().Select(r => r.Entity).ToHashSet();
        var expected = selected.Context.ConsumedEntities.ToHashSet();
        if (role == "orchestrator")
        {
            // `runs` is consumed by the intake's IntakeRunDispatcher (same code path as POST /api/runs), not by a generic handler.
            // Checked on the descriptors: resolving it would build the pipeline (and connect to SQL).
            Assert.Contains(services, d => d.ServiceType == typeof(IntakeRunDispatcher));
            Assert.Contains(services, d => d.ServiceType == typeof(IHostedService) && d.ImplementationFactory != null);
            expected.Remove("runs");
        }
        Assert.Equal(expected.Order(), handled.Order());
        Assert.Contains(services, d => d.ServiceType == typeof(AgentQueueConsumer));
        Assert.IsType<CatalogScopedPublisher>(sp.GetRequiredService<IAgentQueuePublisher>());
    }

    public static TheoryData<string> Roles() => new(WorkerKit.WorkerRoles);

    [Theory]
    [InlineData("scanner")]
    [InlineData("triage")]
    [InlineData("verifier")]
    [InlineData("audit-writer")]
    public void Handlers_of_roles_without_a_database_resolve_from_the_container(string role)
    {
        var (sp, _) = WorkerKit.Compose(WorkerKit.Config(role, WorkerKit.TempDir()));
        using var __ = sp;
        using var scope = sp.CreateScope();
        foreach (var reg in sp.GetServices<AgentHandlerRegistration>())
            Assert.IsAssignableFrom<IAgentMessageHandler>(scope.ServiceProvider.GetRequiredService(reg.HandlerType));
    }

    [Fact]
    public void Intake_role_serves_the_webhook_and_never_starts_runs()
    {
        var (sp, selected) = WorkerKit.Compose(WorkerKit.Config("intake", WorkerKit.TempDir()));
        using var _ = sp;
        Assert.IsAssignableFrom<IAgentRoleEndpoints>(selected.Module);
        Assert.NotNull(sp.GetRequiredService<IIntakeWebhookHandler>());
        var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecAgent.Intake.Configuration.IntakeOptions>>().Value;
        Assert.False(opts.DispatcherEnabled);
        Assert.False(sp.GetRequiredService<IRunAdmission>().CanStartRun);
        Assert.Empty(sp.GetServices<AgentHandlerRegistration>());
    }

    [Fact]
    public void Scanner_role_registers_the_four_scanner_adapters_and_needs_no_database()
    {
        var cfg = WorkerKit.Config("scanner", WorkerKit.TempDir());
        cfg.Remove("SECAGENT_SQL");
        var (sp, _) = WorkerKit.Compose(cfg);
        using var __ = sp;
        Assert.Equal(["binary_check", "gitleaks", "semgrep", "trivy"], sp.GetServices<SecAgent.Agents.IScannerAdapter>().Select(a => a.Id).Order());
    }

    [Fact]
    public void Orchestrator_wires_connector_ports_from_the_shipped_worker_settings()
    {
        var cfg = WorkerKit.Config("orchestrator", WorkerKit.TempDir());
        var shipped = new ConfigurationBuilder().AddJsonFile(Path.Combine(TestEnv.RepoRoot, "src", "SecAgent.Worker", "appsettings.json")).Build();
        foreach (var (k, v) in shipped.AsEnumerable().Where(kv => kv.Key.StartsWith("Connectors"))) cfg[k] = v;
        var (sp, _) = WorkerKit.Compose(cfg);
        using var __ = sp;
        // Resolving the connector ports needs no SQL (the pipeline itself is not built here).
        var ports = sp.GetRequiredService<SecAgent.Agents.PipelineConnectors>();
        var tenant = ports.Tenants.ForRepository("zulq2019/sec-agent-sample-app");
        Assert.Equal("local", tenant);
        Assert.Equal("github", sp.GetRequiredService<SecAgent.Connectors.ITenantConnectionResolver>().Resolve(tenant, SecAgent.Connectors.ConnectorKind.SourceControl)!.Provider);
    }

    [Fact]
    public void Orchestrator_without_sql_fails_at_composition()
    {
        var cfg = WorkerKit.Config("orchestrator", WorkerKit.TempDir());
        cfg.Remove("SECAGENT_SQL");
        var e = Assert.Throws<AgentHostConfigurationException>(() => WorkerKit.Compose(cfg));
        Assert.Contains("SECAGENT_SQL", e.Message);
    }

    [Theory]
    [InlineData("", "SECAGENT_AGENT")]
    [InlineData("nope", "not in")]
    [InlineData("agent-api", "dashboard host")]
    public void Bad_role_fails_fast_with_a_clear_message(string role, string expected)
    {
        var e = Assert.Throws<AgentHostConfigurationException>(() => WorkerKit.Compose(WorkerKit.Config(role, WorkerKit.TempDir())));
        Assert.Contains(expected, e.Message);
    }

    [Fact]
    public void Role_in_catalogue_but_not_in_this_host_is_refused()
    {
        var registry = new AgentHostRegistry().AddTransport(new InProcessTransportModule()).AddRole(new ScannerRole());
        var e = Assert.Throws<AgentHostConfigurationException>(() => WorkerKit.Compose(WorkerKit.Config("triage", WorkerKit.TempDir()), registry));
        Assert.Contains("This host runs: scanner", e.Message);
    }

    [Fact]
    public void Unknown_transport_is_refused_and_servicebus_needs_a_namespace()
    {
        var e = Assert.Throws<AgentHostConfigurationException>(() => WorkerKit.Compose(WorkerKit.Config("triage", WorkerKit.TempDir(), "carrier-pigeon")));
        Assert.Contains("unknown queue transport", e.Message);
        e = Assert.Throws<AgentHostConfigurationException>(() => WorkerKit.Compose(WorkerKit.Config("triage", WorkerKit.TempDir(), AgentTransportKeys.ServiceBus)));
        Assert.Contains("SECAGENT_SERVICEBUS_NAMESPACE", e.Message);
    }

    [Fact]
    public void Servicebus_transport_composes_with_a_namespace_without_connecting()
    {
        var cfg = WorkerKit.Config("triage", WorkerKit.TempDir(), AgentTransportKeys.ServiceBus);
        cfg["Agent:ServiceBus:Namespace"] = "sb-secagent-dev-uks-00000.servicebus.windows.net";
        var (sp, selected) = WorkerKit.Compose(cfg);
        using var _ = sp;
        Assert.Equal("servicebus", selected.Transport);
        Assert.Equal(("run-events", "audit"), ServiceBusAgentTransport.SplitSubscription("run-events/subscriptions/audit"));
        Assert.Equal((null, null), ServiceBusAgentTransport.SplitSubscription("scan"));
    }

    [Fact]
    public void Bicep_environment_names_map_onto_the_agent_section()
    {
        var env = new Dictionary<string, string> { ["SECAGENT_AGENT"] = "scanner", ["SECAGENT_QUEUE"] = "servicebus", ["SECAGENT_SERVICEBUS_NAMESPACE"] = "sb.example", ["SECAGENT_DATA_ROOT"] = "/data" };
        var cfg = new ConfigurationBuilder().AddSecAgentEnvironmentAliases(k => env.GetValueOrDefault(k)).Build();
        Assert.Equal("scanner", cfg["Agent:Role"]);
        Assert.Equal("servicebus", cfg["Agent:Transport"]);
        Assert.Equal("sb.example", cfg["Agent:ServiceBus:Namespace"]);
        Assert.Equal("/data", cfg["Agent:DataRoot"]);
    }

    [Fact]
    public void A_handler_for_an_entity_the_role_does_not_consume_is_refused()
    {
        var ctx = new AgentRoleContext(new AgentSpec { Name = "triage", Consumes = ["triage"] }, new AgentCatalog(), new AgentHostOptions(), new ConfigurationBuilder().Build());
        var e = Assert.Throws<AgentHostConfigurationException>(() => new ServiceCollection().AddAgentMessageHandler<DeferredStepHandlerProbe>(ctx, "scan"));
        Assert.Contains("does not consume 'scan'", e.Message);
    }

    sealed class DeferredStepHandlerProbe : IAgentMessageHandler
    {
        public Task HandleAsync(AgentDeliveryContext context, CancellationToken ct) => Task.CompletedTask;
    }

    [Fact]
    public async Task Publisher_enforces_the_catalogue_like_service_bus_rbac()
    {
        var c = AgentCatalog.Load(Path.Combine(TestEnv.RepoRoot, "deploy", "agents.json"));
        var cfg = new ConfigurationBuilder().Build();
        var sink = new RecordingPublisher();
        var scanner = new CatalogScopedPublisher(sink, new AgentRoleContext(c.Find("scanner")!, c, new AgentHostOptions(), cfg));
        var orch = new CatalogScopedPublisher(sink, new AgentRoleContext(c.Find("orchestrator")!, c, new AgentHostOptions(), cfg));
        var msg = new AgentMessage("m1", Guid.NewGuid().ToString(), "t", "{}");
        await scanner.PublishAsync("results", msg, default);
        await Assert.ThrowsAsync<QueueNotAllowedException>(() => scanner.PublishAsync("fix-library", msg, default));
        await Assert.ThrowsAsync<QueueNotAllowedException>(() => scanner.PublishToTopicAsync("run-events", ["audit"], msg, default));
        await orch.PublishAsync("fix-library", msg, default);
        await orch.PublishToTopicAsync("run-events", ["audit"], msg, default);
        await Assert.ThrowsAsync<QueueNotAllowedException>(() => orch.PublishAsync("results", msg, default));
        Assert.Equal(["results", "fix-library", "run-events"], sink.Sent);
    }
}

sealed class RecordingPublisher : IAgentQueuePublisher
{
    public List<string> Sent { get; } = [];
    public List<(string Entity, AgentMessage Message)> Messages { get; } = [];
    public Task PublishAsync(string queue, AgentMessage message, CancellationToken ct) { lock (Sent) { Sent.Add(queue); Messages.Add((queue, message)); } return Task.CompletedTask; }
    public Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct) { lock (Sent) { Sent.Add(topic); Messages.Add((topic, message)); } return Task.CompletedTask; }
}

public class FileSystemMessageQueueTests
{
    [Fact]
    public void Publish_receive_complete_in_fifo_order_with_duplicate_detection()
    {
        var q = new FileSystemMessageQueue(WorkerKit.TempDir());
        Assert.True(q.Publish("scan", "a", "{\"n\":1}"));
        Assert.True(q.Publish("scan", "b", "{\"n\":2}"));
        Assert.False(q.Publish("scan", "a", "{\"n\":1}"));   // duplicate within the window
        Assert.True(q.TryReceive("scan", out var m1));
        Assert.Equal("a", m1!.MessageId);
        Assert.Equal(1, m1.DeliveryCount);
        q.Complete(m1);
        Assert.True(q.TryReceive("scan", out var m2));
        Assert.Equal("b", m2!.MessageId);
        q.Complete(m2);
        Assert.False(q.TryReceive("scan", out _));
    }

    [Fact]
    public void Abandon_redelivers_then_dead_letters_after_max_deliveries()
    {
        var q = new FileSystemMessageQueue(WorkerKit.TempDir(), maxDeliveries: 2);
        q.Publish("triage", "x", "{}");
        Assert.True(q.TryReceive("triage", out var m));
        q.Abandon(m!, "boom 1");
        Assert.True(q.TryReceive("triage", out m));
        Assert.Equal(2, m!.DeliveryCount);
        q.Abandon(m, "boom 2");
        Assert.False(q.TryReceive("triage", out _));
        var dlq = Assert.Single(q.DeadLetters("triage"));
        Assert.Equal("boom 2", dlq.Error);
    }

    [Fact]
    public void Two_processes_sharing_the_folder_never_get_the_same_message()
    {
        var root = WorkerKit.TempDir();
        var a = new FileSystemMessageQueue(root);
        var b = new FileSystemMessageQueue(root);
        for (var i = 0; i < 50; i++) a.Publish("verify", $"m{i}", "{}");
        var got = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, 4, w =>
        {
            var q = w % 2 == 0 ? a : b;
            while (q.TryReceive("verify", out var m)) { got.Add(m!.MessageId); q.Complete(m); }
        });
        Assert.Equal(50, got.Count);
        Assert.Equal(50, got.Distinct().Count());
    }

    [Fact]
    public void An_expired_claim_is_put_back_like_a_service_bus_lock()
    {
        var root = WorkerKit.TempDir();
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var crashed = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        crashed.Publish("scan", "c", "{}");
        Assert.True(crashed.TryReceive("scan", out _));          // claimed, never settled (consumer died)
        clock.Now += TimeSpan.FromMinutes(2);
        var other = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        Assert.True(other.TryReceive("scan", out var again));
        Assert.Equal(2, again!.DeliveryCount);
    }

    [Fact]
    public void Subscription_entities_map_to_safe_folder_names()
    {
        Assert.Equal("run-events_subscriptions_audit", FileSystemMessageQueue.SafeName("run-events/subscriptions/audit"));
        Assert.Equal("___etc", FileSystemMessageQueue.SafeName("../etc"));
        Assert.Equal("__", FileSystemMessageQueue.SafeName(".."));
    }
}

/// <summary>The generic consumer, end to end on the in-process transport with a test catalogue and a test role.</summary>
public sealed class AgentQueueConsumerTests
{
    sealed class Probe
    {
        public readonly List<string> Seen = [];
        public Func<AgentDeliveryContext, CancellationToken, Task> Behaviour = (_, _) => Task.CompletedTask;
        public readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    sealed class ProbeHandler(Probe probe) : IAgentMessageHandler
    {
        public async Task HandleAsync(AgentDeliveryContext context, CancellationToken ct)
        {
            lock (probe.Seen) probe.Seen.Add(context.Message.MessageId);
            probe.Started.TrySetResult();
            await probe.Behaviour(context, ct);
        }
    }

    sealed class ProbeRole(Probe probe) : IAgentRoleModule
    {
        public string Role => "probe-agent";
        public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
        {
            services.AddSingleton(probe);
            services.AddAgentMessageHandler<ProbeHandler>(context, "probe-q");
        }
    }

    static async Task<(WebApplication App, IMessageQueue Queue, string Base)> Start(Probe probe, int drainSeconds = 5, int lockRenewalSeconds = 30)
    {
        var dir = WorkerKit.TempDir();
        var catalog = Path.Combine(dir, "agents.json");
        File.WriteAllText(catalog, """{ "agents": [ { "name": "probe-agent", "consumes": ["probe-q"], "sends": ["results"] } ] }""");
        var b = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        b.Logging.ClearProviders();
        b.WebHost.UseUrls("http://127.0.0.1:0");
        b.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Agent:Role"] = "probe-agent", ["Agent:ContentRoot"] = TestEnv.RepoRoot, ["Agent:DataRoot"] = dir, ["Agent:CatalogPath"] = catalog,
            ["Agent:ReceiveWaitSeconds"] = "1", ["Agent:DrainTimeoutSeconds"] = drainSeconds.ToString(), ["Agent:MaxDeliveries"] = "2",
            ["Agent:LockRenewalSeconds"] = lockRenewalSeconds.ToString(),
        });
        b.Services.AddSecAgentAgentHost(b.Configuration, new AgentHostRegistry().AddTransport(new InProcessTransportModule()).AddRole(new ProbeRole(probe)));
        var app = b.Build();
        app.MapSecAgentAgentHost();
        await app.StartAsync();
        var url = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First().TrimEnd('/');
        return (app, app.Services.GetRequiredService<IMessageQueue>(), url);
    }

    static void Send(IMessageQueue q, string id) =>
        q.Publish("probe-q", id, JsonSerializer.Serialize(new AgentMessage(id, Guid.NewGuid().ToString(), "test", "{}"), new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    static async Task Until(Func<bool> condition, int ms = 10000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (!condition()) { if (DateTime.UtcNow > until) throw new TimeoutException(); await Task.Delay(50); }
    }

    [Fact]
    public async Task Messages_are_handled_and_completed_failures_retry_then_dead_letter_rejections_dead_letter_at_once()
    {
        var probe = new Probe();
        probe.Behaviour = (c, _) => c.Message.MessageId switch
        {
            "fails" => throw new InvalidOperationException("transient"),
            "poison" => throw new AgentMessageRejectedException("bad shape"),
            _ => Task.CompletedTask,
        };
        var (app, q, _) = await Start(probe);
        try
        {
            Send(q, "ok"); Send(q, "fails"); Send(q, "poison");
            await Until(() => q.DeadLetters("probe-q").Count == 2);
            lock (probe.Seen)
            {
                Assert.Single(probe.Seen, "ok");
                Assert.Equal(2, probe.Seen.Count(s => s == "fails"));   // MaxDeliveries = 2
                Assert.Single(probe.Seen, "poison");                     // no retry
            }
            Assert.Equal(["fails", "poison"], q.DeadLetters("probe-q").Select(m => m.MessageId).Order());
        }
        finally { await app.StopAsync(); await app.DisposeAsync(); }
    }

    [Fact]
    public async Task Shutdown_drains_the_in_flight_message_and_readiness_goes_down_first()
    {
        var probe = new Probe();
        var release = new TaskCompletionSource();
        var finished = false;
        probe.Behaviour = async (_, ct) => { await release.Task.WaitAsync(ct); await Task.Delay(200, ct); finished = true; };
        var (app, q, url) = await Start(probe, drainSeconds: 10);
        using var http = new HttpClient();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync($"{url}/readyz")).StatusCode);
        Send(q, "slow");
        await probe.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var readiness = app.Services.GetRequiredService<AgentReadiness>();
        var stop = app.StopAsync();
        await Until(() => readiness.IsDraining);
        release.SetResult();
        await stop;
        Assert.True(finished);                                     // not cancelled: it got the drain window
        Assert.Empty(q.DeadLetters("probe-q"));
        Assert.False(q.TryReceive("probe-q", out _));              // completed, not abandoned
        await app.DisposeAsync();
    }

    [Fact]
    public async Task A_message_still_running_at_the_drain_deadline_is_cancelled_and_abandoned_for_redelivery()
    {
        var probe = new Probe();
        probe.Behaviour = (_, ct) => Task.Delay(Timeout.Infinite, ct);
        var (app, q, _) = await Start(probe, drainSeconds: 0);
        Send(q, "stuck");
        await probe.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await app.StopAsync();
        Assert.True(q.TryReceive("probe-q", out var again));      // back on the queue
        Assert.Equal("shutdown: drain timeout", again!.Error);
        await app.DisposeAsync();
    }

    [Fact]
    public async Task Health_endpoints_report_liveness_and_readiness_with_the_role()
    {
        var (app, _, url) = await Start(new Probe());
        try
        {
            using var http = new HttpClient();
            var live = await http.GetAsync($"{url}/healthz");
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);
            var ready = JsonDocument.Parse(await http.GetStringAsync($"{url}/readyz")).RootElement;
            Assert.Equal("Healthy", ready.GetProperty("status").GetString());
            var checks = ready.GetProperty("checks").EnumerateArray().ToDictionary(c => c.GetProperty("name").GetString()!, c => c.GetProperty("detail").GetString());
            Assert.Contains("role=probe-agent", checks["role"]);
            Assert.Equal(["consumer", "role", "transport"], checks.Keys.Order());
            Assert.Equal(0, await HealthProbe.RunAsync($"{url}/readyz"));
            Assert.Equal(1, await HealthProbe.RunAsync("http://127.0.0.1:1/healthz"));
        }
        finally { await app.StopAsync(); await app.DisposeAsync(); }
    }
}

/// <summary>Lock renewal and settlement failures in the generic consumer, driven with a fake delivery (no broker).</summary>
public sealed class AgentConsumerLockTests
{
    sealed class FakeDelivery : IAgentDelivery
    {
        public AgentMessage Message { get; } = new("m-" + Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString(), "test", "{}");
        public int DeliveryCount => 1;
        public int Renewals;
        public bool FailSettlement;
        public string? Settled;
        public Task CompleteAsync(CancellationToken ct) => Settle("complete");
        public Task AbandonAsync(string error, CancellationToken ct) => Settle("abandon");
        public Task DeadLetterAsync(string reason, CancellationToken ct) => Settle("dead-letter");
        Task Settle(string how) { Settled = how; return FailSettlement ? Task.FromException(new InvalidOperationException("lock lost")) : Task.CompletedTask; }
        public Task<bool> RenewLockAsync(CancellationToken ct) { Interlocked.Increment(ref Renewals); return Task.FromResult(true); }
    }

    sealed class SlowHandler : IAgentMessageHandler
    {
        public static TimeSpan Duration = TimeSpan.Zero;
        public Task HandleAsync(AgentDeliveryContext context, CancellationToken ct) => Task.Delay(Duration, ct);
    }

    sealed class SlowRole : IAgentRoleModule
    {
        public string Role => "slow-agent";
        public void ConfigureServices(IServiceCollection services, AgentRoleContext context) => services.AddAgentMessageHandler<SlowHandler>(context, "slow-q");
    }

    static (IHost Host, AgentQueueConsumer Consumer, AgentHandlerRegistration Reg) Compose(int lockRenewalSeconds)
    {
        var dir = WorkerKit.TempDir();
        var catalog = Path.Combine(dir, "agents.json");
        File.WriteAllText(catalog, """{ "agents": [ { "name": "slow-agent", "consumes": ["slow-q"], "sends": ["results"] } ] }""");
        var b = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Testing" });
        b.Logging.ClearProviders();
        b.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Agent:Role"] = "slow-agent", ["Agent:ContentRoot"] = TestEnv.RepoRoot, ["Agent:DataRoot"] = dir, ["Agent:CatalogPath"] = catalog,
            ["Agent:LockRenewalSeconds"] = lockRenewalSeconds.ToString(),
        });
        b.Services.AddSecAgentAgentHost(b.Configuration, new AgentHostRegistry().AddTransport(new InProcessTransportModule()).AddRole(new SlowRole()));
        var host = b.Build();   // not started: ProcessAsync is driven directly
        var consumer = host.Services.GetServices<IHostedService>().OfType<AgentQueueConsumer>().Single();
        return (host, consumer, host.Services.GetServices<AgentHandlerRegistration>().Single());
    }

    [Fact]
    public async Task The_lock_is_renewed_while_a_long_handler_runs_and_renewal_stops_with_it()
    {
        var (host, consumer, reg) = Compose(lockRenewalSeconds: 1);
        using var _ = host;
        SlowHandler.Duration = TimeSpan.FromMilliseconds(2600);
        var d = new FakeDelivery();
        await consumer.ProcessAsync(reg, d);
        Assert.Equal("complete", d.Settled);
        Assert.InRange(d.Renewals, 2, 3);
        var after = d.Renewals;
        await Task.Delay(1300);
        Assert.Equal(after, d.Renewals);   // the renewal loop ended with the handler
    }

    [Fact]
    public async Task A_failing_settlement_is_logged_and_does_not_escape_the_consumer()
    {
        var (host, consumer, reg) = Compose(lockRenewalSeconds: 0);   // 0 = renewal off
        using var _ = host;
        SlowHandler.Duration = TimeSpan.Zero;
        var d = new FakeDelivery { FailSettlement = true };
        await consumer.ProcessAsync(reg, d);   // would previously throw and end the receive loop
        Assert.Equal("complete", d.Settled);
        Assert.Equal(0, d.Renewals);
        Assert.Equal(0, consumer.InFlight);
    }
}

/// <summary>File-queue leases: renewal keeps a claim; a lost claim's late settlement never touches the peer that re-claimed it.</summary>
public sealed class FileQueueLeaseTests
{
    [Fact]
    public void Renewing_the_lease_keeps_the_claim_past_the_original_expiry()
    {
        var root = WorkerKit.TempDir();
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var a = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        a.Publish("scan", "long", "{}");
        Assert.True(a.TryReceive("scan", out var m));
        clock.Now += TimeSpan.FromSeconds(50);
        Assert.True(a.RenewLease(m!));
        clock.Now += TimeSpan.FromSeconds(50);   // 100 s after the claim, 50 s after the renewal
        var b = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        Assert.False(b.TryReceive("scan", out _));
        a.Complete(m!);
        Assert.Equal(0, a.ReadyCount("scan"));
    }

    [Fact]
    public void A_late_complete_or_abandon_after_the_lease_expired_leaves_the_peers_claim_alone()
    {
        var root = WorkerKit.TempDir();
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var slow = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        slow.Publish("scan", "x", "{}");
        slow.Publish("scan", "y", "{}");
        Assert.True(slow.TryReceive("scan", out var x1));
        Assert.True(slow.TryReceive("scan", out var y1));
        clock.Now += TimeSpan.FromMinutes(2);   // both leases expire
        var peer = new FileSystemMessageQueue(root, lease: TimeSpan.FromMinutes(1), clock: clock);
        Assert.True(peer.TryReceive("scan", out var x2));
        Assert.True(peer.TryReceive("scan", out var y2));
        Assert.Equal(["x", "y"], new[] { x2!.MessageId, y2!.MessageId }.Order());   // frozen clock: same enqueue tick, order not asserted

        Assert.False(slow.RenewLease(x1!));   // the claim is gone
        slow.Complete(x1!);                    // late settlements: no-ops
        slow.Abandon(y1!, "late");
        Assert.Equal(0, peer.ReadyCount("scan"));                       // nothing duplicated back to ready/
        Assert.Equal(2, Directory.EnumerateFiles(Path.Combine(root, "scan", "inflight")).Count());   // peer's claims intact
        Assert.True(peer.RenewLease(x2));
        peer.Complete(x2);
        peer.Complete(y2);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(root, "scan", "inflight")));
        Assert.Empty(peer.DeadLetters("scan"));
    }
}

/// <summary>Service Bus readiness does a real broker operation, so a namespace that cannot be reached is not ready.</summary>
public sealed class ServiceBusReadinessTests
{
    sealed class FakeCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("synthetic-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    [Fact]
    public async Task An_unreachable_namespace_reports_not_ready_even_though_the_client_is_open()
    {
        await using var client = new Azure.Messaging.ServiceBus.ServiceBusClient("secagent-test.servicebus.invalid", new FakeCredential(),
            new Azure.Messaging.ServiceBus.ServiceBusClientOptions
            {
                RetryOptions = new Azure.Messaging.ServiceBus.ServiceBusRetryOptions { MaxRetries = 0, TryTimeout = TimeSpan.FromSeconds(5) },
            });
        var transport = new ServiceBusAgentTransport(client, new ServiceBusTransportOptions { Namespace = "secagent-test.servicebus.invalid" },
            new ServiceBusProbeTargets(["results"], []), TimeProvider.System);
        Assert.False(client.IsClosed);
        var (ok, detail) = await transport.CheckAsync(CancellationToken.None);
        Assert.False(ok);
        Assert.Contains("not usable", detail);
        await transport.DisposeAsync();
    }

    [Fact]
    public void Probe_targets_cover_sends_and_peekable_entities_but_never_session_queues()
    {
        var c = AgentCatalog.Load(Path.Combine(TestEnv.RepoRoot, "deploy", "agents.json"));
        var ctx = new AgentRoleContext(c.Find("audit-writer")!, c, new AgentHostOptions(), new ConfigurationBuilder().Build());
        var t = ServiceBusProbeTargets.For(ctx, new ServiceBusTransportOptions());
        Assert.All(t.PeekEntities, e => Assert.NotNull(ServiceBusAgentTransport.SplitSubscription(e).Topic));
        var orch = new AgentRoleContext(c.Find("orchestrator")!, c, new AgentHostOptions(), new ConfigurationBuilder().Build());
        var o = ServiceBusProbeTargets.For(orch, new ServiceBusTransportOptions());
        Assert.Contains(c.RunEventsTopic, o.SendEntities);
        Assert.DoesNotContain("results", o.PeekEntities);   // session-enabled queue: accepting a session would take it
    }
}

/// <summary>Run-event fan-out retries a failed publish instead of dropping the event (the audit writer's evidence).</summary>
public sealed class RunEventFanOutTests
{
    sealed class FlakyPublisher(int failures) : IAgentQueuePublisher
    {
        int _left = failures;
        public readonly List<string> Delivered = [];
        public int Attempts;
        public Task PublishAsync(string queue, AgentMessage message, CancellationToken ct) => throw new NotSupportedException();
        public Task PublishToTopicAsync(string topic, IReadOnlyList<string> subscriptions, AgentMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref Attempts);
            if (Interlocked.Decrement(ref _left) >= 0) throw new InvalidOperationException("broker unavailable");
            lock (Delivered) Delivered.Add(message.MessageId);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Events_are_retried_through_transient_failures_and_delivered_in_order()
    {
        var c = AgentCatalog.Load(Path.Combine(TestEnv.RepoRoot, "deploy", "agents.json"));
        var ctx = new AgentRoleContext(c.Find("orchestrator")!, c, new AgentHostOptions(), new ConfigurationBuilder().Build());
        var masker = new SecretMasker();
        var bus = new RunEventBus(masker);
        var publisher = new FlakyPublisher(failures: 3);
        var fanOut = new RunEventFanOut(bus, masker, publisher, ctx, new RunEventPublishRetry(TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(40)),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<RunEventFanOut>.Instance);
        await fanOut.StartAsync(CancellationToken.None);
        var run = Guid.NewGuid();
        bus.Publish(run, "a", new { });
        bus.Publish(run, "b", new { });
        var until = DateTime.UtcNow.AddSeconds(10);
        while (true) { lock (publisher.Delivered) if (publisher.Delivered.Count == 2) break; if (DateTime.UtcNow > until) throw new TimeoutException(); await Task.Delay(20); }
        await fanOut.StopAsync(CancellationToken.None);
        Assert.Equal([$"{run:N}:1", $"{run:N}:2"], publisher.Delivered);
        Assert.Equal(5, publisher.Attempts);
    }
}

/// <summary>Role handlers with test doubles for their ports (no scanners, no network).</summary>
public class WorkerRoleHandlerTests
{
    static AgentRoleContext Ctx(string role, string dataRoot)
    {
        var c = AgentCatalog.Load(Path.Combine(TestEnv.RepoRoot, "deploy", "agents.json"));
        return new AgentRoleContext(c.Find(role)!, c, new AgentHostOptions { DataRoot = dataRoot }, new ConfigurationBuilder().Build());
    }

    sealed class FakeFetcher : IRepositoryFetcher
    {
        public async Task<(string Dir, string CommitSha)> FetchAsync(ScanRequest request, string workDir, CancellationToken ct)
        {
            Directory.CreateDirectory(workDir);
            File.WriteAllText(Path.Combine(workDir, "Program.cs"), "class P { }");
            await Proc.RunAsync("git", ["init", "--quiet"], workDir, ct);
            await Proc.RunAsync("git", ["add", "."], workDir, ct);
            return (workDir, "0123456789abcdef0123456789abcdef01234567");
        }
    }

    sealed class EmptyScanner(string id) : IScannerAdapter
    {
        public string Id => id;
        public string Version => "test";
        public bool Supports(string issueType) => true;
        public Task<RawOutput> ScanAsync(ScanTarget target, CancellationToken ct) => Task.FromResult(new RawOutput(id, "test", "[]", "[]", 1, ""));
        public List<Finding> Normalise(RawOutput raw, ScanTarget t, HashSet<string> tracked) => [];
    }

    [Fact]
    public async Task Scanner_runs_the_configured_adapters_stores_canonical_output_and_replies_on_results()
    {
        var data = WorkerKit.TempDir();
        var ctx = Ctx("scanner", data);
        var pub = new RecordingPublisher();
        var blob = new LocalBlobStore(Path.Combine(data, "blob"));
        var adapters = new IScannerAdapter[] { new EmptyScanner("gitleaks"), new EmptyScanner("semgrep"), new EmptyScanner("not-in-routing") };
        var h = new ScanRequestHandler(new FakeFetcher(), adapters, TestEnv.Cfg, new SchemaValidator(TestEnv.Cfg, new JsonSchemaCache()), blob, pub, ctx,
            LoggerFactory.Create(_ => { }).CreateLogger<ScanRequestHandler>());
        var run = Guid.NewGuid();
        var msg = AgentMessage.Create("scan-1", run, AgentMessageTypes.ScanRequest, new ScanRequest(run, "zulq2019/sec-agent-sample-app", "main"));
        await h.HandleAsync(new AgentDeliveryContext(msg, 1, "scan"), default);

        var (entity, reply) = Assert.Single(pub.Messages);
        Assert.Equal("results", entity);
        Assert.Equal("scan-1:result", reply.MessageId);
        var result = reply.Payload<WorkResult>();
        Assert.Equal(WorkResultStatus.Completed, result.Status);
        Assert.Equal("0", result.Data!["count.gitleaks"]);
        Assert.False(result.Data.ContainsKey("count.not-in-routing"));    // routing.yaml decides which scanners run
        Assert.Equal("[]", blob.Read(result.Data["findings_uri"]));
        Assert.False(Directory.Exists(Path.Combine(data, "work", "scan", run.ToString("N"))) && Directory.EnumerateFileSystemEntries(Path.Combine(data, "work", "scan", run.ToString("N"))).Any());
    }

    [Theory]
    [InlineData("owner/repo", "--upload-pack=evil")]
    [InlineData("owner/repo", "-oProxyCommand")]
    [InlineData("owner/repo", "main/../../x")]
    [InlineData("../etc/passwd", "main")]
    [InlineData("owner/repo;rm -rf", "main")]
    public void Scan_requests_that_could_inject_git_arguments_are_rejected(string repo, string gitRef)
    {
        Assert.Throws<AgentMessageRejectedException>(() => ScanRequestRules.Validate(new ScanRequest(Guid.NewGuid(), repo, gitRef)));
    }

    [Fact]
    public void Local_repo_paths_are_confined_to_the_configured_root()
    {
        var root = WorkerKit.TempDir();
        Assert.StartsWith(root, ScanRequestRules.LocalPathUnder(root, "sample-app"));
        Assert.Throws<AgentMessageRejectedException>(() => ScanRequestRules.LocalPathUnder(root, "../outside"));
        Assert.Throws<AgentMessageRejectedException>(() => ScanRequestRules.LocalPathUnder("", "sample-app"));
    }

    [Fact]
    public async Task Pipeline_step_roles_acknowledge_with_a_deferred_result()
    {
        var pub = new RecordingPublisher();
        var (sp, _) = WorkerKit.Compose(WorkerKit.Config("fixer-library", WorkerKit.TempDir()));
        using var __ = sp;
        using var scope = sp.CreateScope();
        var reg = Assert.Single(sp.GetServices<AgentHandlerRegistration>());
        Assert.Equal("fix-library", reg.Entity);
        var ctx = sp.GetRequiredService<AgentRoleContext>();
        var handler = (IAgentMessageHandler)ActivatorUtilities.CreateInstance(scope.ServiceProvider, reg.HandlerType, pub, ctx);
        var run = Guid.NewGuid();
        await handler.HandleAsync(new AgentDeliveryContext(AgentMessage.Create("fx-1", run, AgentMessageTypes.StepRequest, new StepRequest(run, "fix-library")), 1, "fix-library"), default);
        var (entity, reply) = Assert.Single(pub.Messages);
        Assert.Equal("results", entity);
        Assert.Equal(WorkResultStatus.Deferred, reply.Payload<WorkResult>().Status);
        Assert.Equal("fixer-library", reply.Payload<WorkResult>().Agent);
    }

    [Fact]
    public async Task Audit_writer_stores_each_event_once_masked_in_the_write_once_evidence_store()
    {
        var data = WorkerKit.TempDir();
        var (sp, _) = WorkerKit.Compose(WorkerKit.Config("audit-writer", data));
        using var __ = sp;
        var masker = sp.GetRequiredService<SecretMasker>();
        masker.Register("synthetic-audit-value-1234");
        using var scope = sp.CreateScope();
        var reg = Assert.Single(sp.GetServices<AgentHandlerRegistration>());
        Assert.Equal("run-events/subscriptions/audit", reg.Entity);
        var h = (IAgentMessageHandler)scope.ServiceProvider.GetRequiredService(reg.HandlerType);
        var run = Guid.NewGuid();
        var msg = new AgentMessage($"{run:N}:7", run.ToString(), AgentMessageTypes.RunEvent, """{"seq":7,"type":"entry","data":{"text":"token synthetic-audit-value-1234"}}""");
        await h.HandleAsync(new AgentDeliveryContext(msg, 1, reg.Entity), default);
        await h.HandleAsync(new AgentDeliveryContext(msg, 2, reg.Entity), default);   // redelivery: same blob, no second copy
        var files = Directory.GetFiles(Path.Combine(data, "blob", "evidence", "audit", run.ToString("N")));
        var text = File.ReadAllText(Assert.Single(files));
        Assert.DoesNotContain("synthetic-audit-value-1234", text);
        Assert.Contains("\"seq\":7", text);
    }

    [Fact]
    public async Task Malformed_message_bodies_are_rejected_not_retried()
    {
        var pub = new RecordingPublisher();
        var data = WorkerKit.TempDir();
        var h = new ScanRequestHandler(new FakeFetcher(), [], TestEnv.Cfg, new SchemaValidator(TestEnv.Cfg, new JsonSchemaCache()), new LocalBlobStore(data), pub,
            Ctx("scanner", data), LoggerFactory.Create(_ => { }).CreateLogger<ScanRequestHandler>());
        await Assert.ThrowsAsync<AgentMessageRejectedException>(() =>
            h.HandleAsync(new AgentDeliveryContext(new AgentMessage("m", Guid.NewGuid().ToString(), "scan-request", "not json"), 1, "scan"), default));
        Assert.Empty(pub.Messages);
    }
}
