using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Agents;
using SecAgent.Connectors;
using SecAgent.Connectors.Configuration;
using SecAgent.Connectors.OpenAI;
using Xunit;

namespace SecAgent.Tests.Connectors;

/// <summary>The dashboard composition root with real configuration: the shipped appsettings.json and the examples in docs/connectors.md.</summary>
public class ConnectorCompositionTests
{
    static ServiceProvider Compose(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(configuration);
        services.AddSecAgentConnectorPlugins(configuration, AgentServices.LoadConfig(TestEnv.RepoRoot).Gateway);
        return services.BuildServiceProvider();
    }

    static IConfiguration FromJson(string json) =>
        new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json))).Build();

    [Fact]
    public void Shipped_appsettings_compose_the_pipeline_ports()
    {
        var json = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "src", "SecAgent.Dashboard", "appsettings.json"));
        using var sp = Compose(FromJson(json));
        var options = sp.GetRequiredService<IOptions<ConnectorOptions>>().Value;   // runs the validator
        Assert.Equal(DeploymentModel.SingleTenant, options.DeploymentModel);

        var ports = sp.GetRequiredService<PipelineConnectors>();
        var tenant = ports.Tenants.ForRepository("zulq2019/sec-agent-sample-app");
        Assert.Equal("local", tenant);

        var resolver = sp.GetRequiredService<ITenantConnectionResolver>();
        Assert.Equal("github", resolver.Resolve(tenant, ConnectorKind.SourceControl)!.Provider);
        Assert.Equal("gh-cli:token", resolver.Resolve(tenant, ConnectorKind.SourceControl)!.Secret!.Value.Value);
        // The ModelProvider switch becomes the default model connection (backwards compatible).
        Assert.Equal(OpenAICompatibleModelConnector.Id, resolver.Resolve(tenant, ConnectorKind.ModelProvider)!.Provider);
        Assert.Null(resolver.Resolve(tenant, ConnectorKind.IssueTracker));
        Assert.Null(resolver.Resolve(tenant, ConnectorKind.Notifier));
        Assert.False(ports.IssueTrackers.TryForTenant(tenant, out _));
        Assert.False(ports.Notifiers.TryForTenant(tenant, out _));

        var catalog = sp.GetRequiredService<IConnectorCatalog>();
        foreach (var id in new[] { "github", "jira", "blackduck", "openai-compatible", "teams", "fake" })
            Assert.Contains(catalog.Descriptors, d => d.Id == id);
    }

    static IReadOnlyList<string> DocJsonExamples()
    {
        var md = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "docs", "connectors.md"));
        return Regex.Matches(md, "```json\\s*\\n(.*?)```", RegexOptions.Singleline).Select(m => m.Groups[1].Value).ToList();
    }

    [Fact]
    public void Every_config_example_in_docs_is_valid()
    {
        var examples = DocJsonExamples();
        Assert.True(examples.Count >= 3, $"expected the single-tenant, multi-tenant and fakes examples, found {examples.Count}");
        foreach (var json in examples)
        {
            using var sp = Compose(FromJson(json));
            var ex = Record.Exception(() => sp.GetRequiredService<IOptions<ConnectorOptions>>().Value);
            Assert.True(ex == null, $"docs example failed validation: {ex?.Message}\n{json}");
            Assert.NotNull(sp.GetRequiredService<PipelineConnectors>());
        }
    }

    [Fact]
    public void Docs_multi_tenant_example_isolates_tenants()
    {
        var json = DocJsonExamples().Single(j => j.Contains("\"MultiTenant\""));
        using var sp = Compose(FromJson(json));
        var tenants = sp.GetRequiredService<ITenantResolver>();
        var resolver = sp.GetRequiredService<ITenantConnectionResolver>();

        Assert.Equal("tenant-a", tenants.ForRepository("tenant-a-org/anything"));
        Assert.Equal("tenant-b", tenants.ForRepository("tenant-b-org/payments-api"));
        Assert.Throws<UnknownTenantException>(() => tenants.ForRepository("tenant-b-org/not-listed"));
        Assert.Throws<UnknownTenantException>(() => tenants.ForRepository("someone-else/repo"));
        Assert.Throws<UnknownTenantException>(() => resolver.Resolve("tenant-c", ConnectorKind.SourceControl));

        Assert.Equal("jira", resolver.Resolve("tenant-a", ConnectorKind.IssueTracker)!.Provider);
        Assert.Null(resolver.Resolve("tenant-b", ConnectorKind.IssueTracker));
        Assert.Contains("kv-secagent-tenant-b", resolver.Resolve("tenant-b", ConnectorKind.SourceControl)!.Secret!.Value.Value);
        // The shared model deployment comes from Defaults for both tenants.
        Assert.Equal("openai-compatible", resolver.Resolve("tenant-a", ConnectorKind.ModelProvider)!.Provider);
        Assert.Equal("openai-compatible", resolver.Resolve("tenant-b", ConnectorKind.ModelProvider)!.Provider);
    }
}
