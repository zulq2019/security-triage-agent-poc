using Xunit;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Connectors;
using SecAgent.Connectors.BlackDuck;
using SecAgent.Connectors.Fakes;

namespace SecAgent.Tests.Connectors;

/// <summary>Synthetic Black Duck project: 130 vulnerable components (more than one page), one with upgrade guidance.</summary>
public static class ScannerFixture
{
    public const string Project = "payments-api", Version = "1.4.0";
    public static readonly ComponentVersionRef Lodash = new("c-lodash", "v-41720", "lodash", "4.17.20");
    public static readonly ScannerVulnerability[] Vulns = Enumerable.Range(0, 130).Select(i => i == 0
        ? new ScannerVulnerability("BDSA-2026-0001", "high", 7.5, "lodash", "4.17.20", Lodash, "Synthetic prototype pollution", "NEW", ["CVE-2026-1111"], "CWE-1321", null)
        : new ScannerVulnerability($"CVE-2026-{2000 + i}", "medium", 5.0, $"lib{i}", "1.0.0", new ComponentVersionRef($"c-{i}", $"v-{i}", $"lib{i}", "1.0.0"), null, "NEW", [], null, null)).ToArray();
    public static readonly RemediationGuidance Guidance = new("lodash", "4.17.20", "4.17.21", "4.18.0");
}

/// <summary>Contract every <see cref="IScannerSourceClient"/> must honour (fake and Black Duck run the same assertions).</summary>
public abstract class ScannerSourceContract
{
    protected abstract IScannerSourceClient CreateSeededClient();

    [Fact]
    public async Task Finds_a_project_version_by_name()
    {
        var c = CreateSeededClient();
        var pv = await c.FindProjectVersionAsync(ScannerFixture.Project, ScannerFixture.Version, default);
        Assert.Equal((ScannerFixture.Project, ScannerFixture.Version), (pv!.ProjectName, pv.VersionName));
        Assert.False(string.IsNullOrEmpty(pv.ProjectId));
        Assert.Null(await c.FindProjectVersionAsync(ScannerFixture.Project, "9.9.9", default));
        Assert.Null(await c.FindProjectVersionAsync("no-such-project", "1.0", default));
    }

    [Fact]
    public async Task Lists_the_whole_vulnerability_backlog_with_component_references()
    {
        var c = CreateSeededClient();
        var pv = await c.FindProjectVersionAsync(ScannerFixture.Project, ScannerFixture.Version, default);
        var vulns = await c.ListVulnerabilitiesAsync(pv!, default);
        Assert.Equal(130, vulns.Count);
        var first = vulns.Single(v => v.VulnerabilityId == "BDSA-2026-0001");
        Assert.Equal(("high", 7.5, "lodash", "4.17.20", "CWE-1321"), (first.Severity, first.Score, first.ComponentName, first.ComponentVersion, first.CweId));
        Assert.Equal(("c-lodash", "v-41720"), (first.Component!.ComponentId, first.Component.ComponentVersionId));
        Assert.Contains("CVE-2026-1111", first.RelatedIds);
        Assert.Equal(129, vulns.Count(v => v.Severity == "medium"));
    }

    [Fact]
    public async Task Returns_component_upgrade_guidance()
    {
        var c = CreateSeededClient();
        var g = await c.GetRemediationGuidanceAsync(ScannerFixture.Lodash, default);
        Assert.Equal(("4.17.21", "4.18.0"), (g!.ShortTermVersion, g.LongTermVersion));
        Assert.Null(await c.GetRemediationGuidanceAsync(new ComponentVersionRef("c-x", "v-x"), default));
    }
}

public sealed class FakeScannerSourceContractTests : ScannerSourceContract
{
    protected override IScannerSourceClient CreateSeededClient()
    {
        var world = new FakeConnectorWorld();
        world.ScannerSource.AddProjectVersion(ConnectorTestKit.Tenant, ScannerFixture.Project, ScannerFixture.Version, ScannerFixture.Vulns);
        world.ScannerSource.AddGuidance(ConnectorTestKit.Tenant, ScannerFixture.Lodash, ScannerFixture.Guidance);
        return ConnectorTestKit.Services(ConnectorTestKit.AllFakes(), b => b.AddFakeConnectors(world))
            .GetRequiredService<IConnectorClientFactory<IScannerSourceClient>>().ForTenant(ConnectorTestKit.Tenant);
    }
}

/// <summary>In-memory Black Duck REST API (subset). Shapes follow the public API docs; see ASSUMPTION notes on the client.</summary>
public sealed class BlackDuckSimulator : HttpStub
{
    public const string Base = "https://blackduck.acme.test/";
    public string ApiToken { get; set; } = "synthetic-bd-api-token";
    public int TokenExchanges { get; private set; }
    public bool ExpireBearerOnce { get; set; }
    string _bearer = "";

    protected override HttpResponseMessage Handle(SeenRequest r)
    {
        var path = r.Path.TrimStart('/');
        if (path == "api/tokens/authenticate" && r.Method == HttpMethod.Post)
        {
            if (r.AuthScheme != "token" || r.AuthParameter != ApiToken) return Status(HttpStatusCode.Unauthorized);
            _bearer = $"bearer-{++TokenExchanges}";
            return Json(new JsonObject { ["bearerToken"] = _bearer, ["expiresInMilliseconds"] = 7_200_000 });
        }
        if (r.AuthScheme != "Bearer" || r.AuthParameter != _bearer) return Status(HttpStatusCode.Unauthorized);
        if (ExpireBearerOnce) { ExpireBearerOnce = false; _bearer = "expired"; return Status(HttpStatusCode.Unauthorized); }
        var q = System.Web.HttpUtility.ParseQueryString(r.PathAndQuery.Contains('?') ? r.PathAndQuery[(r.PathAndQuery.IndexOf('?') + 1)..] : "");
        if (path == "api/projects")
        {
            var name = q["q"]?.Replace("name:", "");
            var items = name == null || name == ScannerFixture.Project
                ? new JsonArray(new JsonObject { ["name"] = ScannerFixture.Project, ["_meta"] = new JsonObject { ["href"] = Base + "api/projects/p-1" } }) : [];
            return Json(new JsonObject { ["totalCount"] = items.Count, ["items"] = items });
        }
        if (path == "api/projects/p-1/versions")
        {
            var v = q["q"]?.Replace("versionName:", "");
            var items = v == ScannerFixture.Version
                ? new JsonArray(new JsonObject { ["versionName"] = ScannerFixture.Version, ["_meta"] = new JsonObject { ["href"] = Base + "api/projects/p-1/versions/pv-1" } }) : [];
            return Json(new JsonObject { ["totalCount"] = items.Count, ["items"] = items });
        }
        if (path == "api/projects/p-1/versions/pv-1/vulnerable-bom-components")
        {
            if (!r.Accept!.Contains("bill-of-materials-6+json")) return Status(HttpStatusCode.NotAcceptable);
            int limit = int.Parse(q["limit"]!), offset = int.Parse(q["offset"]!);
            var page = ScannerFixture.Vulns.Skip(offset).Take(limit).Select(v => (JsonNode)new JsonObject
            {
                ["componentName"] = v.ComponentName, ["componentVersionName"] = v.ComponentVersion,
                ["componentVersion"] = $"{Base}api/components/{v.Component!.ComponentId}/versions/{v.Component.ComponentVersionId}",
                ["vulnerabilityWithRemediation"] = new JsonObject
                {
                    ["vulnerabilityName"] = v.VulnerabilityId, ["severity"] = v.Severity.ToUpperInvariant(), ["overallScore"] = v.Score, ["description"] = v.Description,
                    ["remediationStatus"] = v.RemediationStatus, ["cweId"] = v.CweId,
                    ["relatedVulnerability"] = v.RelatedIds.Count > 0 ? $"{Base}api/vulnerabilities/{v.RelatedIds[0]}" : null,
                },
                ["_meta"] = new JsonObject { ["href"] = $"{Base}api/projects/p-1/versions/pv-1/vulnerable-bom-components/{v.VulnerabilityId}" },
            }).ToArray();
            return Json(new JsonObject { ["totalCount"] = ScannerFixture.Vulns.Length, ["items"] = new JsonArray(page) });
        }
        if (path == $"api/components/{ScannerFixture.Lodash.ComponentId}/versions/{ScannerFixture.Lodash.ComponentVersionId}/upgrade-guidance")
            return Json(new JsonObject { ["componentName"] = "lodash", ["versionName"] = "4.17.20", ["shortTerm"] = new JsonObject { ["versionName"] = "4.17.21" },
                ["longTerm"] = new JsonObject { ["versionName"] = "4.18.0" } });
        return Status(HttpStatusCode.NotFound);
    }
}

public sealed class BlackDuckScannerSourceContractTests : ScannerSourceContract
{
    readonly BlackDuckSimulator _sim = new();

    IScannerSourceClient Client()
    {
        var config = new Dictionary<string, string?>
        {
            ["Connectors:DeploymentModel"] = "SingleTenant", ["Connectors:DefaultTenant"] = ConnectorTestKit.Tenant,
            ["Connectors:Tenants:t1:ScannerSource:Provider"] = "blackduck", ["Connectors:Tenants:t1:ScannerSource:BaseUrl"] = BlackDuckSimulator.Base,
            ["Connectors:Tenants:t1:ScannerSource:Secret"] = "memory:bd-token", ["Connectors:Resilience:PermitsPerSecond"] = "1000",
        };
        var sp = ConnectorTestKit.Services(config, b => b.AddFakeConnectors().AddBlackDuckConnector(),
            s => s.ConfigureHttpClientDefaults(h => h.ConfigurePrimaryHttpMessageHandler(() => _sim)));
        sp.GetRequiredService<InMemorySecretSource>().Set("bd-token", "synthetic-bd-api-token");
        return sp.GetRequiredService<IConnectorClientFactory<IScannerSourceClient>>().ForTenant(ConnectorTestKit.Tenant);
    }

    protected override IScannerSourceClient CreateSeededClient() => Client();

    [Fact]
    public async Task Exchanges_the_api_token_once_and_refreshes_the_bearer_after_401()
    {
        var c = Client();
        var pv = await c.FindProjectVersionAsync(ScannerFixture.Project, ScannerFixture.Version, default);
        Assert.Equal(1, _sim.TokenExchanges);
        _sim.ExpireBearerOnce = true;
        Assert.Equal(130, (await c.ListVulnerabilitiesAsync(pv!, default)).Count);
        Assert.Equal(2, _sim.TokenExchanges);
        Assert.Equal(2, _sim.Seen.Count(r => r.Path.EndsWith("/vulnerable-bom-components") && r.AuthParameter is { } p && p.StartsWith("bearer-2")));   // two pages, fresh token
        Assert.DoesNotContain(_sim.Seen, r => r.Method != HttpMethod.Get && !r.Path.EndsWith("/tokens/authenticate"));   // read-only connector
    }
}
