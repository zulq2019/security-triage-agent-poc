using Microsoft.Extensions.DependencyInjection;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.BlackDuck;

/// <summary>Plug-in for Black Duck (provider id "blackduck"). Setup: BaseUrl (https://blackduck.example), Secret (API token reference).
/// The API token is exchanged for a short-lived bearer token (POST /api/tokens/authenticate) that is kept in memory only.</summary>
public sealed class BlackDuckConnector(IHttpClientFactory httpFactory, ISecretProvider secrets, TimeProvider time) : IConnectorClientProvider<IScannerSourceClient>
{
    public const string Id = "blackduck";

    public static readonly ConnectorDescriptor Descriptor = new(
        Id, "Black Duck", ConnectorKind.ScannerSource, "findings_input", ConnectorTransport.Http,
        [ConnectorCapabilities.VulnerabilityBacklogRead, ConnectorCapabilities.RemediationGuidanceRead],
        [
            new("Projects and versions", "read", "Find the project version of a repository's default branch (backlog mode)."),
            new("Vulnerable BOM components", "read", "Pull existing vulnerabilities for the nightly backlog sweep."),
            new("Component upgrade guidance", "read", "Short- and long-term upgrade targets for the library fixer."),
        ],
        ["policy_change", "ignore_component", "remediation_status_write", "admin"],
        [
            new("BaseUrl", "Black Duck server URL", true, Example: "https://blackduck.example.invalid"),
            new("Secret", "API token reference", true, true, "kv:blackduck-api-token"),
        ],
        SelectionKind.Projects,
        Notes: "Read-only. ASSUMPTION: response fields from the public REST docs (bill-of-materials-6 media type); not yet verified on a live server.");

    public ConnectorDescriptor Describe() => Descriptor;

    public IScannerSourceClient CreateClient(ConnectionSettings connection) =>
        new BlackDuckScannerSourceClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), connection, secrets, time);

    public async Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct)
    {
        try
        {
            var n = await new BlackDuckScannerSourceClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), connection, secrets, time).ProjectCountAsync(ct);
            return HealthResult.Healthy($"authenticated; {n} projects visible", time.GetUtcNow());
        }
        catch (ConnectorException e) { return HealthResult.Failing(e.Message, time.GetUtcNow()); }
    }
}

public static class BlackDuckConnectorRegistration
{
    public static ConnectorsBuilder AddBlackDuckConnector(this ConnectorsBuilder builder)
    {
        builder.Services.AddConnectorHttpClient(BlackDuckConnector.Id);
        return builder.AddConnector<BlackDuckConnector, IScannerSourceClient>();
    }
}
