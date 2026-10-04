using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.BlackDuck;

/// <summary>Black Duck REST client (read-only). Endpoints (public docs):
/// POST /api/tokens/authenticate (Authorization: token &lt;api token&gt;) → bearerToken, expiresInMilliseconds ·
/// GET /api/projects?q=name:&lt;name&gt; · GET /api/projects/{id}/versions?q=versionName:&lt;v&gt; ·
/// GET /api/projects/{id}/versions/{id}/vulnerable-bom-components (Accept bill-of-materials-6+json, paged by limit/offset) ·
/// GET /api/components/{id}/versions/{id}/upgrade-guidance.
/// ASSUMPTION (unverified against a live server): item field names (componentName, componentVersionName, componentVersion href,
/// vulnerabilityWithRemediation.*), the upgrade-guidance media type and shortTerm / longTerm shape.</summary>
public sealed class BlackDuckScannerSourceClient(HttpClient http, ConnectionSettings connection, ISecretProvider secrets, TimeProvider time)
    : ConnectorRestClient(http, connection, BlackDuckConnector.Id), IScannerSourceClient
{
    public const string BomMediaType = "application/vnd.blackducksoftware.bill-of-materials-6+json";
    public const string ComponentMediaType = "application/vnd.blackducksoftware.component-detail-5+json";   // ASSUMPTION
    const int PageSize = 100;
    readonly SemaphoreSlim _tokenLock = new(1, 1);
    sealed record BearerToken(string Token, DateTimeOffset Expires);
    volatile BearerToken? _bearer;

    protected override async ValueTask AuthorizeAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("/api/tokens/authenticate", StringComparison.Ordinal))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("token", await secrets.GetSecretAsync(Connection.RequireSecret(), ct));
            return;
        }
        Bearer(request, await BearerAsync(ct));
    }

    protected override ValueTask<bool> OnUnauthorizedAsync(CancellationToken ct)
    {
        _bearer = null;   // expired or revoked: retry once with a fresh bearer token (no lock: may run inside the token exchange)
        return ValueTask.FromResult(true);
    }

    async Task<string> BearerAsync(CancellationToken ct)
    {
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_bearer is { } b && b.Expires > time.GetUtcNow().AddSeconds(60)) return b.Token;
            var j = await SendAsync(HttpMethod.Post, "api/tokens/authenticate", null, ct, accept: "application/vnd.blackducksoftware.user-4+json");
            var token = StrOrNull(j, "bearerToken") ?? throw new ConnectorException("blackduck: token exchange returned no bearerToken");
            var ms = j?["expiresInMilliseconds"] is JsonValue v && v.TryGetValue<long>(out var x) ? x : 3_600_000;
            _bearer = new BearerToken(token, time.GetUtcNow().AddMilliseconds(ms));
            return token;
        }
        finally { _tokenLock.Release(); }
    }

    public async Task<ScannerProjectVersion?> FindProjectVersionAsync(string projectName, string versionName, CancellationToken ct)
    {
        var projects = (await GetAsync($"api/projects?q={Uri.EscapeDataString("name:" + projectName)}&limit={PageSize}", ct))?["items"]?.AsArray() ?? [];
        var project = projects.FirstOrDefault(p => Str(p, "name").Equals(projectName, StringComparison.OrdinalIgnoreCase));
        if (project == null) return null;
        var projectHref = Href(project);
        var versions = (await GetAsync($"{projectHref}/versions?q={Uri.EscapeDataString("versionName:" + versionName)}&limit={PageSize}", ct))?["items"]?.AsArray() ?? [];
        var version = versions.FirstOrDefault(v => Str(v, "versionName").Equals(versionName, StringComparison.OrdinalIgnoreCase));
        return version == null ? null : new ScannerProjectVersion(LastSegment(projectHref), Str(project, "name"), LastSegment(Href(version)), Str(version, "versionName"));
    }

    public async Task<IReadOnlyList<ScannerVulnerability>> ListVulnerabilitiesAsync(ScannerProjectVersion version, CancellationToken ct)
    {
        var list = new List<ScannerVulnerability>();
        var basePath = $"api/projects/{Uri.EscapeDataString(version.ProjectId)}/versions/{Uri.EscapeDataString(version.VersionId)}/vulnerable-bom-components";
        for (var offset = 0; offset < 100_000; offset += PageSize)
        {
            var page = await GetAsync($"{basePath}?limit={PageSize}&offset={offset}", ct, accept: BomMediaType);
            var items = page?["items"]?.AsArray() ?? [];
            list.AddRange(items.Select(Map));
            var total = page?["totalCount"] is JsonValue t && t.TryGetValue<int>(out var n) ? n : list.Count;
            if (items.Count < PageSize || list.Count >= total) break;
        }
        return list;
    }

    public async Task<RemediationGuidance?> GetRemediationGuidanceAsync(ComponentVersionRef component, CancellationToken ct)
    {
        var j = await GetAsync($"api/components/{Uri.EscapeDataString(component.ComponentId)}/versions/{Uri.EscapeDataString(component.ComponentVersionId)}/upgrade-guidance",
            ct, notFoundIsNull: true, accept: ComponentMediaType);
        if (j == null) return null;
        return new RemediationGuidance(StrOrNull(j, "componentName") ?? component.ComponentName ?? "", StrOrNull(j, "versionName") ?? component.Version ?? "",
            StrOrNull(j["shortTerm"], "versionName"), StrOrNull(j["longTerm"], "versionName"),
            j["shortTerm"]?["vulnerabilityRisk"] is JsonObject risk ? "short-term target still has: " + string.Join(", ", risk.Select(kv => $"{kv.Key} {kv.Value}")) : null);
    }

    internal async Task<int> ProjectCountAsync(CancellationToken ct) => Int(await GetAsync("api/projects?limit=1", ct), "totalCount");

    static ScannerVulnerability Map(JsonNode? item)
    {
        var v = item?["vulnerabilityWithRemediation"];
        var cvHref = StrOrNull(item, "componentVersion");
        ComponentVersionRef? component = null;
        if (cvHref != null && TryComponentIds(cvHref, out var cid, out var cvid))
            component = new ComponentVersionRef(cid, cvid, Str(item, "componentName"), Str(item, "componentVersionName"), StrOrNull(item, "componentVersionOriginId"));
        var related = new List<string>();
        if (StrOrNull(v, "relatedVulnerability") is { } rel && LastSegment(rel) is { Length: > 0 } relId) related.Add(relId);
        var score = v?["overallScore"] is JsonValue os && os.TryGetValue<double>(out var o) ? o : v?["baseScore"] is JsonValue bs && bs.TryGetValue<double>(out var b) ? b : (double?)null;
        return new ScannerVulnerability(Str(v, "vulnerabilityName"), Severity(Str(v, "severity")), score, Str(item, "componentName"), Str(item, "componentVersionName"),
            component, StrOrNull(v, "description"), StrOrNull(v, "remediationStatus"), related, StrOrNull(v, "cweId"), StrOrNull(item?["_meta"], "href"));
    }

    static string Severity(string s) => s.ToUpperInvariant() switch
    {
        "CRITICAL" => "critical", "HIGH" => "high", "MEDIUM" => "medium", "LOW" => "low", _ => "info",
    };

    static string Href(JsonNode? n) => StrOrNull(n?["_meta"], "href") ?? throw new ConnectorException("blackduck: item without _meta.href");
    static string LastSegment(string href) => href.TrimEnd('/').Split('/').Last();

    static bool TryComponentIds(string href, out string componentId, out string versionId)
    {
        var parts = new Uri(href, UriKind.RelativeOrAbsolute).IsAbsoluteUri ? new Uri(href).AbsolutePath.Split('/') : href.Split('/');
        var ci = Array.IndexOf(parts, "components");
        var vi = Array.IndexOf(parts, "versions");
        componentId = ci >= 0 && ci + 1 < parts.Length ? parts[ci + 1] : "";
        versionId = vi >= 0 && vi + 1 < parts.Length ? parts[vi + 1] : "";
        return componentId.Length > 0 && versionId.Length > 0;
    }
}
