using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecAgent.Connectors.Http;

/// <summary>Base for REST connectors (Template Method): builds requests against the connection's BaseUrl, tags them with the tenant (so the
/// HTTP resilience handler keeps one pipeline per tenant), lets the subclass authenticate, and maps failures to <see cref="ConnectorException"/>
/// with method, path and status only (no bodies, headers, query strings or secrets).</summary>
public abstract class ConnectorRestClient(HttpClient http, ConnectionSettings connection, string connectorId)
{
    protected static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    protected ConnectionSettings Connection { get; } = connection;
    protected string ConnectorId { get; } = connectorId;

    /// <summary>Adds credentials. Called for every request (and again after a 401 when <see cref="OnUnauthorizedAsync"/> returns true).</summary>
    protected abstract ValueTask AuthorizeAsync(HttpRequestMessage request, CancellationToken ct);

    /// <summary>Lets a client refresh a short-lived token once after a 401. Default: no retry.</summary>
    protected virtual ValueTask<bool> OnUnauthorizedAsync(CancellationToken ct) => ValueTask.FromResult(false);

    protected virtual Uri ResolveUri(string pathOrUrl)
    {
        var baseUri = Connection.RequireBaseUrl();
        if (Uri.TryCreate(pathOrUrl, UriKind.Absolute, out var abs) && (abs.Scheme == Uri.UriSchemeHttps || abs.Scheme == Uri.UriSchemeHttp))
        {
            // Links returned by the server (e.g. Black Duck _meta.href) are followed only on the connection's own host: the tenant's
            // credentials are never sent to another host.
            if (!string.Equals(abs.Authority, baseUri.Authority, StringComparison.OrdinalIgnoreCase) || abs.Scheme != baseUri.Scheme)
                throw new ConnectorException($"{ConnectorId}: refusing to follow a link to another host ({abs.Host})");
            return abs;
        }
        var b = baseUri.ToString();
        return new Uri(new Uri(b.EndsWith('/') ? b : b + "/"), pathOrUrl.TrimStart('/'));
    }

    protected Task<JsonNode?> GetAsync(string path, CancellationToken ct, bool notFoundIsNull = false, string? accept = null) =>
        SendAsync(HttpMethod.Get, path, null, ct, notFoundIsNull, accept);

    protected async Task<JsonNode?> SendAsync(HttpMethod method, string path, object? body, CancellationToken ct, bool notFoundIsNull = false, string? accept = null)
    {
        var uri = ResolveUri(path);
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, uri);
            request.Options.Set(ConnectorHttp.TenantOption, Connection.TenantId);
            if (accept != null) request.Headers.Accept.ParseAdd(accept);
            if (body != null) request.Content = new StringContent(body as string ?? JsonSerializer.Serialize(body, Json), Encoding.UTF8, "application/json");
            await AuthorizeAsync(request, ct);
            HttpResponseMessage response;
            try { response = await http.SendAsync(request, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException || e.GetType().Name == "TimeoutRejectedException")
            {
                throw new ConnectorException($"{ConnectorId} {method} {uri.AbsolutePath}: {(e is TaskCanceledException ? "timed out" : e.GetType().Name)}", true, null, null, e);
            }
            using (response)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized && attempt == 0 && await OnUnauthorizedAsync(ct)) continue;
                if (notFoundIsNull && response.StatusCode == HttpStatusCode.NotFound) return null;
                if (!response.IsSuccessStatusCode) throw Failure(method, uri, response);
                var text = await response.Content.ReadAsStringAsync(ct);
                return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
            }
        }
    }

    ConnectorException Failure(HttpMethod method, Uri uri, HttpResponseMessage r)
    {
        var code = (int)r.StatusCode;
        var transient = code is 408 or 429 or >= 500;
        TimeSpan? retryAfter = r.Headers.RetryAfter?.Delta ?? (r.Headers.RetryAfter?.Date is { } d ? d - DateTimeOffset.UtcNow : null);
        return new ConnectorException($"{ConnectorId} {method} {uri.AbsolutePath} returned {code} {r.ReasonPhrase}", transient, r.StatusCode, retryAfter);
    }

    protected static void Bearer(HttpRequestMessage request, string token) => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    protected static string Str(JsonNode? n, string name) => n?[name]?.GetValue<string>() ?? "";
    protected static string? StrOrNull(JsonNode? n, string name) => n?[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    protected static int Int(JsonNode? n, string name) => n?[name] is JsonValue v && v.TryGetValue<int>(out var i) ? i : 0;
}
