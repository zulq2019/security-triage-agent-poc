using Xunit;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace SecAgent.Tests.Connectors;

/// <summary>One request as the stub saw it (for request-shape assertions). Only the auth scheme is kept, never a credential.</summary>
public sealed record SeenRequest(HttpMethod Method, string PathAndQuery, string? AuthScheme, string? AuthParameter, string? Accept, string? Body,
    IReadOnlyDictionary<string, string> Headers)
{
    public JsonNode? Json => Body is { Length: > 0 } b ? JsonNode.Parse(b) : null;
    public string Path => PathAndQuery.Split('?')[0];
}

/// <summary>HttpMessageHandler stand-in for a REST service: records every request and answers through <see cref="Handle"/>.
/// Never touches the network; shared across HttpClient instances, so disposing a client does not dispose it.</summary>
public abstract class HttpStub : HttpMessageHandler
{
    readonly List<SeenRequest> _seen = [];
    readonly object _lock = new();
    public IReadOnlyList<SeenRequest> Seen { get { lock (_lock) return _seen.ToList(); } }
    public void ClearSeen() { lock (_lock) _seen.Clear(); }

    protected abstract HttpResponseMessage Handle(SeenRequest r);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content == null ? null : await request.Content.ReadAsStringAsync(ct);
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        var seen = new SeenRequest(request.Method, request.RequestUri!.PathAndQuery, request.Headers.Authorization?.Scheme, request.Headers.Authorization?.Parameter,
            request.Headers.Accept.ToString(), body, headers);
        lock (_lock) _seen.Add(seen);
        HttpResponseMessage resp;
        lock (_lock) resp = Handle(seen);
        resp.RequestMessage = request;
        return resp;
    }

    protected override void Dispose(bool disposing) { }   // shared by every pooled handler chain

    public static HttpResponseMessage Json(object? body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body is JsonNode n ? n.ToJsonString() : System.Text.Json.JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
    public static HttpResponseMessage Status(HttpStatusCode code) => new(code) { Content = new StringContent("") };
}

/// <summary>Scripted stub: a queue of responses per request (for resilience tests).</summary>
public sealed class ScriptedStub(Func<SeenRequest, int, HttpResponseMessage> respond) : HttpStub
{
    int _n;
    protected override HttpResponseMessage Handle(SeenRequest r) => respond(r, ++_n);
}
