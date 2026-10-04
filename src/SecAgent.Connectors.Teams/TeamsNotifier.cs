using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.Teams;

/// <summary>Plug-in "teams". Setup: Secret = reference to the channel's Workflows webhook URL.</summary>
public sealed class TeamsNotifierConnector(IHttpClientFactory httpFactory, ISecretProvider secrets, TimeProvider time) : IConnectorClientProvider<INotifierClient>
{
    public const string Id = "teams";

    public static readonly ConnectorDescriptor Descriptor = new(
        Id, "Microsoft Teams", ConnectorKind.Notifier, "alerts", ConnectorTransport.Http,
        [ConnectorCapabilities.NotificationSend],
        [new("Channel webhook", "post", "Post run summaries and early warnings to one channel.")],
        ["read_messages", "admin"],
        [new("Secret", "Workflows webhook URL reference", true, true, "kv:teams-webhook-url")],
        Notes: "ASSUMPTION: Teams Workflows 'post to a channel when a webhook request is received' accepts the message + Adaptive Card envelope.");

    public ConnectorDescriptor Describe() => Descriptor;

    public INotifierClient CreateClient(ConnectionSettings connection) =>
        new TeamsWorkflowNotifierClient(httpFactory.CreateClient(ConnectorHttp.ClientName(Id)), connection, secrets);

    /// <summary>A probe would post a message, so health only checks that the webhook reference resolves to an https URL.</summary>
    public async Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct)
    {
        try
        {
            var url = await secrets.GetSecretAsync(connection.RequireSecret(), ct);
            return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps
                ? new HealthResult(HealthState.Degraded, "webhook reference resolves; not probed (a probe would post to the channel)", time.GetUtcNow())
                : HealthResult.Failing("webhook reference does not resolve to an https URL", time.GetUtcNow());
        }
        catch (ConnectorException e) { return HealthResult.Failing(e.Message, time.GetUtcNow()); }
    }
}

public sealed class TeamsWorkflowNotifierClient(HttpClient http, ConnectionSettings connection, ISecretProvider secrets)
    : ConnectorRestClient(http, connection, TeamsNotifierConnector.Id), INotifierClient
{
    string? _url;

    protected override ValueTask AuthorizeAsync(HttpRequestMessage request, CancellationToken ct) => ValueTask.CompletedTask;   // the URL carries its own signature
    protected override Uri ResolveUri(string pathOrUrl) => new(pathOrUrl);

    public async Task NotifyAsync(Notification n, CancellationToken ct)
    {
        _url ??= await secrets.GetSecretAsync(Connection.RequireSecret(), ct);
        await SendAsync(HttpMethod.Post, _url, Card(n), ct);
    }

    /// <summary>Adaptive Card 1.4 in the message envelope that Teams webhooks accept.</summary>
    public static JsonObject Card(Notification n)
    {
        var facts = new JsonArray();
        foreach (var f in n.Facts) facts.Add(new JsonObject { ["title"] = f.Name, ["value"] = f.Value });
        var body = new JsonArray(
            new JsonObject { ["type"] = "TextBlock", ["text"] = n.Title, ["weight"] = "Bolder", ["size"] = "Medium", ["wrap"] = true,
                ["color"] = n.Level switch { NotificationLevel.Critical => "Attention", NotificationLevel.Warning => "Warning", _ => "Default" } },
            new JsonObject { ["type"] = "TextBlock", ["text"] = n.Summary, ["wrap"] = true },
            new JsonObject { ["type"] = "FactSet", ["facts"] = facts });
        var card = new JsonObject { ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json", ["type"] = "AdaptiveCard", ["version"] = "1.4", ["body"] = body };
        if (n.LinkUrl != null)
            card["actions"] = new JsonArray(new JsonObject { ["type"] = "Action.OpenUrl", ["title"] = n.LinkText ?? "Open", ["url"] = n.LinkUrl });
        return new JsonObject
        {
            ["type"] = "message",
            ["attachments"] = new JsonArray(new JsonObject { ["contentType"] = "application/vnd.microsoft.card.adaptive", ["content"] = card }),
        };
    }
}

public static class TeamsNotifierRegistration
{
    public static ConnectorsBuilder AddTeamsNotifier(this ConnectorsBuilder builder)
    {
        builder.Services.AddConnectorHttpClient(TeamsNotifierConnector.Id);
        return builder.AddConnector<TeamsNotifierConnector, INotifierClient>();
    }
}
