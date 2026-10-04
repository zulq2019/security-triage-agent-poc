using System.ClientModel;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using global::OpenAI;

namespace SecAgent.Connectors.OpenAI;

/// <summary>One provider connection. Moved from ModelGateway.Client / AvailableModelsAsync: the API key is read through the secret provider
/// (never from a file), one IChatClient per model with OpenTelemetry (no sensitive data), and the Ollama model list cached for 30 s.</summary>
public sealed class OpenAICompatibleModelClient(ConnectionSettings connection, ISecretProvider secrets, IHttpClientFactory httpFactory, TimeProvider time) : IModelProviderClient
{
    readonly ConcurrentDictionary<string, IChatClient> _clients = new();
    readonly SemaphoreSlim _health = new(1, 1);
    (DateTimeOffset At, IReadOnlyCollection<string> Models) _catalog = (DateTimeOffset.MinValue, []);

    public string ProviderFamily => (connection.Get("Flavor") ?? "ollama").ToLowerInvariant();
    bool Hosted => ProviderFamily is "openai" or "azureopenai";

    internal async Task<string> EnsureKeyAsync(CancellationToken ct)
    {
        if (connection.Secret is not { IsValid: true } secret)
            return Hosted ? throw new ConnectorConfigurationException($"{ProviderFamily}: no API key reference configured (Secret)") : "ollama";   // Ollama ignores the key
        try { return await secrets.GetSecretAsync(secret, ct); }
        catch (ConnectorConfigurationException) when (!Hosted) { return "ollama"; }
        catch (ConnectorConfigurationException e) when (secret.Scheme == "env")
        {
            throw new ConnectorConfigurationException($"Environment variable {secret.Name} is not set (the API key is read only from the environment)", e);
        }
    }

    async Task<IChatClient> ClientAsync(string model, CancellationToken ct)
    {
        if (_clients.TryGetValue(model, out var c)) return c;
        var key = await EnsureKeyAsync(ct);
        var timeout = int.TryParse(connection.Get("RequestTimeoutSeconds"), out var t) ? t : 180;
        var oc = new OpenAIClient(new ApiKeyCredential(key), new OpenAIClientOptions
        {
            Endpoint = connection.RequireBaseUrl(), NetworkTimeout = TimeSpan.FromSeconds(timeout),
            // Factory-managed HttpClient (pooled sockets, DNS refresh, and a seam for HttpMessageHandler stubs in tests).
            Transport = new System.ClientModel.Primitives.HttpClientPipelineTransport(httpFactory.CreateClient(OpenAICompatibleModelConnector.ChatClient)),
        });
        c = oc.GetChatClient(model).AsIChatClient().AsBuilder().UseOpenTelemetry(sourceName: "SecAgent.GenAI", configure: o => o.EnableSensitiveData = false).Build();
        return _clients.GetOrAdd(model, c);
    }

    public async Task<ModelResponse> CompleteAsync(ModelRequest request, CancellationToken ct)
    {
        var client = await ClientAsync(request.Model, ct);
        // Microsoft Agent Framework agent: one fresh session per call (no ever-growing chat history).
        AIAgent agent = new ChatClientAgent(client, new ChatClientAgentOptions
        {
            Name = request.AgentName,
            ChatOptions = new ChatOptions
            {
                Temperature = request.Temperature, Seed = request.Seed, MaxOutputTokens = request.MaxOutputTokens,
                ResponseFormat = request.Output is { } o ? ChatResponseFormat.ForJsonSchema(o.Schema, o.Name, o.Description) : null,
            },
        });
        var messages = request.Messages.Select(m => new ChatMessage(m.Role switch
        {
            ModelRole.System => ChatRole.System, ModelRole.Assistant => ChatRole.Assistant, _ => ChatRole.User,
        }, m.Text)).ToList();
        try
        {
            var resp = await agent.RunAsync(messages, cancellationToken: ct);
            return new ModelResponse(resp.Text, request.Model, resp.ResponseId, new TokenUsage(resp.Usage?.InputTokenCount ?? 0, resp.Usage?.OutputTokenCount ?? 0));
        }
        catch (ClientResultException e)
        {
            var transient = e.Status is 0 or 408 or 429 or >= 500;
            throw new ConnectorException($"{ProviderFamily} {request.Model}: {(e.Status == 0 ? "no response" : $"HTTP {e.Status}")}", transient,
                e.Status == 0 ? null : (System.Net.HttpStatusCode)e.Status, null, e);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or TimeoutException || e is TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new ConnectorException($"{ProviderFamily} {request.Model}: {e.GetType().Name}", true, null, null, e);
        }
    }

    public async Task<IReadOnlyCollection<string>?> ListAvailableModelsAsync(CancellationToken ct)
    {
        if (ProviderFamily != "ollama" || connection.Get("HealthUrl") is not { } url) return null;   // hosted: failures trip the gateway's breaker instead
        await _health.WaitAsync(ct);
        try
        {
            if (time.GetUtcNow() - _catalog.At < TimeSpan.FromSeconds(30)) return _catalog.Models;
            try
            {
                var j = await httpFactory.CreateClient(OpenAICompatibleModelConnector.CatalogClient).GetFromJsonAsync<JsonElement>(url, ct);
                _catalog = (time.GetUtcNow(), j.GetProperty("models").EnumerateArray().Select(m => m.GetProperty("name").GetString()!).ToHashSet());
            }
            catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested) { _catalog = (time.GetUtcNow(), []); }
            return _catalog.Models;
        }
        finally { _health.Release(); }
    }
}
