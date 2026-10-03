using Microsoft.Extensions.DependencyInjection;

namespace SecAgent.Connectors.OpenAI;

/// <summary>Plug-in "openai-compatible". Setup: BaseUrl (http://localhost:11434/v1, https://api.openai.com/v1,
/// https://&lt;resource&gt;.openai.azure.com/openai/v1/), Secret (API key reference; optional for Ollama), Settings: Flavor = ollama | openai |
/// azureopenai, HealthUrl (Ollama model list, e.g. http://localhost:11434/api/tags), RequestTimeoutSeconds.
/// The dashboard derives this connection from the existing ModelProvider section, so the provider switch stays one setting.</summary>
public sealed class OpenAICompatibleModelConnector(ISecretProvider secrets, IHttpClientFactory httpFactory, TimeProvider time) : IConnectorClientProvider<IModelProviderClient>
{
    public const string Id = "openai-compatible";
    public const string CatalogClient = "secagent.connector.openai-compatible.catalog";
    public const string ChatClient = "secagent.connector.openai-compatible.chat";

    public static readonly ConnectorDescriptor Descriptor = new(
        Id, "Models (Ollama / OpenAI / Azure OpenAI)", ConnectorKind.ModelProvider, "models", ConnectorTransport.Sdk,
        [ConnectorCapabilities.ChatCompletion, ConnectorCapabilities.StructuredOutput, ConnectorCapabilities.TokenUsage, ConnectorCapabilities.ModelCatalog],
        [new("Chat completions", "call", "Small and strong tiers through the model gateway (routing, budgets, schema validation stay in SecAgent).")],
        ["bypass_gateway", "see_unmasked_secrets", "fine_tune", "admin"],
        [
            new("BaseUrl", "OpenAI-compatible endpoint", true, Example: "https://api.openai.com/v1"),
            new("Secret", "API key reference (not needed for Ollama)", false, true, "kv:openai-api-key"),
            new("Flavor", "ollama | openai | azureopenai", false, Example: "openai"),
            new("HealthUrl", "Model list URL (Ollama only)", false, Example: "http://localhost:11434/api/tags"),
        ],
        Notes: "Managed identity for Azure OpenAI is an open item (API key reference today).");

    public ConnectorDescriptor Describe() => Descriptor;

    public IModelProviderClient CreateClient(ConnectionSettings connection) => new OpenAICompatibleModelClient(connection, secrets, httpFactory, time);

    public async Task<HealthResult> CheckHealthAsync(ConnectionSettings connection, CancellationToken ct)
    {
        try
        {
            var client = new OpenAICompatibleModelClient(connection, secrets, httpFactory, time);
            await client.EnsureKeyAsync(ct);
            var models = await client.ListAvailableModelsAsync(ct);
            return models switch
            {
                null => HealthResult.Healthy($"{client.ProviderFamily}: key reference resolves (hosted API, no model list probe)", time.GetUtcNow()),
                { Count: 0 } => HealthResult.Failing($"{client.ProviderFamily}: model list empty or unreachable", time.GetUtcNow()),
                _ => HealthResult.Healthy($"{client.ProviderFamily}: {models.Count} models available", time.GetUtcNow()),
            };
        }
        catch (ConnectorException e) { return HealthResult.Failing(e.Message, time.GetUtcNow()); }
    }
}

public static class OpenAICompatibleModelConnectorRegistration
{
    public static ConnectorsBuilder AddOpenAICompatibleModelConnector(this ConnectorsBuilder builder)
    {
        builder.Services.AddHttpClient(OpenAICompatibleModelConnector.CatalogClient, c => c.Timeout = TimeSpan.FromSeconds(5));
        builder.Services.AddHttpClient(OpenAICompatibleModelConnector.ChatClient, c => c.Timeout = Timeout.InfiniteTimeSpan);   // the SDK's NetworkTimeout applies
        return builder.AddConnector<OpenAICompatibleModelConnector, IModelProviderClient>();
    }
}
