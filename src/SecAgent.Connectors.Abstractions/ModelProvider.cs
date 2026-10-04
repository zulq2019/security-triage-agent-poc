using System.Text.Json;

namespace SecAgent.Connectors;

// Model provider: chat completion with structured (JSON schema) output and token usage. Routing, budgets, schema validation and
// failover stay in the pipeline's model gateway; a provider only performs one call against one model / deployment.

public enum ModelRole { System, User, Assistant }

public sealed record ModelMessage(ModelRole Role, string Text);

/// <summary>Ask the model for JSON matching <paramref name="Schema"/> (JSON Schema).</summary>
public sealed record StructuredOutput(string Name, string Description, JsonElement Schema);

public sealed record ModelRequest(string Model, IReadOnlyList<ModelMessage> Messages, StructuredOutput? Output = null, int? MaxOutputTokens = null,
    float? Temperature = null, long? Seed = null, string? AgentName = null);

public sealed record TokenUsage(long InputTokens, long OutputTokens)
{
    public long TotalTokens => InputTokens + OutputTokens;
    public static readonly TokenUsage None = new(0, 0);
}

public sealed record ModelResponse(string Text, string Model, string? ResponseId, TokenUsage Usage);

public interface IModelCompletion
{
    /// <summary>One completion. Provider failures surface as <see cref="ConnectorException"/> (IsTransient = worth failing over).</summary>
    Task<ModelResponse> CompleteAsync(ModelRequest request, CancellationToken ct);
}

public interface IModelCatalog
{
    /// <summary>Models the provider serves right now, or null when the provider has no catalogue to probe (hosted APIs).</summary>
    Task<IReadOnlyCollection<string>?> ListAvailableModelsAsync(CancellationToken ct);
}

public interface IModelProviderClient : IModelCompletion, IModelCatalog
{
    /// <summary>Provider family for usage records and pricing: ollama | openai | azureopenai | fake.</summary>
    string ProviderFamily { get; }
}
