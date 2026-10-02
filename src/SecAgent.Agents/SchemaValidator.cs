using System.Text.Json;
using Json.Schema;
using SecAgent.Core;

namespace SecAgent.Agents;

/// <summary>Validates adapter and agent outputs against the versioned JSON Schemas in rules/schema (section 7.1).</summary>
public sealed class SchemaValidator(ConfigSnapshot cfg)
{
    readonly Dictionary<string, JsonSchema> _cache = [];

    public JsonSchema Get(string name)
    {
        lock (_cache)
        {
            if (!_cache.TryGetValue(name, out var s)) _cache[name] = s = JsonSchema.FromText(cfg.Schemas[name]);
            return s;
        }
    }

    public JsonElement SchemaElement(string name) => JsonDocument.Parse(cfg.Schemas[name]).RootElement;

    /// <summary>Returns null when valid, else the first error.</summary>
    public string? Validate(string schemaName, JsonElement instance)
    {
        var result = Get(schemaName).Evaluate(instance, new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (result.IsValid) return null;
        var err = result.Details?.Where(d => d.Errors != null && d.Errors.Count > 0)
            .Select(d => $"{d.InstanceLocation}: {string.Join("; ", d.Errors!.Values)}").FirstOrDefault();
        return err ?? "schema validation failed";
    }

    public string? ValidateFinding(Finding f) =>
        Validate("finding", JsonSerializer.SerializeToElement(f, Schema.Json));
}
