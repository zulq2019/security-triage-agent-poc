using System.Text.Json;
using Json.Schema;
using SecAgent.Core;

namespace SecAgent.Agents;

/// <summary>Validates adapter and agent outputs against the versioned JSON Schemas in rules/schema (section 7.1).</summary>
public sealed class SchemaValidator(ConfigSnapshot cfg)
{
    // Process-wide: JsonSchema.Net registers each schema's $id globally, so a second validator instance building the same schema
    // would throw "Overwriting registered schemas is not permitted". Keyed by content so a changed schema is still rebuilt.
    static readonly Dictionary<string, JsonSchema> Cache = [];

    public JsonSchema Get(string name)
    {
        var text = cfg.Schemas[name];
        var key = name + "|" + Hashing.Sha256(text);
        lock (Cache)
        {
            if (!Cache.TryGetValue(key, out var s)) Cache[key] = s = JsonSchema.FromText(text, new BuildOptions { SchemaRegistry = new SchemaRegistry() });
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
