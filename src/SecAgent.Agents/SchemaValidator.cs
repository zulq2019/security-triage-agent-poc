using System.Collections.Concurrent;
using System.Text.Json;
using Json.Schema;
using SecAgent.Abstractions;
using SecAgent.Core;

namespace SecAgent.Agents;

/// <summary>Compiled JSON Schemas, keyed by name + content hash. Register one instance per container (singleton) and inject it.
/// Each schema is built with its own <see cref="SchemaRegistry"/>, so JsonSchema.Net's global $id registry is never touched and several
/// caches (e.g. one per test) can coexist without "Overwriting registered schemas is not permitted".</summary>
public sealed class JsonSchemaCache
{
    readonly ConcurrentDictionary<string, Lazy<JsonSchema>> _schemas = new();

    public int Count => _schemas.Count;

    public JsonSchema GetOrCompile(string name, string schemaText) =>
        _schemas.GetOrAdd(name + "|" + Hashing.Sha256(schemaText),
            _ => new Lazy<JsonSchema>(() => JsonSchema.FromText(schemaText, new BuildOptions { SchemaRegistry = new SchemaRegistry() }))).Value;
}

/// <summary>Validates adapter and agent outputs against the versioned JSON Schemas in rules/schema (section 7.1).</summary>
public sealed class SchemaValidator(ConfigSnapshot cfg, JsonSchemaCache cache) : IFindingSchemaValidator
{
    public JsonSchema Get(string name) => cache.GetOrCompile(name, cfg.Schemas[name]);

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
