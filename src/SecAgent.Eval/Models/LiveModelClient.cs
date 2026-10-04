using System.ClientModel;
using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;
using SecAgent.Agents;
using SecAgent.Agents.Llm;
using SecAgent.Core;

namespace SecAgent.Eval.Models;

/// <summary>Live mode: calls the provider selected by the existing provider switch (ollama | openai | azureopenai, see ModelProviderSettings)
/// with the same tier rules as the pipeline's ModelGateway (task tier, one tier up for critical/high severity), JSON-schema output and
/// schema-repair retries. It does not go through ModelGateway itself because that class persists every call to SQL.</summary>
public sealed class LiveModelClient(ConfigSnapshot cfg, SchemaValidator validator, TimeProvider time) : IEvalModelClient
{
    readonly Dictionary<string, IChatClient> _clients = new();
    readonly SemaphoreSlim _gate = new(Math.Max(1, cfg.Gateway.MaxConcurrentCalls));

    public string Mode => "live";

    /// <summary>First choice for the task (primary deployment of its tier).</summary>
    public DeploymentConfig Choose(string taskType, string? severity) => Candidates(taskType, severity)[0];

    /// <summary>The tier's deployments, primary first then fallbacks: the order ModelGateway.CallAsync fails over in.</summary>
    public IReadOnlyList<DeploymentConfig> Candidates(string taskType, string? severity)
    {
        var g = cfg.Gateway;
        var tier = g.TaskTiers.GetValueOrDefault(taskType, "small");
        if (severity != null && g.QualityRules.HighIfSeverity.Contains(severity))
        {
            var i = g.TierOrder.IndexOf(tier);
            if (i >= 0 && i < g.TierOrder.Count - 1) tier = g.TierOrder[i + 1];
        }
        return g.Tiers[tier].OrderBy(d => d.Fallback).ToList();
    }

    IChatClient Client(DeploymentConfig d)
    {
        lock (_clients)
        {
            if (_clients.TryGetValue(d.Id, out var c)) return c;
            var key = Environment.GetEnvironmentVariable(cfg.Gateway.ApiKeyEnv);
            if (string.IsNullOrEmpty(key))
            {
                if (cfg.Gateway.Provider is "openai" or "azureopenai")
                    throw new ModelUnavailableException($"Environment variable {cfg.Gateway.ApiKeyEnv} is not set (the API key is read only from the environment)");
                key = "ollama";
            }
            var oc = new OpenAIClient(new ApiKeyCredential(key), new OpenAIClientOptions
            {
                Endpoint = new Uri(cfg.Gateway.Endpoint), NetworkTimeout = TimeSpan.FromSeconds(cfg.Gateway.RequestTimeoutSeconds),
            });
            return _clients[d.Id] = oc.GetChatClient(d.Model).AsIChatClient();
        }
    }

    /// <summary>Tries the tier's deployments in order and fails over on transport errors (no response, timeout, 408/429/5xx), as the
    /// production gateway does. Schema failures and configuration errors are not failed over.</summary>
    public async Task<ModelReply> CompleteAsync(ModelRequest r, CancellationToken ct)
    {
        Exception? last = null;
        foreach (var d in Candidates(r.TaskType, r.Severity))
        {
            try { return await CompleteWithAsync(d, r, ct); }
            catch (Exception e) when (IsTransient(e, ct)) { last = e; }
        }
        throw new ModelUnavailableException($"All deployments failed: {last?.GetType().Name} {last?.Message}");
    }

    /// <summary>Errors a different deployment may not have (exposed for tests).</summary>
    public static bool IsTransient(Exception e, CancellationToken ct) => e switch
    {
        ClientResultException c => c.Status is 0 or 408 or 429 or >= 500,
        HttpRequestException or IOException or TimeoutException => true,
        TaskCanceledException => !ct.IsCancellationRequested,
        _ => false,
    };

    async Task<ModelReply> CompleteWithAsync(DeploymentConfig d, ModelRequest r, CancellationToken ct)
    {
        var schema = validator.SchemaElement(r.SchemaName);
        AIAgent agent = new ChatClientAgent(Client(d), new ChatClientAgentOptions
        {
            Name = r.AgentId,
            ChatOptions = new ChatOptions
            {
                Temperature = cfg.Gateway.SendTemperature ? 0 : null, Seed = cfg.Gateway.SendSeed ? 42 : null, MaxOutputTokens = cfg.Gateway.OutputReserveTokens,
                ResponseFormat = ChatResponseFormat.ForJsonSchema(schema, r.SchemaName.Replace("-", "_"), "SecAgent " + r.SchemaName),
            },
        });
        await _gate.WaitAsync(ct);
        try
        {
            var t0 = time.GetTimestamp();
            int tin = 0, tout = 0; string? lastError = null;
            var max = cfg.Policies.Retries.MaxSchemaRetries;
            for (int attempt = 0; attempt <= max; attempt++)
            {
                var resp = await agent.RunAsync([new ChatMessage(ChatRole.System, r.SystemText), new ChatMessage(ChatRole.User, r.UserText)], cancellationToken: ct);
                tin += (int)(resp.Usage?.InputTokenCount ?? 0); tout += (int)(resp.Usage?.OutputTokenCount ?? 0);
                try
                {
                    var el = JsonDocument.Parse(StripFences(resp.Text)).RootElement.Clone();
                    lastError = validator.Validate(r.SchemaName, el);
                    if (lastError == null)
                    {
                        var provider = UsageMath.ProviderOf(cfg.Gateway);
                        var price = UsageMath.PriceFor(cfg.Gateway, provider, d.Model, d);
                        return new ModelReply(el, new ModelUsageRecord(r.Step, provider, d.Model, tin, tout, "reported", UsageMath.Cost(tin, tout, price), price.Source,
                            (long)time.GetElapsedTime(t0).TotalMilliseconds, attempt + 1, false));
                    }
                }
                catch (JsonException e) { lastError = "invalid JSON: " + e.Message; }
            }
            throw new SchemaInvalidException($"Model output failed schema '{r.SchemaName}' after {max + 1} attempts: {lastError}");
        }
        finally { _gate.Release(); }
    }

    static string StripFences(string s)
    {
        s = s.Trim();
        if (s.StartsWith("```")) { s = s[(s.IndexOf('\n') + 1)..]; if (s.EndsWith("```")) s = s[..^3]; }
        return s.Trim();
    }
}
