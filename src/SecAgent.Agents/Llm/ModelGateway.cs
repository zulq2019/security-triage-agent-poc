using System.Diagnostics;
using System.Text.Json;
using SecAgent.Connectors;
using SecAgent.Core;

namespace SecAgent.Agents.Llm;

public sealed class RunBudget(int tokens, decimal cost)
{
    int _used; decimal _cost;
    public int Tokens => tokens;
    public decimal CostCap => cost;
    public int Used => _used;
    public decimal CostUsed => _cost;
    public int Remaining => Math.Max(0, tokens - _used);
    public void Add(int t, decimal c) { Interlocked.Add(ref _used, t); lock (this) _cost += c; }
}

public sealed record CallSpec(string TaskType, string SchemaName, string? Severity = null, int AttemptNo = 1, double? Confidence = null, string TriggerType = "pr",
    string? Repo = null, int? PrNumber = null);
public sealed record GatewayResult(JsonElement Json, RoutingDecision Routing, double Seconds);

public sealed class ModelUnavailableException(string m) : Exception(m);
public sealed class SchemaInvalidException(string m) : Exception(m);
public sealed class OverBudgetPackException(string m) : Exception(m);

/// <summary>Thin model gateway (stands in for the APIM AI gateway, FR-40): applies the routing policy from gateway/models.yaml,
/// logs a RoutingDecision per call, fails over within a tier, enforces run budgets and the kill switch, validates JSON output.
/// The call itself goes through the tenant's model provider connector (<see cref="IModelProviderClient"/>: Ollama / OpenAI / Azure OpenAI
/// via a Microsoft Agent Framework ChatClientAgent, or the in-memory fake); the gateway never sees an API key.</summary>
public sealed class ModelGateway
{
    readonly ConfigSnapshot _cfg; readonly SqlStore _store; readonly KillSwitch _kill; readonly SchemaValidator _validator; readonly PipelineConnectors _connectors;
    readonly SemaphoreSlim _gate;
    readonly Dictionary<string, int> _failures = new();

    public ModelGateway(ConfigSnapshot cfg, SqlStore store, KillSwitch kill, SchemaValidator validator, PipelineConnectors connectors)
    {
        _cfg = cfg; _store = store; _kill = kill; _validator = validator; _connectors = connectors;
        _gate = new SemaphoreSlim(Math.Max(1, cfg.Gateway.MaxConcurrentCalls));
    }

    /// <summary>The model provider of the repository's tenant (multi-tenant: no repository = no tenant = refused, never a fallback).</summary>
    IModelProviderClient ModelClient(CallSpec spec) => _connectors.Models.ForTenant(_connectors.Tenants.ForRepository(spec.Repo ?? ""));

    async Task<HashSet<string>> AvailableModelsAsync(CallSpec spec, CancellationToken ct)
    {
        IReadOnlyCollection<string>? models;
        try { models = await ModelClient(spec).ListAvailableModelsAsync(ct); }
        catch (ConnectorException e) when (e is not ConnectorConfigurationException and not ConnectorNotConfiguredException and not UnknownTenantException) { models = []; }
        catch (ConnectorException e) { throw new ModelUnavailableException(e.Message); }
        // Hosted provider (no model list probe): every configured deployment is a candidate; the circuit breaker handles failures.
        return models?.ToHashSet() ?? _cfg.Gateway.Tiers.Values.SelectMany(t => t).Select(d => d.Model).ToHashSet();
    }

    public async Task<(RoutingDecision Decision, List<DeploymentConfig> Candidates)> RouteAsync(ContextPack pack, CallSpec spec, RunBudget budget, CancellationToken ct)
    {
        var g = _cfg.Gateway;
        var reasons = new List<string>();
        var baseTier = g.TaskTiers.GetValueOrDefault(spec.TaskType, "small");
        reasons.Add($"{spec.TaskType} task: default {baseTier} tier");
        var high = (spec.Severity != null && g.QualityRules.HighIfSeverity.Contains(spec.Severity))
                   || (g.QualityRules.HighIfRetry && spec.AttemptNo > 1)
                   || (spec.Confidence is { } conf && conf < g.QualityRules.HighIfConfidenceBelow);
        var tier = baseTier;
        if (high)
        {
            var why = spec.AttemptNo > 1 ? $"retry #{spec.AttemptNo - 1} after failed verification" : spec.Severity is { } s && g.QualityRules.HighIfSeverity.Contains(s) ? $"severity {s}" : "low confidence";
            var idx = g.TierOrder.IndexOf(baseTier);
            if (idx >= 0 && idx < g.TierOrder.Count - 1) { tier = g.TierOrder[idx + 1]; reasons.Add($"high quality ({why}): escalate one tier to {tier}"); }
            else reasons.Add($"high quality ({why}): already top tier");
        }
        var est = pack.TokenTotal + g.OutputReserveTokens;
        var frac = budget.Tokens == 0 ? 1 : (double)budget.Remaining / budget.Tokens;
        if (frac < _cfg.Policies.Thresholds.LowBudgetFraction || est > budget.Remaining)
        {
            if (high) throw new BudgetExceededException($"Run budget low ({budget.Remaining} tokens left) for a high-quality {spec.TaskType} task: no downgrade, stopping safely.");
            tier = g.TierOrder[0]; reasons.Add($"low budget ({budget.Remaining} tokens left): standard task routed to {tier}");
            if (est > budget.Remaining) throw new BudgetExceededException($"Run token budget exhausted ({budget.Remaining} left, call needs ~{est}).");
        }
        var available = await AvailableModelsAsync(spec, ct);
        var candidates = g.Tiers[tier]
            .Where(d => available.Contains(d.Model) || available.Contains(d.Model + ":latest"))
            .Where(d => d.ContextWindow >= est)
            .Where(d => _failures.GetValueOrDefault(d.Id) < 3)  // circuit breaker
            .OrderBy(d => d.Fallback).ToList();
        if (candidates.Count == 0) throw new ModelUnavailableException($"No available deployment in tier {tier} (pausing for human / resume from checkpoint)");
        if (candidates[0].Fallback) reasons.Add("primary deployment unavailable: fallback deployment of the same tier");
        var latency = g.LatencyTargetsMs.GetValueOrDefault(spec.TriggerType, 120000);
        reasons.Add(spec.TriggerType == "pr" ? $"PR-time: lowest-latency eligible deployment (target {latency / 1000}s)" : "sweep: batch allowed");
        var d0 = candidates[0];
        var rd = new RoutingDecision
        {
            ContextPackId = pack.ContextPackId, RunId = pack.RunId, TaskType = spec.TaskType, RequiredQuality = high ? "high" : "standard",
            ContextTokens = pack.TokenTotal, LatencyTargetMs = latency,
            BudgetRemainingJson = JsonSerializer.Serialize(new { tokens = budget.Remaining, cost = budget.CostCap - budget.CostUsed }),
            CandidateModels = candidates.Select(c => c.Id).ToList(), ChosenModelId = d0.Model, ModelVersion = d0.Version, Deployment = d0.Id, Tier = tier,
            Reason = string.Join("; ", reasons), FallbackUsed = d0.Fallback,
        };
        return (rd, candidates);
    }

    public async Task<GatewayResult> CallAsync(ContextPack pack, CallSpec spec, RunBudget budget, CancellationToken ct)
    {
        _kill.ThrowIfOn("model call");
        if (!pack.MaskingApplied) throw new InvalidOperationException("Refusing to send a context pack without masking (FR-37)");
        if (pack.OverBudget) throw new OverBudgetPackException($"Required context exceeds the {pack.AgentId} budget ({pack.TokenBudget} tokens)");
        var (rd, candidates) = await RouteAsync(pack, spec, budget, ct);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _kill.Token);
        await _gate.WaitAsync(linked.Token);
        using var span = Telemetry.Source.StartActivity($"model.call {spec.TaskType}");
        rd.TraceId = Telemetry.TraceId; rd.SpanId = Telemetry.SpanId;
        span?.SetTag("secagent.context_pack_id", pack.ContextPackId.ToString());
        span?.SetTag("secagent.routing_id", rd.RoutingId.ToString());
        span?.SetTag("gen_ai.request.model", rd.ChosenModelId);
        var sw = Stopwatch.StartNew();
        try
        {
            Exception? last = null;
            foreach (var (d, idx) in candidates.Select((d, i) => (d, i)))
            {
                if (idx > 0) { rd.FallbackUsed = true; rd.Reason += $"; {candidates[idx - 1].Id} failed ({last?.GetType().Name}): failover to {d.Id}"; rd.ChosenModelId = d.Model; rd.Deployment = d.Id; rd.ModelVersion = d.Version; }
                try
                {
                    var json = await InvokeWithSchemaRetriesAsync(d, pack, spec, rd, linked.Token);
                    _failures[d.Id] = 0;
                    rd.LatencyMs = (int)sw.ElapsedMilliseconds;
                    var price = UsageMath.PriceFor(_cfg.Gateway, Provider, d.Model, d);
                    rd.Cost = UsageMath.Cost(rd.TokensIn, rd.TokensOut, price);
                    rd.Outcome = "ok";
                    budget.Add(rd.TokensIn + rd.TokensOut, rd.Cost);
                    span?.SetTag("gen_ai.usage.input_tokens", rd.TokensIn); span?.SetTag("gen_ai.usage.output_tokens", rd.TokensOut);
                    span?.SetTag("secagent.usage.cost", rd.Cost);
                    _store.InsertRouting(rd);
                    RecordUsage(rd, pack, spec, price.Source, span);
                    return new GatewayResult(json, rd, sw.Elapsed.TotalSeconds);
                }
                catch (SchemaInvalidException) { throw; }
                catch (OperationCanceledException) { throw; }
                catch (Exception e) when (e is ConnectorConfigurationException or ConnectorNotConfiguredException or UnknownTenantException)
                {
                    throw new ModelUnavailableException(e.Message);   // e.g. API key not set: no failover can fix configuration
                }
                catch (Exception e) when (e is ConnectorException or HttpRequestException or TimeoutException or IOException)
                {
                    last = e; _failures[d.Id] = _failures.GetValueOrDefault(d.Id) + 1;
                }
            }
            throw new ModelUnavailableException($"All deployments failed: {last?.Message}");
        }
        catch (Exception e)
        {
            rd.LatencyMs = (int)sw.ElapsedMilliseconds;
            rd.Outcome = e is OperationCanceledException && _kill.IsOn ? "cancelled_kill_switch" : e.GetType().Name;
            var dep = candidates.FirstOrDefault(c => c.Id == rd.Deployment);
            var price = UsageMath.PriceFor(_cfg.Gateway, Provider, rd.ChosenModelId, dep);
            rd.Cost = UsageMath.Cost(rd.TokensIn, rd.TokensOut, price);   // tokens spent on failed attempts still cost money on a hosted provider
            budget.Add(rd.TokensIn + rd.TokensOut, rd.Cost);
            _store.InsertRouting(rd);
            RecordUsage(rd, pack, spec, price.Source, span);
            span?.SetStatus(ActivityStatusCode.Error, e.Message);
            throw;
        }
        finally { _gate.Release(); }
    }

    string Provider => UsageMath.ProviderOf(_cfg.Gateway);

    /// <summary>One ModelUsage row per call (usage/cost observability). Never fails the call: a usage write error is tagged on the span.</summary>
    void RecordUsage(RoutingDecision rd, ContextPack pack, CallSpec spec, string priceSource, Activity? span)
    {
        try
        {
            _store.InsertUsage(new ModelUsage
            {
                RoutingId = rd.RoutingId, ContextPackId = pack.ContextPackId, RunId = rd.RunId, TsUtc = rd.DecidedAt, Repo = spec.Repo, PrNumber = spec.PrNumber,
                Mode = spec.TriggerType, AgentId = pack.AgentId, TaskPurpose = spec.TaskType, Tier = rd.Tier, ModelId = rd.ChosenModelId, ModelVersion = rd.ModelVersion,
                Deployment = rd.Deployment, Provider = Provider, InputTokens = rd.TokensIn, OutputTokens = rd.TokensOut, LatencyMs = rd.LatencyMs, Cost = rd.Cost,
                PriceSource = priceSource, Outcome = UsageMath.Outcome(rd.Outcome, rd.SchemaAttempts, rd.FallbackUsed), OutcomeDetail = rd.Outcome == "ok" ? null : rd.Outcome,
                SchemaAttempts = rd.SchemaAttempts, FallbackUsed = rd.FallbackUsed, TraceId = rd.TraceId,
            });
        }
        catch (Exception e) { span?.SetTag("secagent.usage.write_error", e.GetType().Name); }
    }

    async Task<JsonElement> InvokeWithSchemaRetriesAsync(DeploymentConfig d, ContextPack pack, CallSpec spec, RoutingDecision rd, CancellationToken ct)
    {
        var schema = _validator.SchemaElement(spec.SchemaName);
        var provider = ModelClient(spec);
        // One fresh request per attempt (no ever-growing chat history, section 6.1); structured output by JSON schema.
        var request = new ModelRequest(d.Model, [new(ModelRole.System, pack.SystemText), new(ModelRole.User, pack.UserText)],
            new StructuredOutput(spec.SchemaName.Replace("-", "_"), "SecAgent " + spec.SchemaName, schema),
            MaxOutputTokens: _cfg.Gateway.OutputReserveTokens, Temperature: _cfg.Gateway.SendTemperature ? 0 : null, Seed: _cfg.Gateway.SendSeed ? 42 : null,
            AgentName: pack.AgentId);
        var max = _cfg.Policies.Retries.MaxSchemaRetries;
        string? lastError = null;
        for (int attempt = 0; attempt <= max; attempt++)
        {
            rd.SchemaAttempts = attempt + 1;
            var resp = await provider.CompleteAsync(request, ct);
            rd.TokensIn += (int)resp.Usage.InputTokens;
            rd.TokensOut += (int)resp.Usage.OutputTokens;
            rd.GatewayRequestId = resp.ResponseId ?? rd.GatewayRequestId;
            try
            {
                var el = JsonDocument.Parse(StripFences(resp.Text)).RootElement.Clone();
                lastError = _validator.Validate(spec.SchemaName, el);
                if (lastError == null) return el;
            }
            catch (JsonException e) { lastError = "invalid JSON: " + e.Message; }
        }
        throw new SchemaInvalidException($"Model output failed schema '{spec.SchemaName}' after {max + 1} attempts: {lastError}");
    }

    static string StripFences(string s)
    {
        s = s.Trim();
        if (s.StartsWith("```")) { s = s[(s.IndexOf('\n') + 1)..]; if (s.EndsWith("```")) s = s[..^3]; }
        return s.Trim();
    }
}
