using System.Text.Json;
using SecAgent.Eval.Cases;

namespace SecAgent.Eval.Models;

/// <summary>One model call made by a stage. Step is the replay key within the case (triage, fix, fix.repair).</summary>
public sealed record ModelRequest(GoldenCase Case, string Step, string AgentId, string TaskType, string SchemaName, string? Severity,
    string SystemText, string UserText)
{
    /// <summary>sha256 of the exact prompt; a recording made for a different prompt is reported as drift.</summary>
    public string PromptSha256 => SecAgent.Core.Hashing.Sha256(SystemText + "\n\u241E\n" + UserText);
}

/// <summary>Token, cost and latency accounting for one call. TokenSource: reported (by the provider) | recorded (from a recording) | estimate (o200k tokenizer).
/// CostSource: replay (no call made, $0) | local | config | placeholder | none (see UsageMath.PriceFor).</summary>
public sealed record ModelUsageRecord(string Step, string Provider, string Model, int TokensIn, int TokensOut, string TokenSource,
    decimal CostUsd, string CostSource, long LatencyMs, int SchemaAttempts, bool PromptDrift);

public sealed record ModelReply(JsonElement Json, ModelUsageRecord Usage);

/// <summary>The model port of the harness. Strategy chosen by mode: replay, live or record.</summary>
public interface IEvalModelClient
{
    string Mode { get; }
    Task<ModelReply> CompleteAsync(ModelRequest request, CancellationToken ct);
}

public sealed class ReplayMissException(string m) : Exception(m);
