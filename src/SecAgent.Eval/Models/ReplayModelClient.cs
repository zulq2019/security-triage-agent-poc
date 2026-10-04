using SecAgent.Core;

namespace SecAgent.Eval.Models;

/// <summary>Replay mode (default, CI): returns the recorded response for (case, step). No network, no cost, deterministic.
/// Authored recordings carry no usage, so tokens are estimated with the o200k tokenizer and labelled "estimate".</summary>
public sealed class ReplayModelClient(ICassetteStore store, TimeProvider time) : IEvalModelClient
{
    public string Mode => "replay";

    public Task<ModelReply> CompleteAsync(ModelRequest r, CancellationToken ct)
    {
        var t0 = time.GetTimestamp();
        var cassette = store.Load(r.Case) ?? throw new ReplayMissException($"{r.Case.Id}: no replay.json (run the harness with --mode record, or author one)");
        if (!cassette.Steps.TryGetValue(r.Step, out var entry))
            throw new ReplayMissException($"{r.Case.Id}: replay.json has no recording for step '{r.Step}' (the pipeline asked for a call the recording does not cover)");
        var drift = entry.PromptSha256 != null && entry.PromptSha256 != r.PromptSha256;
        var u = entry.Usage;
        var usage = u != null
            ? new ModelUsageRecord(r.Step, u.Provider, u.Model, u.TokensIn, u.TokensOut, "recorded", 0m, "replay", (long)time.GetElapsedTime(t0).TotalMilliseconds, 1, drift)
            : new ModelUsageRecord(r.Step, "replay", cassette.Source, Tokens.Count(r.SystemText) + Tokens.Count(r.UserText), Tokens.Count(entry.Response.GetRawText()),
                "estimate", 0m, "replay", (long)time.GetElapsedTime(t0).TotalMilliseconds, 1, drift);
        return Task.FromResult(new ModelReply(entry.Response.Clone(), usage));
    }
}
