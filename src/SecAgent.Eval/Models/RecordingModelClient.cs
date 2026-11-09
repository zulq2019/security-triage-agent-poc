using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;

namespace SecAgent.Eval.Models;

/// <summary>Record mode: a decorator over the live client that writes each response, its prompt hash and its real usage into the case's
/// replay.json, replacing the previous recording for that case (steps not reached in this run are dropped, never left stale).</summary>
public sealed class RecordingModelClient([FromKeyedServices("live")] IEvalModelClient live, ICassetteStore store, TimeProvider time) : IEvalModelClient
{
    readonly ConcurrentDictionary<string, Cassette> _fresh = new();

    public string Mode => "record";

    public async Task<ModelReply> CompleteAsync(ModelRequest r, CancellationToken ct)
    {
        var reply = await live.CompleteAsync(r, ct);
        var u = reply.Usage;
        var cassette = _fresh.GetOrAdd(r.Case.Id, id => new Cassette { CaseId = id, Source = $"recorded:{u.Provider}/{u.Model}", Note = "Recorded from a live run by secagent-eval --mode record." });
        lock (cassette)
        {
            cassette.Steps[r.Step] = new CassetteEntry
            {
                PromptSha256 = r.PromptSha256, Response = reply.Json.Clone(),
                Usage = new RecordedUsage
                {
                    Provider = u.Provider, Model = u.Model, TokensIn = u.TokensIn, TokensOut = u.TokensOut, LatencyMs = u.LatencyMs, CostUsd = u.CostUsd,
                    CostSource = u.CostSource, RecordedAtUtc = time.GetUtcNow().ToString("O"),
                },
            };
            store.Save(r.Case, cassette);
        }
        return reply;
    }
}
