using Microsoft.Extensions.DependencyInjection;

namespace SecAgent.Eval.Models;

/// <summary>Maintenance mode (secagent-eval stamp): replays as usual and writes the current prompt hash into each recording it served.
/// Use after an intentional prompt or context change, once you have checked that the recorded answers still fit the new prompt.</summary>
public sealed class StampingModelClient([FromKeyedServices("replay")] IEvalModelClient replay, ICassetteStore store) : IEvalModelClient
{
    public string Mode => "stamp";

    public async Task<ModelReply> CompleteAsync(ModelRequest r, CancellationToken ct)
    {
        var reply = await replay.CompleteAsync(r, ct);
        var cassette = store.Load(r.Case)!;
        lock (cassette)
        {
            cassette.Steps[r.Step].PromptSha256 = r.PromptSha256;
            store.Save(r.Case, cassette);
        }
        return reply with { Usage = reply.Usage with { PromptDrift = false } };
    }
}
