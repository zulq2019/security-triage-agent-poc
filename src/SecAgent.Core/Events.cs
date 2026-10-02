using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;

namespace SecAgent.Core;

/// <summary>Live run events for the dashboard (SSE). Every event is masked, persisted (RunEvent table) and broadcast.</summary>
public sealed class RunEventBus(SecretMasker masker)
{
    readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, Channel<string>>> _subs = new();
    readonly ConcurrentDictionary<Guid, int> _seq = new();
    public Action<Guid, int, string>? Persist { get; set; }
    public event Action<Guid, string>? OnEvent;

    public void Publish(Guid runId, string type, object data)
    {
        var seq = _seq.AddOrUpdate(runId, 1, (_, v) => v + 1);
        var json = JsonSerializer.Serialize(new { seq, type, ts = DateTime.UtcNow, data }, Schema.Json);
        json = masker.Mask(json, count: false);
        try { Persist?.Invoke(runId, seq, json); } catch { /* persistence failure must not break the run */ }
        OnEvent?.Invoke(runId, json);
        if (_subs.TryGetValue(runId, out var subs)) foreach (var c in subs.Values) c.Writer.TryWrite(json);
    }

    public (Guid Id, ChannelReader<string> Reader) Subscribe(Guid runId)
    {
        var id = Guid.NewGuid();
        var ch = Channel.CreateUnbounded<string>();
        _subs.GetOrAdd(runId, _ => new())[id] = ch;
        return (id, ch.Reader);
    }

    public void Unsubscribe(Guid runId, Guid id)
    {
        if (_subs.TryGetValue(runId, out var subs) && subs.TryRemove(id, out var ch)) ch.Writer.TryComplete();
    }
}

/// <summary>Helper used by agents to write Claude-style activity entries: text, flag, model reasoning, tool calls, details.</summary>
public sealed class Feed(RunEventBus bus, Guid runId)
{
    public Guid RunId => runId;
    public RunEventBus Bus => bus;

    public void Agent(string agent, string state, string text, int? tokens = null, string? model = null) =>
        bus.Publish(runId, "agent", new { id = agent, state, text, tokens, model });

    public string Entry(string agent, string text, string? kind = null, string[]? flag = null, string? think = null, double? thinkSecs = null)
    {
        var id = "e" + Guid.NewGuid().ToString("N")[..10];
        bus.Publish(runId, "entry", new { id, agent, text, kind, flag, think, think_secs = thinkSecs });
        return id;
    }

    /// <summary>Re-publish an entry with the same id: the dashboard updates text / flag / reasoning in place.</summary>
    public void Update(string id, string agent, string text, string? kind = null, string[]? flag = null, string? think = null, double? thinkSecs = null) =>
        bus.Publish(runId, "entry", new { id, agent, text, kind, flag, think, think_secs = thinkSecs });

    public string ToolStart(string entryId, string name, string args)
    {
        var id = "t" + Guid.NewGuid().ToString("N")[..10];
        bus.Publish(runId, "tool", new { entry = entryId, id, name, args, state = "running" });
        return id;
    }

    public void ToolEnd(string entryId, string toolId, string name, string args, bool ok, long ms) =>
        bus.Publish(runId, "tool", new { entry = entryId, id = toolId, name, args, state = ok ? "ok" : "fail", ms });

    public void Detail(string entryId, object detail) => bus.Publish(runId, "detail", new { entry = entryId, detail });
    public void Flag(string entryId, string cls, string label) => bus.Publish(runId, "flag", new { entry = entryId, flag = new[] { cls, label } });
    public void Publish(string type, object data) => bus.Publish(runId, type, data);
}
