using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecAgent.Core;
using SecAgent.Eval.Cases;

namespace SecAgent.Eval.Models;

/// <summary>Recorded model responses for one case (eval/golden/cases/&lt;id&gt;/replay.json).</summary>
public sealed class Cassette
{
    public string CaseId { get; set; } = "";
    /// <summary>authored-reference (hand-written expected answer of a correct agent) or recorded:&lt;provider&gt;/&lt;model&gt;.</summary>
    public string Source { get; set; } = "authored-reference";
    public string? Note { get; set; }
    public Dictionary<string, CassetteEntry> Steps { get; set; } = [];
}

public sealed class CassetteEntry
{
    public string? PromptSha256 { get; set; }
    public JsonElement Response { get; set; }
    /// <summary>Set only for recordings of a real call; authored responses have no usage (the harness estimates tokens).</summary>
    public RecordedUsage? Usage { get; set; }
}

public sealed class RecordedUsage
{
    public string Provider { get; set; } = ""; public string Model { get; set; } = "";
    public int TokensIn { get; set; } public int TokensOut { get; set; } public long LatencyMs { get; set; } public decimal CostUsd { get; set; }
    public string CostSource { get; set; } = "";
    public string RecordedAtUtc { get; set; } = "";
}

/// <summary>Loads and saves cassettes.</summary>
public interface ICassetteStore
{
    Cassette? Load(GoldenCase c);
    void Save(GoldenCase c, Cassette cassette);
}

public sealed class FileCassetteStore : ICassetteStore
{
    readonly ConcurrentDictionary<string, Cassette?> _cache = new();
    readonly object _write = new();

    public Cassette? Load(GoldenCase c) => _cache.GetOrAdd(c.ReplayPath, p =>
        File.Exists(p) ? JsonSerializer.Deserialize<Cassette>(File.ReadAllText(p), Schema.Json) : null);

    public void Save(GoldenCase c, Cassette cassette)
    {
        lock (_write)
        {
            var node = JsonSerializer.SerializeToNode(cassette, EvalJson.Files)!;
            File.WriteAllText(c.ReplayPath, node.ToJsonString(EvalJson.Files) + "\n");
            _cache[c.ReplayPath] = cassette;
        }
    }
}
