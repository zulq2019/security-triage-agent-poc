using System.Text.Json;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Models;
using Xunit;
using static SecAgent.Eval.Tests.EvalTestKit;

namespace SecAgent.Eval.Tests;

public class ReplayModelClientTests
{
    static (GoldenCase Case, FileCassetteStore Store) CaseWith(string? replayJson)
    {
        var dir = TempDir("eval-case");
        var c = Case("rc"); c.Directory = dir;
        if (replayJson != null) File.WriteAllText(Path.Combine(dir, "replay.json"), replayJson);
        return (c, new FileCassetteStore());
    }

    static ModelRequest Req(GoldenCase c, string step = "triage", string user = "user prompt") =>
        new(c, step, "triage-agent", "triage", "triage-output", "high", "system prompt", user);

    const string Authored = """
        { "case_id": "rc", "source": "authored-reference",
          "steps": { "triage": { "prompt_sha256": null, "response": { "decision": "fix", "severity_effective": "high", "reason": "r", "confidence": 0.9 } } } }
        """;

    [Fact]
    public async Task Returns_the_recorded_response_with_estimated_tokens_and_zero_cost()
    {
        var (c, store) = CaseWith(Authored);
        var reply = await new ReplayModelClient(store, TimeProvider.System).CompleteAsync(Req(c), default);
        Assert.Equal("fix", reply.Json.GetProperty("decision").GetString());
        Assert.Equal("estimate", reply.Usage.TokenSource);
        Assert.True(reply.Usage.TokensIn > 0 && reply.Usage.TokensOut > 0);
        Assert.Equal(0m, reply.Usage.CostUsd);
        Assert.Equal("replay", reply.Usage.Provider);
        Assert.False(reply.Usage.PromptDrift);   // unstamped recording: no drift claim
    }

    [Fact]
    public async Task Missing_recording_or_step_is_a_replay_miss()
    {
        var (none, store) = CaseWith(null);
        await Assert.ThrowsAsync<ReplayMissException>(() => new ReplayModelClient(store, TimeProvider.System).CompleteAsync(Req(none), default));
        var (c, store2) = CaseWith(Authored);
        var e = await Assert.ThrowsAsync<ReplayMissException>(() => new ReplayModelClient(store2, TimeProvider.System).CompleteAsync(Req(c, "fix"), default));
        Assert.Contains("fix", e.Message);
    }

    [Fact]
    public async Task Prompt_change_after_stamping_is_reported_as_drift()
    {
        var (c, store) = CaseWith(Authored);
        var replay = new ReplayModelClient(store, TimeProvider.System);
        var stamp = new StampingModelClient(replay, store);
        await stamp.CompleteAsync(Req(c), default);
        var saved = JsonDocument.Parse(File.ReadAllText(c.ReplayPath)).RootElement.GetProperty("steps").GetProperty("triage").GetProperty("prompt_sha256").GetString();
        Assert.Equal(Req(c).PromptSha256, saved);
        var fresh = new ReplayModelClient(new FileCassetteStore(), TimeProvider.System);
        Assert.False((await fresh.CompleteAsync(Req(c), default)).Usage.PromptDrift);
        Assert.True((await fresh.CompleteAsync(Req(c, user: "changed prompt"), default)).Usage.PromptDrift);
    }

    [Fact]
    public async Task Recorded_usage_is_reported_as_recorded()
    {
        var (c, store) = CaseWith("""
            { "case_id": "rc", "source": "recorded:ollama/qwen2.5-coder:7b",
              "steps": { "triage": { "response": { "decision": "fix", "severity_effective": "high", "reason": "r", "confidence": 0.9 },
                "usage": { "provider": "ollama", "model": "qwen2.5-coder:7b", "tokens_in": 1200, "tokens_out": 80, "latency_ms": 4100, "cost_usd": 0, "cost_source": "local" } } } }
            """);
        var u = (await new ReplayModelClient(store, TimeProvider.System).CompleteAsync(Req(c), default)).Usage;
        Assert.Equal(("recorded", 1200, 80, "ollama", 0m), (u.TokenSource, u.TokensIn, u.TokensOut, u.Provider, u.CostUsd));
    }

    [Fact]
    public void Prompt_hash_covers_system_and_user_text()
    {
        var c = Case();
        Assert.NotEqual(Req(c).PromptSha256, Req(c, user: "other").PromptSha256);
        Assert.Equal(Req(c).PromptSha256, Req(c).PromptSha256);
        Assert.Matches("^[0-9a-f]{64}$", Req(c).PromptSha256);
    }
}

public class LiveModelClientTests
{
    [Fact]
    public void Live_mode_offers_the_whole_tier_primary_first_and_fails_over_only_on_transport_errors()
    {
        var cfg = SecAgent.Core.ConfigSnapshot.Load(RulesRoot);
        var live = new LiveModelClient(cfg, new SecAgent.Agents.SchemaValidator(cfg, new SecAgent.Agents.JsonSchemaCache()), TimeProvider.System);
        var candidates = live.Candidates("triage", null);
        Assert.True(candidates.Count > 1, "rules/gateway/models.yaml lists a fallback deployment per tier");
        Assert.False(candidates[0].Fallback);
        Assert.Contains(candidates.Skip(1), d => d.Fallback);
        Assert.Equal(candidates[0], live.Choose("triage", null));

        Assert.True(LiveModelClient.IsTransient(new HttpRequestException("synthetic"), default));
        Assert.True(LiveModelClient.IsTransient(new TimeoutException(), default));
        Assert.True(LiveModelClient.IsTransient(new TaskCanceledException(), default));             // provider timeout, not our cancellation
        Assert.False(LiveModelClient.IsTransient(new TaskCanceledException(), new CancellationToken(true)));
        Assert.False(LiveModelClient.IsTransient(new SecAgent.Agents.Llm.SchemaInvalidException("bad output"), default));
        Assert.False(LiveModelClient.IsTransient(new SecAgent.Agents.Llm.ModelUnavailableException("API key env var not set"), default));
    }
}
