using SecAgent.Core;
using Xunit;

namespace SecAgent.Tests;

public class UsageCostTests
{
    static GatewayConfig Hosted(decimal smallIn = 0, decimal smallOut = 0) => new()
    {
        Provider = "openai",
        PriceBook = [new() { Provider = "openai", Tier = "small", Model = "m-small", CostPer1kIn = 0.001m, CostPer1kOut = 0.004m, Placeholder = true }],
    };

    [Fact]
    public void Local_models_cost_zero_even_with_tokens()
    {
        var p = UsageMath.PriceFor(TestEnv.Cfg.Gateway, "ollama", "qwen2.5-coder:7b");
        Assert.Equal("local", p.Source);
        Assert.Equal(0m, UsageMath.Cost(120_000, 40_000, p));
    }

    [Fact]
    public void Hosted_cost_uses_price_book_placeholder_and_rounds_to_6dp()
    {
        var p = UsageMath.PriceFor(Hosted(), "openai", "m-small");
        Assert.Equal("placeholder", p.Source);
        Assert.Equal(0.0015m + 0.0008m, UsageMath.Cost(1500, 200, p));          // 1.5k in × 0.001 + 0.2k out × 0.004
        Assert.Equal(0.000002m, UsageMath.Cost(2, 0, new Price(0.001m, 0, "config")));
    }

    [Fact]
    public void Deployment_price_wins_over_price_book_and_unknown_model_is_none()
    {
        var d = new DeploymentConfig { Model = "m-small", CostPer1kIn = 0.002m, CostPer1kOut = 0.01m };
        var p = UsageMath.PriceFor(Hosted(), "openai", "m-small", d);
        Assert.Equal("config", p.Source);
        Assert.Equal(0.012m, UsageMath.Cost(1000, 1000, p));
        Assert.Equal("none", UsageMath.PriceFor(Hosted(), "openai", "not-in-book").Source);
    }

    [Fact]
    public void Models_yaml_price_book_loads_and_is_marked_placeholder()
    {
        var book = TestEnv.Cfg.Gateway.PriceBook;
        Assert.NotEmpty(book);
        Assert.All(book, e => Assert.True(e.Placeholder, $"{e.Model} must be marked placeholder (no invented real prices)"));
        Assert.Contains(book, e => e.Provider == "openai" && e.CostPer1kIn > 0 && e.CostPer1kOut > 0);
        Assert.Contains(book, e => e.Provider == "azureopenai");
        Assert.All(TestEnv.Cfg.Gateway.Tiers.Values.SelectMany(t => t), d => Assert.Equal(0m, d.CostPer1kIn + d.CostPer1kOut));   // local tiers are $0
        Assert.True(TestEnv.Cfg.Policies.UsageBudgets.MonthlyTokens > 0);
    }

    [Theory]
    [InlineData("ok", 1, false, "ok")]
    [InlineData("ok", 2, false, "schema_retry")]
    [InlineData("ok", 1, true, "fallback")]
    [InlineData("ok", 3, true, "schema_retry")]
    [InlineData("SchemaInvalidException", 3, false, "error")]
    [InlineData("TimeoutException", 1, false, "timeout")]
    [InlineData("TaskCanceledException", 1, false, "timeout")]
    [InlineData("cancelled_kill_switch", 1, false, "error")]
    public void Outcome_mapping(string raw, int attempts, bool fallback, string expected) => Assert.Equal(expected, UsageMath.Outcome(raw, attempts, fallback));
}

public class UsageDateTests
{
    [Fact]
    public void Ist_day_window_starts_at_1830_utc_the_previous_day()
    {
        var (from, to) = UsageMath.IstWindow(new DateOnly(2026, 10, 2), new DateOnly(2026, 10, 2));
        Assert.Equal(new DateTime(2026, 10, 1, 18, 30, 0, DateTimeKind.Utc), from);
        Assert.Equal(new DateTime(2026, 10, 2, 18, 30, 0, DateTimeKind.Utc), to);
        Assert.Equal(DateTimeKind.Utc, from.Kind);
    }

    [Fact]
    public void Ist_day_of_utc_timestamps_around_midnight_ist()
    {
        Assert.Equal(new DateOnly(2026, 10, 1), UsageMath.IstDay(new DateTime(2026, 10, 1, 18, 29, 59, DateTimeKind.Utc)));
        Assert.Equal(new DateOnly(2026, 10, 2), UsageMath.IstDay(new DateTime(2026, 10, 1, 18, 30, 0, DateTimeKind.Utc)));
        Assert.Equal("2026-10-02 00:00:00 IST", UsageMath.IstText(new DateTime(2026, 10, 1, 18, 30, 0, DateTimeKind.Utc)));
    }

    [Fact]
    public void Presets_are_inclusive_of_today_in_ist()
    {
        var now = new DateTime(2026, 10, 1, 19, 0, 0, DateTimeKind.Utc);    // 00:30 IST on 2 Oct
        Assert.Equal((new DateOnly(2026, 10, 2), new DateOnly(2026, 10, 2)), UsageMath.Preset("today", now));
        Assert.Equal((new DateOnly(2026, 9, 26), new DateOnly(2026, 10, 2)), UsageMath.Preset("7d", now));
        Assert.Equal((new DateOnly(2026, 9, 3), new DateOnly(2026, 10, 2)), UsageMath.Preset("30d", now));
        Assert.Equal(30, new UsageFilter { From = new DateOnly(2026, 9, 3), To = new DateOnly(2026, 10, 2) }.Days);
    }
}

public class UsageAggregationTests
{
    static ModelUsage R(string model, string agent, int tin, int tout, decimal cost = 0, string outcome = "ok", int attempts = 1, bool cache = false, bool syn = false,
        string provider = "ollama", DateTime? ts = null, Guid? run = null, int latency = 1000) => new()
    {
        ModelId = model, AgentId = agent, TaskPurpose = "triage", InputTokens = tin, OutputTokens = tout, Cost = cost, Outcome = outcome, SchemaAttempts = attempts,
        CacheHit = cache, Synthetic = syn, Provider = provider, TsUtc = ts ?? new DateTime(2026, 10, 2, 6, 0, 0, DateTimeKind.Utc), RunId = run ?? Guid.Empty, LatencyMs = latency,
        PriceSource = provider == "ollama" ? "local" : "placeholder",
    };

    [Fact]
    public void Totals_count_calls_without_cache_hits_and_compute_rates()
    {
        var rows = new List<ModelUsage>
        {
            R("a", "triage-agent", 1000, 100, latency: 1000), R("a", "triage-agent", 1000, 100, attempts: 2, latency: 3000),
            R("b", "library", 2000, 500, cost: 0.5m, provider: "openai", outcome: "error", latency: 5000),
            R("a", "triage-agent", 0, 0, cache: true, latency: 0),
        };
        var t = UsageAggregator.Totals(rows);
        Assert.Equal(3, t.Calls); Assert.Equal(1, t.CacheHits);
        Assert.Equal(4000, t.InputTokens); Assert.Equal(700, t.OutputTokens); Assert.Equal(4700, t.TotalTokens);
        Assert.Equal(0.5m, t.Cost);
        Assert.Equal(3000, t.AvgLatencyMs);                 // cache hit excluded from latency
        Assert.Equal(Math.Round(1 / 3.0, 4), t.ErrorRate); Assert.Equal(Math.Round(1 / 3.0, 4), t.RetryRate);
        Assert.False(t.AllLocal); Assert.True(t.HasPlaceholderPrices);
    }

    [Fact]
    public void Group_by_model_and_agent_with_percent_of_total()
    {
        var rows = new List<ModelUsage> { R("a", "triage-agent", 300, 100), R("a", "verifier", 300, 100), R("b", "library", 1500, 500, cost: 1m, provider: "openai") };
        var byModel = UsageAggregator.Group(rows, "model");
        Assert.Equal(["b", "a"], byModel.Select(g => g.Key));
        Assert.Equal(71.4, byModel[0].PctTokens); Assert.Equal(28.6, byModel[1].PctTokens);
        Assert.Equal(100, byModel[0].PctCost);
        Assert.True(byModel[1].Local); Assert.False(byModel[0].Local);
        Assert.Equal(3, UsageAggregator.Group(rows, "agent").Count);
        Assert.Throws<ArgumentException>(() => UsageAggregator.Group(rows, "colour"));
    }

    [Fact]
    public void Group_by_day_uses_ist_days_and_zero_fills_the_range()
    {
        var rows = new List<ModelUsage>
        {
            R("a", "t", 100, 10, ts: new DateTime(2026, 9, 30, 18, 29, 0, DateTimeKind.Utc)),   // 30 Sep 23:59 IST
            R("a", "t", 200, 20, ts: new DateTime(2026, 9, 30, 18, 31, 0, DateTimeKind.Utc)),   // 1 Oct 00:01 IST
        };
        var days = UsageAggregator.Group(rows, "day", new DateOnly(2026, 9, 29), new DateOnly(2026, 10, 2));
        Assert.Equal(["2026-09-29", "2026-09-30", "2026-10-01", "2026-10-02"], days.Select(d => d.Key));
        Assert.Equal([0L, 110L, 220L, 0L], days.Select(d => d.TotalTokens));
    }

    [Fact]
    public void Budget_burn_against_policy_caps()
    {
        var run = Guid.NewGuid();
        var rows = new List<ModelUsage> { R("a", "t", 25_000, 5_000, run: run) };
        var pol = new PolicyConfig { Budgets = new() { ["pr"] = new BudgetConfig { Tokens = 60_000 } }, UsageBudgets = new() { DailyTokens = 100_000, MonthlyTokens = 1_000_000, MonthlyCost = 10 } };
        var f = new UsageFilter { From = new DateOnly(2026, 10, 1), To = new DateOnly(2026, 10, 2) };
        var json = System.Text.Json.JsonSerializer.Serialize(UsageAggregator.Budget(rows, rows, f, pol, new DateTime(2026, 10, 2, 6, 0, 0, DateTimeKind.Utc)), Schema.Json);
        var b = System.Text.Json.JsonDocument.Parse(json).RootElement;
        Assert.Equal(200_000, b.GetProperty("window").GetProperty("budget_tokens").GetInt64());
        Assert.Equal(15.0, b.GetProperty("window").GetProperty("pct").GetDouble());
        Assert.Equal(3.0, b.GetProperty("month").GetProperty("pct_tokens").GetDouble());
        Assert.Equal(465_000, b.GetProperty("month").GetProperty("projected_tokens").GetInt64());   // 30k / 2 days × 31
        Assert.Equal(50.0, b.GetProperty("runs").GetProperty("max_pct").GetDouble());
    }
}

public class SyntheticUsageTests
{
    [Fact]
    public void Seed_is_flagged_synthetic_deterministic_and_uses_config_placeholders()
    {
        var now = new DateTime(2026, 10, 2, 12, 0, 0, DateTimeKind.Utc);
        var a = SyntheticUsage.Generate(TestEnv.Cfg.Gateway, 30, 7, now);
        var b = SyntheticUsage.Generate(TestEnv.Cfg.Gateway, 30, 7, now);
        Assert.True(a.Count > 300);
        Assert.Equal(a.Select(r => (r.RunId, r.TsUtc, r.TotalTokens)), b.Select(r => (r.RunId, r.TsUtc, r.TotalTokens)));
        Assert.All(a, r => Assert.True(r.Synthetic));
        Assert.All(a, r => Assert.True(r.TsUtc <= now && UsageMath.IstDay(r.TsUtc) >= new DateOnly(2026, 9, 3)));
        Assert.All(a.Where(r => r.Provider == "ollama"), r => Assert.Equal(0m, r.Cost));
        Assert.All(a.Where(r => r.Provider != "ollama" && !r.CacheHit), r => Assert.Equal("placeholder", r.PriceSource));
        var bookModels = TestEnv.Cfg.Gateway.PriceBook.Select(p => p.Model).ToHashSet();
        Assert.Contains(a, r => r.Provider == "openai" && bookModels.Contains(r.ModelId));
        Assert.Contains(a, r => r.Provider == "azureopenai" && bookModels.Contains(r.ModelId));
        Assert.All(a, r => Assert.StartsWith("synthetic-org/", r.Repo));
        Assert.All(a.GroupBy(r => r.RunId), g => Assert.True(g.Sum(r => r.TotalTokens) <= 60000 * 1.0 + 20000));   // stays near the run cap
    }
}

/// <summary>Integration: real SQL Server. Rows use a private run id in Jan 2020 and are deleted afterwards.</summary>
public class UsageStoreTests
{
    [Fact]
    public void Store_filters_by_ist_day_boundaries_synthetic_flag_and_pages()
    {
        var s = TestEnv.Store();
        s.EnsureSchema(Path.Combine(TestEnv.RepoRoot, "db", "schema.sql"));
        s.EnsureMigrations(Path.Combine(TestEnv.RepoRoot, "db", "migrations"));
        var run = Guid.NewGuid();
        ModelUsage Row(DateTime ts, bool syn) => new() { RunId = run, TsUtc = ts, AgentId = "triage-agent", TaskPurpose = "triage", Tier = "small", ModelId = "test-model",
            ModelVersion = "t", Deployment = "t", Provider = "ollama", InputTokens = 10, OutputTokens = 5, Synthetic = syn, Repo = "test/repo", Mode = "pr" };
        try
        {
            s.InsertUsageBatch([
                Row(new DateTime(2019, 12, 31, 18, 29, 59, DateTimeKind.Utc), false),   // 31 Dec 2019 23:59:59 IST
                Row(new DateTime(2019, 12, 31, 18, 30, 0, DateTimeKind.Utc), false),    // 1 Jan 2020 00:00:00 IST
                Row(new DateTime(2020, 1, 1, 18, 29, 59, DateTimeKind.Utc), true),      // 1 Jan 2020 23:59:59 IST (synthetic)
                Row(new DateTime(2020, 1, 1, 18, 30, 0, DateTimeKind.Utc), false),      // 2 Jan 2020 00:00:00 IST
            ]);
            var day = new UsageFilter { From = new DateOnly(2020, 1, 1), To = new DateOnly(2020, 1, 1), Run = run };
            var rows = s.QueryUsage(day);
            Assert.Equal(2, rows.Count);
            Assert.All(rows, r => Assert.Equal(new DateOnly(2020, 1, 1), UsageMath.IstDay(r.TsUtc)));
            Assert.All(rows, r => Assert.Equal(DateTimeKind.Utc, r.TsUtc.Kind));
            Assert.Equal(15, rows[0].TotalTokens);
            Assert.Single(s.QueryUsage(new UsageFilter { From = day.From, To = day.To, Run = run, Synthetic = "exclude" }));
            Assert.Single(s.QueryUsage(new UsageFilter { From = day.From, To = day.To, Run = run, Synthetic = "only" }));
            var (total, page2) = s.QueryUsagePage(new UsageFilter { From = new DateOnly(2019, 12, 31), To = new DateOnly(2020, 1, 2), Run = run }, 2, 3);
            Assert.Equal(4, total); Assert.Single(page2);
            Assert.Equal(new DateTime(2019, 12, 31, 18, 29, 59, DateTimeKind.Utc), page2[0].TsUtc);    // newest first → oldest on page 2
            Assert.Empty(s.QueryUsage(new UsageFilter { From = day.From, To = day.To, Run = run, Model = "other" }));
            // migrations are idempotent: re-applying does not duplicate backfilled rows
            var before = s.QueryUsage(new UsageFilter { From = new DateOnly(2026, 1, 1), To = new DateOnly(2026, 12, 31), Synthetic = "exclude" }).Count;
            s.EnsureMigrations(Path.Combine(TestEnv.RepoRoot, "db", "migrations"));
            Assert.Equal(before, s.QueryUsage(new UsageFilter { From = new DateOnly(2026, 1, 1), To = new DateOnly(2026, 12, 31), Synthetic = "exclude" }).Count);
        }
        finally { s.DeleteUsageForRuns([run]); }
    }
}
