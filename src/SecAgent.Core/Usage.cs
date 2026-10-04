namespace SecAgent.Core;

/// <summary>One row per model call (table ModelUsage, db/migrations/002_model_usage.sql). Timestamps are UTC; IST is a view concern.</summary>
public sealed class ModelUsage
{
    public Guid UsageId { get; set; } = Guid.NewGuid();
    public Guid? RoutingId { get; set; }
    public Guid? ContextPackId { get; set; }
    public Guid RunId { get; set; }
    public DateTime TsUtc { get; set; } = DateTime.UtcNow;
    public string TsIst => UsageMath.IstText(TsUtc);         // display only (not a column)
    public string? Repo { get; set; }
    public int? PrNumber { get; set; }
    public string Mode { get; set; } = "pr";                // pr | backlog
    public string AgentId { get; set; } = "";               // triage-agent | library | secrets | unsafe_code | binary_licence | verifier
    public string TaskPurpose { get; set; } = "";           // triage | fix | verify | summarise
    public string Tier { get; set; } = "";
    public string ModelId { get; set; } = "";
    public string ModelVersion { get; set; } = "";
    public string Deployment { get; set; } = "";
    public string Provider { get; set; } = "ollama";        // ollama | openai | azureopenai
    public int InputTokens { get; set; }
    public int OutputTokens { get; set; }
    public int TotalTokens { get => InputTokens + OutputTokens; set { } }   // persisted computed column in SQL
    public int LatencyMs { get; set; }
    public decimal Cost { get; set; }
    public string PriceSource { get; set; } = "local";      // local | config | placeholder | none
    public string Outcome { get; set; } = "ok";             // ok | schema_retry | fallback | error | timeout
    public string? OutcomeDetail { get; set; }
    public int SchemaAttempts { get; set; }
    public bool FallbackUsed { get; set; }
    public bool CacheHit { get; set; }
    public bool Synthetic { get; set; }
    public string? TraceId { get; set; }
}

public sealed record Price(decimal In, decimal Out, string Source);

/// <summary>Pure usage helpers: provider naming, pricing, cost, outcome mapping and IST (UTC+5:30, no DST) day windows.</summary>
public static class UsageMath
{
    public static readonly TimeSpan IstOffset = TimeSpan.FromMinutes(330);
    public static readonly string[] Outcomes = ["ok", "schema_retry", "fallback", "error", "timeout"];

    public static string ProviderOf(GatewayConfig g) => g.Provider is "openai" or "azureopenai" ? g.Provider : "ollama";

    /// <summary>Local models are $0. Hosted: the deployment's own price (appsettings) if set, else the models.yaml price book (placeholders), else none.</summary>
    public static Price PriceFor(GatewayConfig g, string provider, string model, DeploymentConfig? d = null)
    {
        if (provider == "ollama") return new(0, 0, "local");
        if (d != null && (d.CostPer1kIn > 0 || d.CostPer1kOut > 0)) return new(d.CostPer1kIn, d.CostPer1kOut, "config");
        var e = g.PriceBook.FirstOrDefault(p => p.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase) && p.Model == model);
        if (e != null) return new(e.CostPer1kIn, e.CostPer1kOut, e.Placeholder ? "placeholder" : "config");
        return new(0, 0, "none");
    }

    public static decimal Cost(int tokensIn, int tokensOut, Price p) => Math.Round(tokensIn / 1000m * p.In + tokensOut / 1000m * p.Out, 6);

    /// <summary>Maps the gateway's raw outcome (ok or an exception type name) to the usage outcome. Schema retry wins over fallback.</summary>
    public static string Outcome(string raw, int schemaAttempts, bool fallback) => raw switch
    {
        "ok" when schemaAttempts > 1 => "schema_retry",
        "ok" when fallback => "fallback",
        "ok" => "ok",
        _ when raw.Contains("Timeout", StringComparison.OrdinalIgnoreCase) || raw.Contains("TaskCanceled", StringComparison.OrdinalIgnoreCase) => "timeout",
        _ => "error",
    };

    public static DateTime ToIst(DateTime utc) => DateTime.SpecifyKind(utc, DateTimeKind.Unspecified) + IstOffset;
    public static DateOnly IstDay(DateTime utc) => DateOnly.FromDateTime(ToIst(utc));
    public static DateOnly TodayIst(DateTime? nowUtc = null) => IstDay(nowUtc ?? DateTime.UtcNow);
    public static string IstText(DateTime utc) => ToIst(utc).ToString("yyyy-MM-dd HH:mm:ss") + " IST";

    /// <summary>Inclusive IST calendar dates → [fromUtc, toUtcExclusive). 2026-10-02 IST starts at 2026-10-01T18:30Z.</summary>
    public static (DateTime FromUtc, DateTime ToUtcExclusive) IstWindow(DateOnly from, DateOnly to)
    {
        if (to < from) (from, to) = (to, from);
        var f = DateTime.SpecifyKind(from.ToDateTime(TimeOnly.MinValue) - IstOffset, DateTimeKind.Utc);
        var t = DateTime.SpecifyKind(to.AddDays(1).ToDateTime(TimeOnly.MinValue) - IstOffset, DateTimeKind.Utc);
        return (f, t);
    }

    /// <summary>Range presets used by the dashboard: today | 7d | 30d (inclusive of today, IST).</summary>
    public static (DateOnly From, DateOnly To) Preset(string preset, DateTime? nowUtc = null)
    {
        var today = TodayIst(nowUtc);
        return preset switch { "today" => (today, today), "7d" => (today.AddDays(-6), today), "30d" => (today.AddDays(-29), today), _ => (today.AddDays(-6), today) };
    }
}

/// <summary>Query filter for usage endpoints. Dates are IST calendar dates (inclusive).</summary>
public sealed class UsageFilter
{
    public DateOnly From { get; set; }
    public DateOnly To { get; set; }
    public string? Model { get; set; }
    public string? Agent { get; set; }
    public string? Provider { get; set; }
    public string? Task { get; set; }
    public Guid? Run { get; set; }
    public string Synthetic { get; set; } = "include";      // include | exclude | only
    public (DateTime FromUtc, DateTime ToUtcExclusive) Window => UsageMath.IstWindow(From, To);
    public int Days => To.DayNumber - From.DayNumber + 1;
}

public sealed class UsageTotals
{
    public int Calls { get; set; }
    public int CacheHits { get; set; }
    public long InputTokens { get; set; }
    public long OutputTokens { get; set; }
    public long TotalTokens { get; set; }
    public decimal Cost { get; set; }
    public double AvgLatencyMs { get; set; }
    public double P95LatencyMs { get; set; }
    public int Errors { get; set; }
    public int Timeouts { get; set; }
    public int Retries { get; set; }
    public int Fallbacks { get; set; }
    public double ErrorRate { get; set; }
    public double RetryRate { get; set; }
    public int Runs { get; set; }
    public int SyntheticRows { get; set; }
    public int RealRows { get; set; }
    public bool HasPlaceholderPrices { get; set; }
    public bool AllLocal { get; set; }
}

public sealed class UsageGroup
{
    public string Key { get; set; } = "";
    public string? Provider { get; set; }
    public string? Repo { get; set; }
    public int? PrNumber { get; set; }
    public string? Mode { get; set; }
    public int Calls { get; set; }
    public int CacheHits { get; set; }
    public long InputTokens { get; set; }
    public long OutputTokens { get; set; }
    public long TotalTokens { get; set; }
    public decimal Cost { get; set; }
    public double AvgLatencyMs { get; set; }
    public int Errors { get; set; }
    public int Retries { get; set; }
    public double PctTokens { get; set; }
    public double PctCost { get; set; }
    public double PctCalls { get; set; }
    public bool Local { get; set; }
    public bool Placeholder { get; set; }
    public int SyntheticRows { get; set; }
    public DateTime? FirstUtc { get; set; }
    public DateTime? LastUtc { get; set; }
}

/// <summary>Aggregation over filtered usage rows (pure, unit-tested). A "call" is a row without cache_hit; cache hits spend no tokens.</summary>
public static class UsageAggregator
{
    public static readonly string[] GroupKeys = ["model", "agent", "task", "run", "day", "provider"];

    public static UsageTotals Totals(IReadOnlyCollection<ModelUsage> rows)
    {
        var calls = rows.Where(r => !r.CacheHit).ToList();
        var lat = calls.Select(r => r.LatencyMs).OrderBy(x => x).ToList();
        var t = new UsageTotals
        {
            Calls = calls.Count, CacheHits = rows.Count - calls.Count,
            InputTokens = rows.Sum(r => (long)r.InputTokens), OutputTokens = rows.Sum(r => (long)r.OutputTokens),
            Cost = rows.Sum(r => r.Cost),
            AvgLatencyMs = lat.Count == 0 ? 0 : Math.Round(lat.Average(), 1),
            P95LatencyMs = lat.Count == 0 ? 0 : lat[Math.Min(lat.Count - 1, (int)Math.Ceiling(lat.Count * 0.95) - 1)],
            Errors = calls.Count(r => r.Outcome == "error"), Timeouts = calls.Count(r => r.Outcome == "timeout"),
            Retries = calls.Count(r => r.SchemaAttempts > 1), Fallbacks = calls.Count(r => r.FallbackUsed),
            Runs = rows.Select(r => r.RunId).Distinct().Count(),
            SyntheticRows = rows.Count(r => r.Synthetic), RealRows = rows.Count(r => !r.Synthetic),
            HasPlaceholderPrices = rows.Any(r => r.PriceSource == "placeholder"),
            AllLocal = rows.All(r => r.Provider == "ollama"),
        };
        t.TotalTokens = t.InputTokens + t.OutputTokens;
        t.ErrorRate = t.Calls == 0 ? 0 : Math.Round((double)(t.Errors + t.Timeouts) / t.Calls, 4);
        t.RetryRate = t.Calls == 0 ? 0 : Math.Round((double)t.Retries / t.Calls, 4);
        return t;
    }

    public static string KeyOf(ModelUsage r, string groupBy) => groupBy switch
    {
        "model" => r.ModelId, "agent" => r.AgentId, "task" => r.TaskPurpose, "run" => r.RunId.ToString(),
        "day" => UsageMath.IstDay(r.TsUtc).ToString("yyyy-MM-dd"), "provider" => r.Provider,
        _ => throw new ArgumentException($"groupBy must be one of {string.Join("|", GroupKeys)}"),
    };

    /// <summary>Groups rows; for groupBy=day every IST day in [from, to] is present (zero-filled) so charts have no gaps.</summary>
    public static List<UsageGroup> Group(IReadOnlyCollection<ModelUsage> rows, string groupBy, DateOnly? from = null, DateOnly? to = null)
    {
        var all = Totals(rows);
        var groups = rows.GroupBy(r => KeyOf(r, groupBy)).Select(g =>
        {
            var list = g.ToList(); var t = Totals(list); var first = list.MinBy(r => r.TsUtc)!;
            return new UsageGroup
            {
                Key = g.Key, Provider = list.Select(r => r.Provider).Distinct().Count() == 1 ? first.Provider : "mixed",
                Repo = groupBy == "run" ? first.Repo : null, PrNumber = groupBy == "run" ? first.PrNumber : null, Mode = groupBy == "run" ? first.Mode : null,
                Calls = t.Calls, CacheHits = t.CacheHits, InputTokens = t.InputTokens, OutputTokens = t.OutputTokens, TotalTokens = t.TotalTokens,
                Cost = t.Cost, AvgLatencyMs = t.AvgLatencyMs, Errors = t.Errors + t.Timeouts, Retries = t.Retries,
                PctTokens = all.TotalTokens == 0 ? 0 : Math.Round(100.0 * t.TotalTokens / all.TotalTokens, 1),
                PctCost = all.Cost == 0 ? 0 : Math.Round((double)(100m * t.Cost / all.Cost), 1),
                PctCalls = all.Calls == 0 ? 0 : Math.Round(100.0 * t.Calls / all.Calls, 1),
                Local = t.AllLocal, Placeholder = t.HasPlaceholderPrices, SyntheticRows = t.SyntheticRows,
                FirstUtc = DateTime.SpecifyKind(first.TsUtc, DateTimeKind.Utc), LastUtc = DateTime.SpecifyKind(list.Max(r => r.TsUtc), DateTimeKind.Utc),
            };
        }).ToList();
        if (groupBy == "day" && from is { } f && to is { } e)
        {
            var have = groups.Select(g => g.Key).ToHashSet();
            for (var d = f; d <= e; d = d.AddDays(1))
                if (have.Add(d.ToString("yyyy-MM-dd"))) groups.Add(new UsageGroup { Key = d.ToString("yyyy-MM-dd"), Local = true });
            return groups.OrderBy(g => g.Key, StringComparer.Ordinal).ToList();
        }
        return groupBy == "run" ? groups.OrderByDescending(g => g.LastUtc).ToList() : groups.OrderByDescending(g => g.TotalTokens).ThenByDescending(g => g.Calls).ToList();
    }

    /// <summary>Budget burn: per-run token cap (policies budgets[mode].tokens), the window vs daily budget, and IST month-to-date vs monthly budget.</summary>
    public static object Budget(IReadOnlyCollection<ModelUsage> windowRows, IReadOnlyCollection<ModelUsage> monthRows, UsageFilter f, PolicyConfig p, DateTime? nowUtc = null)
    {
        var today = UsageMath.TodayIst(nowUtc);
        var monthStart = new DateOnly(today.Year, today.Month, 1);
        var daysInMonth = DateTime.DaysInMonth(today.Year, today.Month);
        var elapsed = today.Day;
        var ub = p.UsageBudgets;
        var winTokens = windowRows.Sum(r => (long)r.TotalTokens);
        var winBudget = (long)ub.DailyTokens * f.Days;
        var mTokens = monthRows.Sum(r => (long)r.TotalTokens);
        var mCost = monthRows.Sum(r => r.Cost);
        var runs = Group(windowRows, "run").Select(g =>
        {
            var cap = p.Budgets.TryGetValue(g.Mode ?? "pr", out var b) ? b.Tokens : p.Budgets.Values.FirstOrDefault()?.Tokens ?? 0;
            return new { run_id = g.Key, g.Repo, pr_number = g.PrNumber, g.Mode, tokens = g.TotalTokens, cap_tokens = cap, cost = g.Cost,
                pct = cap == 0 ? 0 : Math.Round(100.0 * g.TotalTokens / cap, 1), synthetic = g.SyntheticRows > 0, last_utc = g.LastUtc };
        }).ToList();
        return new
        {
            window = new { from = f.From, to = f.To, days = f.Days, tokens = winTokens, budget_tokens = winBudget, pct = winBudget == 0 ? 0 : Math.Round(100.0 * winTokens / winBudget, 1),
                           daily_budget_tokens = ub.DailyTokens },
            month = new
            {
                label = monthStart.ToString("MMM yyyy"), from = monthStart, to = today, days_elapsed = elapsed, days_in_month = daysInMonth,
                tokens = mTokens, budget_tokens = ub.MonthlyTokens, pct_tokens = ub.MonthlyTokens == 0 ? 0 : Math.Round(100.0 * mTokens / ub.MonthlyTokens, 1),
                projected_tokens = (long)Math.Round((double)mTokens / elapsed * daysInMonth),
                cost = mCost, budget_cost = ub.MonthlyCost, pct_cost = ub.MonthlyCost == 0 ? 0 : Math.Round((double)(100m * mCost / ub.MonthlyCost), 1),
                projected_cost = Math.Round(mCost / elapsed * daysInMonth, 4),
            },
            runs = new
            {
                cap_tokens = p.Budgets.TryGetValue("pr", out var pr) ? pr.Tokens : 0, count = runs.Count,
                avg_pct = runs.Count == 0 ? 0 : Math.Round(runs.Average(r => r.pct), 1), max_pct = runs.Count == 0 ? 0 : runs.Max(r => r.pct),
                over_80 = runs.Count(r => r.pct >= 80), items = runs.Take(12),
            },
        };
    }
}
