namespace SecAgent.Core;

/// <summary>SYNTHETIC demo data for the Usage tab (scripts/seed-usage.sh). Every row is flagged synthetic = 1, uses made-up repos
/// ("synthetic-org/..."), random run ids that have no Run row, and the placeholder hosted model names/prices from config.
/// Never called by a real run, and nothing seeds by default.</summary>
public static class SyntheticUsage
{
    public sealed record ModelChoice(string Provider, string Tier, string Model, string Version, string Deployment, bool Fallback = false);

    static readonly string[] Repos = ["synthetic-org/orders-api", "synthetic-org/payments-svc", "synthetic-org/identity-web", "synthetic-org/reporting-batch"];
    static readonly string[] Fixers = ["library", "secrets", "unsafe_code", "binary_licence"];

    /// <summary>Profiles per provider (small, strong, optional fallback) taken from config: Ollama from the tiers, hosted from the price book.</summary>
    public static Dictionary<string, (ModelChoice Small, ModelChoice Strong, ModelChoice? Fallback)> Profiles(GatewayConfig g)
    {
        var d = new Dictionary<string, (ModelChoice, ModelChoice, ModelChoice?)>();
        if (UsageMath.ProviderOf(g) == "ollama" && g.Tiers.TryGetValue("small", out var sm) && g.Tiers.TryGetValue("strong", out var st))
        {
            var s0 = sm.First(x => !x.Fallback); var t0 = st.First(x => !x.Fallback); var fb = st.FirstOrDefault(x => x.Fallback) ?? sm.FirstOrDefault(x => x.Fallback);
            d["ollama"] = (new("ollama", "small", s0.Model, s0.Version, s0.Id), new("ollama", "strong", t0.Model, t0.Version, t0.Id),
                           fb == null ? null : new("ollama", st.Contains(fb) ? "strong" : "small", fb.Model, fb.Version, fb.Id, true));
        }
        else d["ollama"] = (new("ollama", "small", "qwen2.5:3b", "local", "small-a"), new("ollama", "strong", "qwen2.5-coder:7b", "local", "strong-a"),
                            new("ollama", "strong", "qwen2.5-coder:3b", "local", "strong-b", true));
        foreach (var grp in g.PriceBook.GroupBy(p => p.Provider))
        {
            var small = grp.FirstOrDefault(p => p.Tier == "small"); var strong = grp.FirstOrDefault(p => p.Tier == "strong");
            if (small == null || strong == null) continue;
            d[grp.Key] = (new(grp.Key, "small", small.Model, grp.Key, "small-a"), new(grp.Key, "strong", strong.Model, grp.Key, "strong-a"),
                          new(grp.Key, "strong", small.Model, grp.Key, "strong-b", true));
        }
        return d;
    }

    public static List<ModelUsage> Generate(GatewayConfig g, int days = 30, int seed = 42, DateTime? nowUtc = null, int runTokenCap = 60000)
    {
        var rnd = new Random(seed);
        var now = nowUtc ?? DateTime.UtcNow;
        var today = UsageMath.TodayIst(now);
        var profiles = Profiles(g);
        var rows = new List<ModelUsage>();
        double N(double mean, double sd) { var u = 1 - rnd.NextDouble(); var v = rnd.NextDouble(); return mean + sd * Math.Sqrt(-2 * Math.Log(u)) * Math.Cos(2 * Math.PI * v); }
        int Tok(double mean, double sd, int min) => Math.Max(min, (int)N(mean, sd));
        Guid NewId() { var b = new byte[16]; rnd.NextBytes(b); b[7] = (byte)((b[7] & 0x0F) | 0x40); return new Guid(b); }

        for (var day = today.AddDays(-(days - 1)); day <= today; day = day.AddDays(1))
        {
            var age = today.DayNumber - day.DayNumber;
            var weekend = day.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday;
            var runsToday = weekend ? rnd.Next(0, 3) : rnd.Next(3, 8);
            for (var k = 0; k < runsToday; k++)
            {
                // Story for the demo: Ollama only at first; from ~2 weeks ago some runs move to the hosted placeholders (OpenAI, then Azure).
                var roll = rnd.NextDouble();
                var prov = age > 14 || roll < 0.45 ? "ollama" : roll < 0.75 && profiles.ContainsKey("openai") ? "openai" : profiles.ContainsKey("azureopenai") ? "azureopenai" : "ollama";
                var (small, strong, fallback) = profiles[prov];
                var local = prov == "ollama";
                var mode = rnd.NextDouble() < 0.15 ? "backlog" : "pr";
                var rerun = mode == "pr" && rnd.NextDouble() < 0.12;     // idempotent re-run: triage decisions reused (cache hits), no fixes
                var runId = NewId();
                var repo = Repos[rnd.Next(Repos.Length)];
                int? pr = mode == "pr" ? rnd.Next(12, 420) : null;
                var istStart = day.ToDateTime(new TimeOnly(9, 30)).AddMinutes(rnd.Next(0, 10 * 60 + 30));
                var t = DateTime.SpecifyKind(istStart - UsageMath.IstOffset, DateTimeKind.Utc);
                if (t > now) continue;

                long runTokens = 0;
                void Call(string agent, string task, ModelChoice m, double inMean, double outMean, double latMean)
                {
                    if (runTokens > runTokenCap * 0.9) return;     // a real run stops at its token budget; keep the demo plausible
                    var choice = m;
                    var fb = fallback != null && rnd.NextDouble() < (local ? 0.04 : 0.015);
                    if (fb) choice = fallback!;
                    var attempts = rnd.NextDouble() < (local ? 0.07 : 0.03) ? 2 : 1;
                    var fail = rnd.NextDouble();
                    var raw = fail < (local ? 0.012 : 0.006) ? "TimeoutException" : fail < (local ? 0.03 : 0.015) ? "SchemaInvalidException" : "ok";
                    if (raw == "SchemaInvalidException") attempts = 3;
                    var outMul = local ? 1.0 : 2.2;                       // hosted reasoning-family models emit more output tokens
                    var tin = Tok(inMean, inMean * 0.25, 200) * attempts;
                    var tout = raw == "TimeoutException" ? 0 : Tok(outMean * outMul, outMean * outMul * 0.35, 20) * attempts;
                    var lat = raw == "TimeoutException" ? (local ? 600_000 : 180_000) : Math.Max(300, (int)(N(latMean, latMean * 0.3) * attempts * (choice.Tier == "strong" && local ? 1.8 : 1)));
                    var price = UsageMath.PriceFor(g, choice.Provider, choice.Model);
                    runTokens += tin + tout;
                    rows.Add(new ModelUsage
                    {
                        RunId = runId, TsUtc = t, Repo = repo, PrNumber = pr, Mode = mode, AgentId = agent, TaskPurpose = task, Tier = choice.Tier,
                        ModelId = choice.Model, ModelVersion = choice.Version, Deployment = choice.Deployment, Provider = choice.Provider,
                        InputTokens = tin, OutputTokens = tout, LatencyMs = lat, Cost = UsageMath.Cost(tin, tout, price), PriceSource = price.Source,
                        Outcome = UsageMath.Outcome(raw, attempts, fb), OutcomeDetail = raw == "ok" ? null : raw, SchemaAttempts = attempts, FallbackUsed = fb,
                        Synthetic = true,
                    });
                    t = t.AddMilliseconds(lat + rnd.Next(500, 8000));
                }

                var findings = mode == "backlog" ? rnd.Next(10, 26) : rnd.Next(3, 9);
                for (var i = 0; i < findings; i++)
                {
                    if (rerun)
                    {
                        rows.Add(new ModelUsage
                        {
                            RunId = runId, TsUtc = t, Repo = repo, PrNumber = pr, Mode = mode, AgentId = "triage-agent", TaskPurpose = "triage", Tier = small.Tier,
                            ModelId = small.Model, ModelVersion = small.Version, Deployment = "cache", Provider = small.Provider, PriceSource = local ? "local" : "none",
                            Outcome = "ok", OutcomeDetail = "decision_reused", CacheHit = true, Synthetic = true,
                        });
                        t = t.AddMilliseconds(rnd.Next(50, 400));
                        continue;
                    }
                    var high = rnd.NextDouble() < 0.2;    // high severity escalates triage one tier
                    Call("triage-agent", "triage", high ? strong : small, 1500, 170, local ? 32_000 : 2_600);
                }
                if (rerun) continue;
                var fixes = mode == "backlog" ? rnd.Next(2, 7) : rnd.Next(1, 5);
                for (var i = 0; i < fixes; i++)
                {
                    var fixer = Fixers[rnd.Next(Fixers.Length)];
                    var tries = rnd.NextDouble() < 0.15 ? 2 : 1;
                    for (var a = 0; a < tries; a++)
                    {
                        Call(fixer, "fix", strong, fixer == "unsafe_code" ? 3600 : 2400, fixer == "unsafe_code" ? 900 : 450, local ? 95_000 : 7_500);
                        Call("verifier", rnd.NextDouble() < 0.25 ? "verify" : "summarise", a > 0 ? strong : small, 1200, 140, local ? 24_000 : 2_000);
                    }
                }
            }
        }
        return rows.Where(r => r.TsUtc <= now).ToList();
    }
}
