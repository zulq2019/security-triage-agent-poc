using System.Text.Json;

namespace SecAgent.Core;

/// <summary>Model provider switch (pure config). Precedence: appsettings.json → appsettings.Local.json (git-ignored) → environment variables.
/// The API key is only ever read from the environment variable named in ApiKeyEnv; it is never stored in a file in the repo.</summary>
public sealed class ModelProviderSettings
{
    public string Provider { get; set; } = "ollama";           // ollama | openai | azureopenai
    public string LocalProfile { get; set; } = "default";      // ollama only: default (3b + 7b) | 3b-only (fits 8-16 GB RAM)
    public Dictionary<string, ProviderSection> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string Source { get; set; } = "built-in defaults";

    public ProviderSection Active => Providers.TryGetValue(Provider, out var p) ? p
        : throw new InvalidOperationException($"Unknown model provider '{Provider}' (expected ollama | openai | azureopenai)");

    static readonly JsonSerializerOptions Opts = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    public static readonly string[] Known = ["ollama", "openai", "azureopenai"];

    /// <summary>Env vars: SECAGENT_MODEL_PROVIDER, SECAGENT_LOCAL_PROFILE, SECAGENT_MODEL_BASE_URL, SECAGENT_SMALL_MODEL, SECAGENT_STRONG_MODEL.</summary>
    public static ModelProviderSettings Load(string repoRoot)
    {
        var s = new ModelProviderSettings();
        var sources = new List<string>();
        foreach (var name in new[] { "appsettings.json", "appsettings.Local.json" })
        {
            var file = Path.Combine(repoRoot, "src", "SecAgent.Dashboard", name);
            if (!File.Exists(file)) continue;
            using var doc = JsonDocument.Parse(File.ReadAllText(file), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!doc.RootElement.TryGetProperty("ModelProvider", out var mp)) continue;
            sources.Add(name);
            if (mp.TryGetProperty("Provider", out var v)) s.Provider = v.GetString()!;
            if (mp.TryGetProperty("LocalProfile", out v)) s.LocalProfile = v.GetString()!;
            if (mp.TryGetProperty("Providers", out var ps))
                foreach (var p in ps.EnumerateObject())
                {
                    var sec = s.Providers.TryGetValue(p.Name, out var existing) ? existing : new ProviderSection();
                    var overlay = p.Value.Deserialize<ProviderSection>(Opts) ?? new();
                    sec.Overlay(overlay);
                    s.Providers[p.Name] = sec;
                }
        }
        string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } x ? x : null;
        if (Env("SECAGENT_MODEL_PROVIDER") is { } prov) { s.Provider = prov; sources.Add("SECAGENT_MODEL_PROVIDER"); }
        if (Env("SECAGENT_LOCAL_PROFILE") is { } lp) { s.LocalProfile = lp; sources.Add("SECAGENT_LOCAL_PROFILE"); }
        s.Provider = s.Provider.Trim().ToLowerInvariant();
        if (!Known.Contains(s.Provider)) throw new InvalidOperationException($"Unknown model provider '{s.Provider}' (expected ollama | openai | azureopenai)");
        if (!s.Providers.ContainsKey(s.Provider)) s.Providers[s.Provider] = new ProviderSection();
        var a = s.Active;
        if (Env("SECAGENT_MODEL_BASE_URL") is { } url) { a.BaseUrl = url; sources.Add("SECAGENT_MODEL_BASE_URL"); }
        if (Env("SECAGENT_SMALL_MODEL") is { } sm) { a.SmallModel = sm; sources.Add("SECAGENT_SMALL_MODEL"); }
        if (Env("SECAGENT_STRONG_MODEL") is { } st) { a.StrongModel = st; sources.Add("SECAGENT_STRONG_MODEL"); }
        s.Source = sources.Count > 0 ? string.Join(" + ", sources) : "built-in defaults";
        return s;
    }

    /// <summary>Overlays the active provider onto the routing policy from gateway/models.yaml (tiers, quality rules and budgets stay as they are).</summary>
    public void ApplyTo(GatewayConfig g)
    {
        var a = Active;
        if (Provider == "ollama")
        {
            // models.yaml already describes the default local profile; only override what is set.
            if (a.BaseUrl is { Length: > 0 }) { g.Endpoint = a.BaseUrl; g.HealthUrl = a.BaseUrl.TrimEnd('/').Replace("/v1", "") + "/api/tags"; }
            if (LocalProfile.Equals("3b-only", StringComparison.OrdinalIgnoreCase))
            {
                // One small coder model for everything: about 3 GB resident, fits a 16 GB laptop next to SQL Server and the scanners.
                var m = a.SmallModel is { Length: > 0 } ? a.SmallModel : "qwen2.5-coder:3b";
                var alt = a.FallbackModel is { Length: > 0 } ? a.FallbackModel : "qwen2.5:3b";
                g.Tiers["small"] = [new() { Id = "small-a", Model = m, Version = "local", ContextWindow = 8192 }, new() { Id = "small-b", Model = alt, Version = "local", ContextWindow = 8192, Fallback = true }];
                g.Tiers["strong"] = [new() { Id = "strong-a", Model = m, Version = "local", ContextWindow = 8192, Note = "3b-only profile: strong tier = same 3B model" }, new() { Id = "strong-b", Model = alt, Version = "local", ContextWindow = 8192, Fallback = true }];
                g.Label += "+3b-only";
            }
            else
            {
                if (a.SmallModel is { Length: > 0 }) g.Tiers["small"][0].Model = a.SmallModel;
                if (a.StrongModel is { Length: > 0 }) g.Tiers["strong"][0].Model = a.StrongModel;
            }
            return;
        }
        // Hosted providers: OpenAI or Azure OpenAI (v1 API, OpenAI-compatible). No local health endpoint; failures trip the circuit breaker instead.
        if (string.IsNullOrWhiteSpace(a.BaseUrl)) throw new InvalidOperationException($"ModelProvider:Providers:{Provider}:BaseUrl is not set");
        if (string.IsNullOrWhiteSpace(a.SmallModel) || string.IsNullOrWhiteSpace(a.StrongModel)) throw new InvalidOperationException($"Set SmallModel and StrongModel for provider '{Provider}' (appsettings.json or SECAGENT_SMALL_MODEL / SECAGENT_STRONG_MODEL)");
        g.Provider = Provider;
        g.Endpoint = a.BaseUrl;
        g.ApiKeyEnv = a.ApiKeyEnv is { Length: > 0 } ? a.ApiKeyEnv : Provider == "openai" ? "OPENAI_API_KEY" : "AZURE_OPENAI_API_KEY";
        g.HealthUrl = "";
        g.MaxConcurrentCalls = a.MaxConcurrentCalls ?? 4;
        g.RequestTimeoutSeconds = a.RequestTimeoutSeconds ?? 180;
        g.OutputReserveTokens = a.OutputReserveTokens ?? 4096;
        g.SendTemperature = a.SendTemperature ?? false;
        g.SendSeed = a.SendSeed ?? false;
        var ctx = a.ContextWindow ?? 128000;
        g.Tiers["small"] = [new() { Id = "small-a", Model = a.SmallModel!, Version = Provider, ContextWindow = ctx, CostPer1kIn = a.SmallCostPer1kIn ?? 0, CostPer1kOut = a.SmallCostPer1kOut ?? 0 }];
        g.Tiers["strong"] = [new() { Id = "strong-a", Model = a.StrongModel!, Version = Provider, ContextWindow = ctx, CostPer1kIn = a.StrongCostPer1kIn ?? 0, CostPer1kOut = a.StrongCostPer1kOut ?? 0 },
                             new() { Id = "strong-b", Model = a.SmallModel!, Version = Provider, ContextWindow = ctx, CostPer1kIn = a.SmallCostPer1kIn ?? 0, CostPer1kOut = a.SmallCostPer1kOut ?? 0, Fallback = true, Note = "fallback: small model" }];
        g.Label += "+" + Provider;
    }

    public string Describe() =>
        Provider == "ollama" ? $"ollama ({LocalProfile} profile)" : $"{Provider} small={Active.SmallModel} strong={Active.StrongModel} key from ${(Active.ApiKeyEnv is { Length: > 0 } k ? k : Provider == "openai" ? "OPENAI_API_KEY" : "AZURE_OPENAI_API_KEY")}";
}

public sealed class ProviderSection
{
    public string? BaseUrl { get; set; }
    public string? ApiKeyEnv { get; set; }
    public string? SmallModel { get; set; }
    public string? StrongModel { get; set; }
    public string? FallbackModel { get; set; }
    public int? ContextWindow { get; set; }
    public int? OutputReserveTokens { get; set; }
    public int? MaxConcurrentCalls { get; set; }
    public int? RequestTimeoutSeconds { get; set; }
    public bool? SendTemperature { get; set; }
    public bool? SendSeed { get; set; }
    public decimal? SmallCostPer1kIn { get; set; }
    public decimal? SmallCostPer1kOut { get; set; }
    public decimal? StrongCostPer1kIn { get; set; }
    public decimal? StrongCostPer1kOut { get; set; }

    public void Overlay(ProviderSection o)
    {
        foreach (var p in typeof(ProviderSection).GetProperties())
            if (p.GetValue(o) is { } v) p.SetValue(this, v);
    }
}
