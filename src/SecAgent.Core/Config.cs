using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecAgent.Core;

public sealed class PolicyConfig
{
    public string Label { get; set; } = "";
    public bool KillSwitch { get; set; }
    public Dictionary<string, BudgetConfig> Budgets { get; set; } = [];
    public ThresholdConfig Thresholds { get; set; } = new();
    public RetryConfig Retries { get; set; } = new();
    public AuthorityConfig Authority { get; set; } = new();
    public Dictionary<string, string> PrMode { get; set; } = [];
}
public sealed class BudgetConfig { public int Tokens { get; set; } public decimal Cost { get; set; } public int MaxFixes { get; set; } public int MaxMinutes { get; set; } }
public sealed class ThresholdConfig { public double ConfidenceMin { get; set; } = 0.6; public double LowBudgetFraction { get; set; } = 0.15; }
public sealed class RetryConfig { public int MaxFixRetries { get; set; } = 2; public int MaxSchemaRetries { get; set; } = 2; }
public sealed class AuthorityConfig { public List<string> AgentMaySuppress { get; set; } = []; public bool NeverLowerSecretSeverity { get; set; } = true; }

public sealed class GatewayConfig
{
    public string Label { get; set; } = "";
    public string Provider { get; set; } = "openai_compatible";
    public string Endpoint { get; set; } = "";
    public string ApiKeyEnv { get; set; } = "";
    public string HealthUrl { get; set; } = "";
    public int OutputReserveTokens { get; set; } = 1024;
    public int MaxConcurrentCalls { get; set; } = 1;
    public int RequestTimeoutSeconds { get; set; } = 600;
    public bool SendTemperature { get; set; } = true;   // reasoning-family hosted models reject temperature
    public bool SendSeed { get; set; } = true;
    public Dictionary<string, List<DeploymentConfig>> Tiers { get; set; } = [];
    public List<string> TierOrder { get; set; } = [];
    public Dictionary<string, string> TaskTiers { get; set; } = [];
    public QualityRules QualityRules { get; set; } = new();
    public Dictionary<string, int> LatencyTargetsMs { get; set; } = [];
}
public sealed class DeploymentConfig
{
    public string Id { get; set; } = ""; public string Model { get; set; } = ""; public string Version { get; set; } = "";
    public int ContextWindow { get; set; } = 8192; public decimal CostPer1kIn { get; set; } public decimal CostPer1kOut { get; set; }
    public bool Fallback { get; set; } public string? Note { get; set; }
}
public sealed class QualityRules { public List<string> HighIfSeverity { get; set; } = []; public bool HighIfRetry { get; set; } public double HighIfConfidenceBelow { get; set; } }

public sealed class ContextConfig
{
    public string Label { get; set; } = "";
    public int SnippetContextLines { get; set; } = 4;
    public int RunSummaryMaxTokens { get; set; } = 200;
    public Dictionary<string, AgentContextConfig> Agents { get; set; } = [];
}
public sealed class AgentContextConfig
{
    public string Purpose { get; set; } = ""; public string Prompt { get; set; } = ""; public int Budget { get; set; }
    public List<string> Required { get; set; } = []; public List<string> Optional { get; set; } = []; public List<string> TrimOrder { get; set; } = [];
}

public sealed class RoutingConfig
{
    public string Label { get; set; } = "";
    public List<string> Scanners { get; set; } = [];
    public Dictionary<string, RouteEntry> Routes { get; set; } = [];
    public Dictionary<string, List<string>> Agents { get; set; } = [];
}
public sealed class RouteEntry
{
    public string RulePack { get; set; } = ""; public string Fixer { get; set; } = ""; public List<string> VerifierChecks { get; set; } = [];
    public string ModelTier { get; set; } = ""; public List<string> EnabledRepos { get; set; } = [];
}

public sealed class RulePack
{
    public string Id { get; set; } = ""; public string Version { get; set; } = ""; public List<string> IssueTypes { get; set; } = [];
    public string Prompt { get; set; } = "triage";
    public Dictionary<string, string> SeverityMap { get; set; } = [];
    public List<SuppressionRule> SuppressionRules { get; set; } = [];
    public Dictionary<string, List<string>> BucketRules { get; set; } = [];
    public List<string> ScannerRules { get; set; } = [];
    public string Guidance { get; set; } = "";
    public string FixGuidance { get; set; } = "";
    public Dictionary<string, object> Detect { get; set; } = [];
    public Dictionary<string, object> Policy { get; set; } = [];
    public Dictionary<string, ProviderRule> Providers { get; set; } = [];
    [YamlIgnore] public string Directory { get; set; } = "";
    [YamlIgnore] public string RawYaml { get; set; } = "";
    public string Ref => $"{Id}@{Version}";

    public string BucketFor(string severity)
    {
        foreach (var (bucket, sevs) in BucketRules) if (sevs.Contains(severity)) return bucket;
        return Buckets.FixBatch;
    }

    public List<string> GetList(Dictionary<string, object> d, string key) =>
        d.TryGetValue(key, out var v) && v is List<object> l ? l.Select(x => x?.ToString() ?? "").ToList() : [];
}
public sealed class ProviderRule { public string Guidance { get; set; } = ""; public List<string> Forbid { get; set; } = []; }

public sealed class SuppressionRule
{
    public string Id { get; set; } = ""; public string Description { get; set; } = "";
    public List<string> PathGlob { get; set; } = []; public Dictionary<string, string> Attribute { get; set; } = [];
    public string MaxSeverity { get; set; } = "medium";
}

public sealed class Prompt
{
    public string Id { get; set; } = ""; public string Version { get; set; } = ""; public string Text { get; set; } = "";
    public string Ref => $"{Id}@{Version}";
}

/// <summary>An immutable, hashed snapshot of all rules-as-code config used by a run (stands in for an App Configuration snapshot label).</summary>
public sealed class ConfigSnapshot
{
    public required string RulesRoot { get; init; }
    public required PolicyConfig Policies { get; init; }
    public required GatewayConfig Gateway { get; init; }
    public required ContextConfig Context { get; init; }
    public required RoutingConfig Routing { get; init; }
    public required Dictionary<string, RulePack> RulePacks { get; init; }
    public required Dictionary<string, Prompt> Prompts { get; init; }
    public required Dictionary<string, string> Schemas { get; init; }
    public required string Hash { get; init; }
    public string Label => $"{Policies.Label}+{Routing.Label}+{Gateway.Label}+{Context.Label}#{Hash[..8]}";

    public RulePack RulePackFor(string issueType) =>
        Routing.Routes.TryGetValue(issueType, out var r) && RulePacks.TryGetValue(r.RulePack, out var rp) ? rp
        : throw new InvalidOperationException($"No rule pack registered for issue type '{issueType}'");

    public static ConfigSnapshot Load(string rulesRoot, ModelProviderSettings? provider = null)
    {
        var de = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).IgnoreUnmatchedProperties().Build();
        var sha = SHA256.Create();
        var all = new StringBuilder();
        T Y<T>(string rel)
        {
            var text = File.ReadAllText(Path.Combine(rulesRoot, rel));
            all.Append(rel).Append('\n').Append(text);
            return de.Deserialize<T>(text);
        }
        var packs = new Dictionary<string, RulePack>();
        foreach (var dir in Directory.GetDirectories(Path.Combine(rulesRoot, "rule-packs")).OrderBy(x => x))
        {
            var file = Path.Combine(dir, "rules.yaml");
            if (!File.Exists(file)) continue;
            var text = File.ReadAllText(file);
            all.Append(file).Append(text);
            var rp = de.Deserialize<RulePack>(text);
            rp.Directory = dir; rp.RawYaml = text;
            packs[rp.Id] = rp;
        }
        var prompts = new Dictionary<string, Prompt>();
        foreach (var f in Directory.GetFiles(Path.Combine(rulesRoot, "prompts"), "*.md").OrderBy(x => x))
        {
            var text = File.ReadAllText(f);
            all.Append(f).Append(text);
            var p = ParsePrompt(text);
            prompts[p.Id] = p;
        }
        var schemas = new Dictionary<string, string>();
        foreach (var f in Directory.GetFiles(Path.Combine(rulesRoot, "schema"), "*.schema.json").OrderBy(x => x))
        {
            var text = File.ReadAllText(f);
            all.Append(f).Append(text);
            schemas[Path.GetFileName(f).Replace(".schema.json", "")] = text;
        }
        var policies = Y<PolicyConfig>("policies/policies.yaml");
        var gateway = Y<GatewayConfig>("gateway/models.yaml");
        var context = Y<ContextConfig>("gateway/context.yaml");
        var routing = Y<RoutingConfig>("routing/routing.yaml");
        if (provider != null)
        {
            provider.ApplyTo(gateway);   // provider switch is part of the hashed snapshot (never the key itself)
            all.Append("provider\n").Append(JsonSerializer.Serialize(gateway.Tiers)).Append(gateway.Endpoint).Append(gateway.ApiKeyEnv);
        }
        var hash = Convert.ToHexStringLower(sha.ComputeHash(Encoding.UTF8.GetBytes(all.ToString())));
        return new ConfigSnapshot
        {
            RulesRoot = rulesRoot, Policies = policies, Gateway = gateway, Context = context, Routing = routing,
            RulePacks = packs, Prompts = prompts, Schemas = schemas, Hash = hash,
        };
    }

    public static Prompt ParsePrompt(string text)
    {
        var p = new Prompt();
        var lines = text.Replace("\r", "").Split('\n');
        int i = 0;
        if (lines.Length > 0 && lines[0].Trim() == "---")
        {
            for (i = 1; i < lines.Length && lines[i].Trim() != "---"; i++)
            {
                var kv = lines[i].Split(':', 2);
                if (kv.Length != 2) continue;
                if (kv[0].Trim() == "id") p.Id = kv[1].Trim();
                if (kv[0].Trim() == "version") p.Version = kv[1].Trim();
            }
            i++;
        }
        p.Text = string.Join('\n', lines.Skip(i)).Trim();
        return p;
    }
}
