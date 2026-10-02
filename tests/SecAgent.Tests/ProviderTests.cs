using SecAgent.Core;
using Xunit;

namespace SecAgent.Tests;

[Collection("env")]   // these tests change process environment variables
public class ProviderTests
{
    static ConfigSnapshot LoadWith(params (string K, string? V)[] env)
    {
        var keys = new[] { "SECAGENT_MODEL_PROVIDER", "SECAGENT_LOCAL_PROFILE", "SECAGENT_SMALL_MODEL", "SECAGENT_STRONG_MODEL", "SECAGENT_MODEL_BASE_URL" };
        var saved = keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var k in keys) Environment.SetEnvironmentVariable(k, null);
            foreach (var (k, v) in env) Environment.SetEnvironmentVariable(k, v);
            return ConfigSnapshot.Load(Path.Combine(TestEnv.RepoRoot, "rules"), ModelProviderSettings.Load(TestEnv.RepoRoot));
        }
        finally { foreach (var (k, v) in saved) Environment.SetEnvironmentVariable(k, v); }
    }

    [Fact]
    public void Default_is_local_ollama_with_two_tiers()
    {
        var c = LoadWith();
        Assert.Equal("http://localhost:11434/v1", c.Gateway.Endpoint);
        Assert.Equal("qwen2.5:3b", c.Gateway.Tiers["small"][0].Model);
        Assert.Equal("qwen2.5-coder:7b", c.Gateway.Tiers["strong"][0].Model);
    }

    [Fact]
    public void Three_b_only_profile_uses_one_small_model_for_both_tiers()
    {
        var c = LoadWith(("SECAGENT_LOCAL_PROFILE", "3b-only"));
        Assert.All(c.Gateway.Tiers.Values.SelectMany(t => t), d => Assert.Contains(":3b", d.Model));
        Assert.Equal("qwen2.5-coder:3b", c.Gateway.Tiers["strong"][0].Model);
        Assert.EndsWith("+3b-only", c.Gateway.Label);
    }

    [Fact]
    public void OpenAI_switch_is_config_only_and_key_comes_from_env_var_name()
    {
        var local = LoadWith();
        var c = LoadWith(("SECAGENT_MODEL_PROVIDER", "openai"), ("SECAGENT_STRONG_MODEL", "my-strong-model"));
        Assert.Equal("openai", c.Gateway.Provider);
        Assert.Equal("https://api.openai.com/v1", c.Gateway.Endpoint);
        Assert.Equal("OPENAI_API_KEY", c.Gateway.ApiKeyEnv);
        Assert.Equal("", c.Gateway.HealthUrl);
        Assert.False(c.Gateway.SendTemperature);
        Assert.Equal("my-strong-model", c.Gateway.Tiers["strong"][0].Model);
        Assert.NotEqual(local.Hash, c.Hash);                         // provider is part of the hashed config snapshot
        Assert.Equal(local.Gateway.QualityRules.HighIfSeverity, c.Gateway.QualityRules.HighIfSeverity); // routing policy unchanged
    }

    [Fact]
    public void Azure_switch_uses_its_own_key_env_var()
    {
        var c = LoadWith(("SECAGENT_MODEL_PROVIDER", "azureopenai"), ("SECAGENT_MODEL_BASE_URL", "https://example.openai.azure.com/openai/v1/"));
        Assert.Equal("AZURE_OPENAI_API_KEY", c.Gateway.ApiKeyEnv);
        Assert.Equal("https://example.openai.azure.com/openai/v1/", c.Gateway.Endpoint);
    }

    [Fact]
    public void Unknown_provider_is_rejected() => Assert.Throws<InvalidOperationException>(() => LoadWith(("SECAGENT_MODEL_PROVIDER", "foo")));

    [Fact]
    public void No_api_key_is_committed_in_appsettings()
    {
        var text = File.ReadAllText(Path.Combine(TestEnv.RepoRoot, "src/SecAgent.Dashboard/appsettings.json"));
        Assert.DoesNotMatch(@"sk-[A-Za-z0-9_\-]{16,}", text);
        Assert.DoesNotContain("\"ApiKey\"", text);
    }
}
