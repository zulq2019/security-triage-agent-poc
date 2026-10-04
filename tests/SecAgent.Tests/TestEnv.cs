using SecAgent.Core;

namespace SecAgent.Tests;

/// <summary>Shared test environment: repo root, rules snapshot, local secrets file (SQL connection + HMAC key).</summary>
public static class TestEnv
{
    public static readonly string RepoRoot = FindRoot();
    public static readonly ConfigSnapshot Cfg;

    static TestEnv()
    {
        var env = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".secagent", "secagent.env");
        if (File.Exists(env))
            foreach (var line in File.ReadAllLines(env))
            {
                var l = line.Trim(); if (l.Length == 0 || l.StartsWith('#')) continue;
                if (l.StartsWith("export ")) l = l[7..];
                var i = l.IndexOf('='); if (i <= 0) continue;
                var k = l[..i]; var v = l[(i + 1)..].Trim().Trim('"', '\'');
                if (Environment.GetEnvironmentVariable(k) == null) Environment.SetEnvironmentVariable(k, v);
            }
        Environment.SetEnvironmentVariable("SECAGENT_HMAC_KEY", Environment.GetEnvironmentVariable("SECAGENT_HMAC_KEY") ?? "test-only-hmac-key");
        Cfg = ConfigSnapshot.Load(Path.Combine(RepoRoot, "rules"));
    }

    static string FindRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !File.Exists(Path.Combine(d.FullName, "SecAgent.slnx"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    public static string? Sql => Environment.GetEnvironmentVariable("SECAGENT_SQL");
    public static SqlStore Store() => new(Sql ?? throw new InvalidOperationException("SECAGENT_SQL not set: golden/integration tests need the local SQL Server (see docs/README.md)"));
}
