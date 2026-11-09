namespace SecAgent.Core;

/// <summary>Scanner-agnostic normalisation rules shared by every scanner → canonical <see cref="Finding"/> adapter
/// (built-in gitleaks/Trivy/Semgrep adapters in SecAgent.Agents and the intake parsers). Pure functions, no state.</summary>
public static class FindingNormalisation
{
    /// <summary>Scanner severity word → canonical severity (unknown words map to medium).</summary>
    public static string Severity(string? s) => (s ?? "").ToLowerInvariant() switch
    {
        "critical" => "critical", "high" => "high", "error" => "high", "medium" => "medium", "moderate" => "medium", "warning" => "medium",
        "low" => "low", "note" => "low", "info" => "info", "negligible" => "info", _ => "medium",
    };

    /// <summary>Scanner path → repo-relative, forward-slash path.</summary>
    public static string RepoRelativePath(string p) => p.Replace('\\', '/').TrimStart('.', '/');
}
