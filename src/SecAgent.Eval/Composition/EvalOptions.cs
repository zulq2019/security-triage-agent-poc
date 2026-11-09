using Microsoft.Extensions.Options;

namespace SecAgent.Eval.Composition;

public static class EvalModes
{
    public const string Replay = "replay", Live = "live", Record = "record", Stamp = "stamp";
    public static readonly string[] All = [Replay, Live, Record, Stamp];
}

/// <summary>Harness settings (CLI flags map onto these). Paths default relative to the repository root.</summary>
public sealed class EvalOptions
{
    public string RepoRoot { get; set; } = "";
    /// <summary>rules/ (prompts, schemas, policies, routing, rule packs): the same rules-as-code the pipeline runs with.</summary>
    public string RulesRoot { get; set; } = "";
    /// <summary>eval/golden: cases/, scanner-rules.yaml, gates.json, baseline.json.</summary>
    public string CasesRoot { get; set; } = "";
    public string OutputDir { get; set; } = "";
    /// <summary>Scratch folder for case workspaces. Must be outside the repository so the repo's Directory.Build.props never applies to fixtures.</summary>
    public string WorkRoot { get; set; } = "";
    /// <summary>replay (default: recorded responses, deterministic, free) | live (calls the configured provider) | record (live + writes recordings).</summary>
    public string Mode { get; set; } = EvalModes.Replay;
    public string BaselinePath { get; set; } = "";
    public string GatesPath { get; set; } = "";
    public List<string> CaseFilter { get; set; } = [];
    public int MaxParallel { get; set; } = 2;
    public bool KeepWorkspaces { get; set; }
    public bool UpdateBaseline { get; set; }
    public int BuildTimeoutSeconds { get; set; } = 600;

    public string ScannerRulesPath => Path.Combine(CasesRoot, "scanner-rules.yaml");

    /// <summary>Fills unset paths from the repository root.</summary>
    public void ApplyDefaults()
    {
        if (RulesRoot.Length == 0) RulesRoot = Path.Combine(RepoRoot, "rules");
        if (CasesRoot.Length == 0) CasesRoot = Path.Combine(RepoRoot, "eval", "golden");
        if (OutputDir.Length == 0) OutputDir = Path.Combine(RepoRoot, "eval", "out");
        if (WorkRoot.Length == 0) WorkRoot = Path.Combine(Path.GetTempPath(), "secagent-eval");
        if (BaselinePath.Length == 0) BaselinePath = Path.Combine(CasesRoot, "baseline.json");
        if (GatesPath.Length == 0) GatesPath = Path.Combine(CasesRoot, "gates.json");
    }
}

/// <summary>Validated on first use: an unknown mode, a missing folder or a work root inside the repository stops the harness.</summary>
public sealed class EvalOptionsValidator : IValidateOptions<EvalOptions>
{
    public ValidateOptionsResult Validate(string? name, EvalOptions o)
    {
        var errors = new List<string>();
        if (!EvalModes.All.Contains(o.Mode)) errors.Add($"Mode '{o.Mode}' is not one of {string.Join(" | ", EvalModes.All)}");
        if (!Directory.Exists(o.RulesRoot)) errors.Add($"RulesRoot not found: {o.RulesRoot}");
        if (!Directory.Exists(o.CasesRoot)) errors.Add($"CasesRoot not found: {o.CasesRoot}");
        if (o.MaxParallel < 1) errors.Add("MaxParallel must be >= 1");
        if (o.RepoRoot.Length > 0 && Path.GetFullPath(o.WorkRoot).StartsWith(Path.GetFullPath(o.RepoRoot) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            errors.Add("WorkRoot must be outside the repository (the repo's Directory.Build.props would apply to the fixtures)");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
