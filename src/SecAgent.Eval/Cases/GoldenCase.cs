using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecAgent.Eval.Cases;

/// <summary>One golden case (eval/golden/cases/&lt;id&gt;/case.json): a synthetic fixture, the canonical finding it produces and the expected outcome.</summary>
public sealed class GoldenCase
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>Vulnerability class, e.g. sql_injection, secret_in_config (used for per-category reporting).</summary>
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>positive (agent should fix) or negative (agent must refuse / escalate), plus free tags.</summary>
    public List<string> Tags { get; set; } = [];
    public ExpectedOutcome Expected { get; set; } = new();
    /// <summary>Acceptance checks beyond the expected outcome (builds, tests_pass, pattern_absent, ...). Each type has an IOutcomeChecker.</summary>
    public List<CheckSpec> Checks { get; set; } = [];
    /// <summary>The finding the verifier must no longer see after a fix (rule id of eval/golden/scanner-rules.yaml + file).</summary>
    public ScanTarget? Target { get; set; }
    /// <summary>Synthetic secret placeholders: name → kind. Values are generated at run time (never committed) and replace {{secret:NAME}} / {{hmac:NAME}}.</summary>
    public Dictionary<string, string> SyntheticSecrets { get; set; } = [];
    /// <summary>Files generated at run time instead of being committed (e.g. a PE stub for the binary case).</summary>
    public List<GeneratedFile> GeneratedFiles { get; set; } = [];
    /// <summary>Package versions the offline resolver knows for this case (package → versions); default: the finding's fixed_version.</summary>
    public Dictionary<string, List<string>> PackageVersions { get; set; } = [];
    public string? Notes { get; set; }

    [JsonIgnore] public string Directory { get; set; } = "";
    [JsonIgnore] public string FixtureDirectory => Path.Combine(Directory, "fixture");
    [JsonIgnore] public string FindingTemplatePath => Path.Combine(Directory, "finding.json");
    [JsonIgnore] public string ReplayPath => Path.Combine(Directory, "replay.json");
    [JsonIgnore] public bool IsNegative => Tags.Contains("negative");

    /// <summary>Expected outcome fields expanded to checks, followed by the explicit acceptance checks.</summary>
    public IReadOnlyList<CheckSpec> AllChecks()
    {
        var list = new List<CheckSpec>
        {
            CheckSpec.Of("triage_decision", Expected.Triage),
            CheckSpec.Of("fixer", Expected.Fixer ?? "none"),
            CheckSpec.Of("outcome", Expected.Outcome),
        };
        if (Expected.SeverityEffective != null) list.Add(CheckSpec.Of("severity_effective", Expected.SeverityEffective));
        foreach (var t in Expected.HumanTasks) list.Add(CheckSpec.Of("human_task", t));
        if (Expected.InjectionFlagged is bool inj) list.Add(CheckSpec.Of("injection_flagged", inj ? "true" : "false"));
        if (SyntheticSecrets.Count > 0) list.Add(new CheckSpec { Type = "secret_not_exposed" });
        list.AddRange(Checks);
        return list;
    }
}

public sealed class ExpectedOutcome
{
    /// <summary>Policy-layer triage decision: fix | suppress | suppress_pending | accept_pending | needs_human.</summary>
    public string Triage { get; set; } = "";
    /// <summary>Fixer id from rules/routing/routing.yaml (library, secrets, unsafe_code, binary_licence) or null when no fixer should run.</summary>
    public string? Fixer { get; set; }
    /// <summary>Final outcome: fixed (verified fix proposed for human review) | suppressed | suppress_pending | accept_pending | needs_human.</summary>
    public string Outcome { get; set; } = "";
    public string? SeverityEffective { get; set; }
    public List<string> HumanTasks { get; set; } = [];
    public bool? InjectionFlagged { get; set; }
}

/// <summary>A check of a given type with free-form arguments (each checker reads its own).</summary>
public sealed class CheckSpec
{
    public string Type { get; set; } = "";
    [JsonExtensionData] public Dictionary<string, JsonElement> Args { get; set; } = [];

    public static CheckSpec Of(string type, string expected) =>
        new() { Type = type, Args = new() { ["expected"] = JsonSerializer.SerializeToElement(expected) } };

    public string? Arg(string name) => Args.TryGetValue(name, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString() : null;
    public string Required(string name) => Arg(name) ?? throw new InvalidOperationException($"check '{Type}' needs argument '{name}'");

    public List<string> ArgList(string name) =>
        !Args.TryGetValue(name, out var v) ? []
        : v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
        : [v.GetString() ?? ""];

    public string Describe() => Args.Count == 0 ? Type : $"{Type}({string.Join(", ", Args.Select(kv => $"{kv.Key}={Render(kv.Value)}"))})";

    static string Render(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString()!,
        JsonValueKind.Array => "[" + string.Join(", ", v.EnumerateArray().Select(Render)) + "]",
        _ => v.GetRawText(),
    };
}

public sealed record ScanTarget(string Rule, string File);

public sealed class GeneratedFile
{
    public string Path { get; set; } = "";
    /// <summary>pe_stub: a few bytes with the PE "MZ" magic (enough for binary detection; not a real executable).</summary>
    public string Kind { get; set; } = "pe_stub";
}
