using System.Text.Json;
using SecAgent.Core;

namespace SecAgent.Eval.Scoring;

/// <summary>The committed reference result (eval/golden/baseline.json): which cases passed last time it was accepted.</summary>
public sealed class Baseline
{
    public string Mode { get; set; } = "";
    public string CreatedUtc { get; set; } = "";
    public string ConfigLabel { get; set; } = "";
    public int Total { get; set; }
    public int Passed { get; set; }
    public double PassRate { get; set; }
    public SortedDictionary<string, BaselineCase> Cases { get; set; } = new(StringComparer.Ordinal);
}

public sealed class BaselineCase
{
    public bool Passed { get; set; }
    public string Outcome { get; set; } = "";
    public string? FailureKind { get; set; }
}

public sealed record BaselineComparison(bool HasBaseline, string? BaselineMode, double? BaselinePassRate, IReadOnlyList<string> Regressions,
    IReadOnlyList<string> Improvements, IReadOnlyList<string> NewCases, IReadOnlyList<string> NotRun)
{
    public static BaselineComparison Compare(Baseline? b, IReadOnlyList<CaseResult> cases)
    {
        if (b == null) return new(false, null, null, [], [], cases.Select(c => c.Id).ToList(), []);
        var run = cases.ToDictionary(c => c.Id);
        return new(true, b.Mode, b.PassRate,
            cases.Where(c => !c.Passed && b.Cases.TryGetValue(c.Id, out var x) && x.Passed).Select(c => c.Id).ToList(),
            cases.Where(c => c.Passed && b.Cases.TryGetValue(c.Id, out var x) && !x.Passed).Select(c => c.Id).ToList(),
            cases.Where(c => !b.Cases.ContainsKey(c.Id)).Select(c => c.Id).ToList(),
            b.Cases.Keys.Where(id => !run.ContainsKey(id)).ToList());
    }
}

public interface IBaselineStore
{
    Baseline? Load(string path);
    void Save(string path, Baseline baseline);
}

public sealed class FileBaselineStore : IBaselineStore
{
    public Baseline? Load(string path) => File.Exists(path) ? JsonSerializer.Deserialize<Baseline>(File.ReadAllText(path), Schema.Json) : null;
    public void Save(string path, Baseline baseline) => File.WriteAllText(path, JsonSerializer.Serialize(baseline, EvalJson.Files) + "\n");

    public static Baseline From(string mode, string createdUtc, string configLabel, EvalSummary s, IReadOnlyList<CaseResult> cases) => new()
    {
        Mode = mode, CreatedUtc = createdUtc, ConfigLabel = configLabel, Total = s.Total, Passed = s.Passed, PassRate = s.PassRate,
        Cases = new(cases.ToDictionary(c => c.Id, c => new BaselineCase { Passed = c.Passed, Outcome = c.Actual.Outcome, FailureKind = c.FailureKind }), StringComparer.Ordinal),
    };
}
