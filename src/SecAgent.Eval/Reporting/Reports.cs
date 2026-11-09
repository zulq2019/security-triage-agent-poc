using System.Globalization;
using System.Text;
using System.Text.Json;
using SecAgent.Core;
using SecAgent.Eval.Scoring;

namespace SecAgent.Eval.Reporting;

/// <summary>Everything one harness run measured. Serialised as eval-report.json; rendered as eval-report.md.</summary>
public sealed record EvalReport(string SchemaVersion, string RunId, string Mode, string ModeDescription, IReadOnlyList<string> Models, string StartedUtc, string FinishedUtc,
    string ConfigLabel, string? Commit, EvalSummary Summary, GateOptions GateOptions, GateResult Gate, BaselineComparison Baseline, IReadOnlyList<CaseResult> Cases);

/// <summary>Writes a report in one format (Strategy; register more with services.AddReportWriter&lt;T&gt;()).</summary>
public interface IReportWriter
{
    string FileName { get; }
    Task<string> WriteAsync(EvalReport report, string outputDir, CancellationToken ct);
}

public sealed class JsonReportWriter : IReportWriter
{
    public string FileName => "eval-report.json";
    public async Task<string> WriteAsync(EvalReport report, string outputDir, CancellationToken ct)
    {
        Directory.CreateDirectory(outputDir);
        var path = Path.Combine(outputDir, FileName);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(report, EvalJson.Files) + "\n", ct);
        return path;
    }
}

/// <summary>Plain-language Markdown summary (also used as the GitHub Actions job summary).</summary>
public sealed class MarkdownReportWriter : IReportWriter
{
    public string FileName => "eval-report.md";

    public async Task<string> WriteAsync(EvalReport report, string outputDir, CancellationToken ct)
    {
        Directory.CreateDirectory(outputDir);
        var path = Path.Combine(outputDir, FileName);
        await File.WriteAllTextAsync(path, Render(report), ct);
        return path;
    }

    public static string Render(EvalReport r)
    {
        var s = r.Summary; var sb = new StringBuilder();
        var ok = r.Gate.Passed ? "✅ passed" : "❌ failed";
        sb.AppendLine($"# SecAgent evaluation: {r.Mode} mode · gate {ok}");
        sb.AppendLine();
        sb.AppendLine("> " + r.ModeDescription);
        sb.AppendLine();
        sb.AppendLine("| | |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| Cases | {s.Total} · **{s.Passed} passed** · {s.Failed} failed · pass rate **{s.PassRate.ToString("P1", CultureInfo.InvariantCulture)}** |");
        sb.AppendLine($"| Unsafe outcomes | {s.UnsafeOutcomes} (wrong suppression, fix where it should have escalated, or a bad fix proposed) |");
        sb.AppendLine($"| Harness errors | {s.Errors} |");
        if (r.Mode == "replay") sb.AppendLine($"| Recordings out of date | {s.PromptDrift} case(s) whose prompt changed since the recording was made |");
        sb.AppendLine($"| Run | `{r.RunId}` · {Ist(r.StartedUtc)} · commit `{(r.Commit is { Length: >= 7 } sha ? sha[..7] : "unknown")}` |");
        sb.AppendLine($"| Config | `{r.ConfigLabel}` |");
        sb.AppendLine($"| Models | {string.Join(", ", r.Models.Select(m => $"`{m}`"))} |");
        sb.AppendLine();
        sb.AppendLine("## Gate");
        sb.AppendLine();
        sb.AppendLine("| Rule | Result | Detail |");
        sb.AppendLine("|---|---|---|");
        foreach (var g in r.Gate.Checks) sb.AppendLine($"| {g.Name} | {(g.Passed ? "✅" : "❌")} | {Esc(g.Detail)} |");
        sb.AppendLine();
        var b = r.Baseline;
        sb.AppendLine("## Compared with the baseline");
        sb.AppendLine();
        if (!b.HasBaseline) sb.AppendLine("No baseline file yet.");
        else
        {
            sb.AppendLine($"Baseline: {b.BaselineMode} mode, pass rate {b.BaselinePassRate?.ToString("P1", CultureInfo.InvariantCulture)}.");
            sb.AppendLine();
            sb.AppendLine($"- Regressions (passed before, fail now): {List(b.Regressions)}");
            sb.AppendLine($"- Improvements (failed before, pass now): {List(b.Improvements)}");
            sb.AppendLine($"- New cases (not in the baseline): {List(b.NewCases)}");
            if (b.NotRun.Count > 0) sb.AppendLine($"- In the baseline but not run (filtered): {List(b.NotRun)}");
        }
        sb.AppendLine();
        sb.AppendLine("## Cases");
        sb.AppendLine();
        sb.AppendLine("| Case | Category | Kind | Expected: triage → fixer → outcome | Actual | Result |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (var c in r.Cases)
        {
            var kind = c.Tags.Contains("negative") ? "refuse/escalate" : "fix";
            var res = c.Passed ? "✅ pass" : $"❌ {c.FailureKind}";
            sb.AppendLine($"| `{c.Id}` | {c.Category} | {kind} | {c.Expected.Triage} → {c.Expected.Fixer} → {c.Expected.Outcome} | {c.Actual.Triage ?? "–"} → {c.Actual.Fixer} → {c.Actual.Outcome} | {res} |");
        }
        var failed = r.Cases.Where(c => !c.Passed).ToList();
        if (failed.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Failures");
            foreach (var c in failed)
            {
                sb.AppendLine();
                sb.AppendLine($"### `{c.Id}`: {Esc(c.Title)}");
                sb.AppendLine();
                sb.AppendLine($"Failure kind: **{c.FailureKind}**. Model proposed `{c.Actual.ProposedByModel ?? "–"}`, policy decided `{c.Actual.Triage ?? "–"}`, outcome `{c.Actual.Outcome}`.");
                sb.AppendLine();
                foreach (var x in c.Checks.Where(x => !x.Passed)) sb.AppendLine($"- ❌ `{Esc(x.Description)}`: {Esc(x.Detail)}");
                if (c.Actual.FixError != null) sb.AppendLine($"- Fixer error: {Esc(c.Actual.FixError)}");
                foreach (var v in c.Actual.VerifyReasons) sb.AppendLine($"- Verifier: {Esc(v)}");
                foreach (var e in c.Errors) sb.AppendLine($"- Harness error: {Esc(e)}");
            }
        }
        sb.AppendLine();
        sb.AppendLine("## By category");
        sb.AppendLine();
        sb.AppendLine("| Category | Passed |");
        sb.AppendLine("|---|---|");
        foreach (var (k, v) in s.ByCategory) sb.AppendLine($"| {k} | {v.Passed}/{v.Total} |");
        sb.AppendLine();
        var u = s.Usage;
        sb.AppendLine("## Tokens, cost, latency");
        sb.AppendLine();
        sb.AppendLine("| Model calls | Tokens in | Tokens out | Token source | Cost (USD) | Cost source | Model time | Case time p50 / p95 / total |");
        sb.AppendLine("|---|---|---|---|---|---|---|---|");
        sb.AppendLine($"| {u.Calls} | {u.TokensIn:N0} | {u.TokensOut:N0} | {string.Join(", ", u.TokenSources)} | {u.CostUsd:0.0000} | {string.Join(", ", u.CostSources)} | {u.ModelLatencyMs / 1000.0:0.0}s | {u.P50CaseLatencyMs / 1000.0:0.0}s / {u.P95CaseLatencyMs / 1000.0:0.0}s / {u.TotalCaseLatencyMs / 1000.0:0.0}s |");
        sb.AppendLine();
        sb.AppendLine("Token source: `estimate` = o200k tokenizer count of the prompt and the recorded answer (no model call was made); `recorded` = what the provider reported when the recording was made; `reported` = what the provider reported in this run. Case time includes building and testing the fixture.");
        return sb.ToString();
    }

    static string Ist(string utc) =>
        DateTimeOffset.TryParse(utc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
            ? $"{t.ToOffset(UsageMath.IstOffset):yyyy-MM-dd HH:mm} IST ({t.UtcDateTime:HH:mm} UTC)" : utc;

    static string List(IReadOnlyList<string> ids) => ids.Count == 0 ? "none" : string.Join(", ", ids.Select(i => $"`{i}`"));
    static string Esc(string s) => s.Replace("|", "\\|").Replace("\r", "").Replace("\n", " ");
}
