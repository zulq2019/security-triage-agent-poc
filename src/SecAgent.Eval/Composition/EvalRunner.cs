using Microsoft.Extensions.Options;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Models;
using SecAgent.Eval.Reporting;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Stages;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Composition;

public sealed record EvalRunOutput(EvalReport Report, IReadOnlyList<string> Files);

/// <summary>Runs the selected cases (bounded parallelism), scores them, compares with the baseline, applies the gates and writes the reports.</summary>
public interface IEvalRunner
{
    Task<EvalRunOutput> RunAsync(CancellationToken ct);
}

public sealed class EvalRunner(IOptions<EvalOptions> options, ICaseSource cases, ICaseRunner runner, IEvalModelClient model, ConfigSnapshot cfg,
    IBaselineStore baselines, IGateEvaluator gates, IEnumerable<IReportWriter> writers, IProcessRunner proc, TimeProvider time) : IEvalRunner
{
    public async Task<EvalRunOutput> RunAsync(CancellationToken ct)
    {
        var o = options.Value;
        var started = time.GetUtcNow();
        var runId = $"eval-{started:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}";
        var runRoot = Path.Combine(o.WorkRoot, runId);
        Directory.CreateDirectory(runRoot);
        var selected = cases.Load(o.CaseFilter);
        if (selected.Count == 0) throw new InvalidOperationException("no golden case matched the filter");
        using var slots = new SemaphoreSlim(o.MaxParallel);
        var results = await Task.WhenAll(selected.Select(async c =>
        {
            await slots.WaitAsync(ct);
            try { return await runner.RunAsync(c, runRoot, ct); }
            finally { slots.Release(); }
        }));
        if (!o.KeepWorkspaces) try { Directory.Delete(runRoot, true); } catch (IOException) { /* best effort */ }
        var ordered = results.OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
        var summary = EvalSummary.From(ordered);
        var baseline = baselines.Load(o.BaselinePath);
        var comparison = BaselineComparison.Compare(baseline, ordered);
        var gateOptions = GateOptions.Load(o.GatesPath);
        var gate = gates.Evaluate(summary, comparison, gateOptions);
        var finished = time.GetUtcNow();
        var report = new EvalReport("1.0", runId, model.Mode, Describe(model.Mode, ordered), Models(ordered), started.UtcDateTime.ToString("O"), finished.UtcDateTime.ToString("O"),
            cfg.Label, await CommitAsync(o.RepoRoot, ct), summary, gateOptions, gate, comparison, ordered);
        var files = new List<string>();
        foreach (var w in writers) files.Add(await w.WriteAsync(report, o.OutputDir, ct));
        if (o.UpdateBaseline)
        {
            baselines.Save(o.BaselinePath, FileBaselineStore.From(model.Mode, report.FinishedUtc, cfg.Label, summary, ordered));
            files.Add(o.BaselinePath);
        }
        return new EvalRunOutput(report, files);
    }

    static IReadOnlyList<string> Models(IReadOnlyList<CaseResult> cases) =>
        cases.SelectMany(c => c.Usage).Select(u => u.Provider == "replay" ? $"replay: {u.Model}" : $"{u.Provider}/{u.Model}").Distinct().Order(StringComparer.Ordinal).ToList();

    static string Describe(string mode, IReadOnlyList<CaseResult> cases) => mode switch
    {
        "replay" or "stamp" => "**Replay mode.** Model answers come from the recordings committed next to each case (`replay.json`); no model was called and nothing was paid. " +
            "This measures the deterministic pipeline (context assembly, JSON-schema validation, the triage policy layer, routing, fix application, build/test verification and the acceptance checks) " +
            "on the golden set. It is not a measure of live model quality: authored recordings are the answers a correct agent would give.",
        "record" => "**Record mode.** Live model calls; the answers were saved as the new recordings. Results are from this single live run.",
        _ => "**Live mode.** Answers come from the configured model provider in this run. Results are from a single run and vary between runs; costs use the price source shown (placeholder prices are not real prices).",
    };

    async Task<string?> CommitAsync(string repoRoot, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_SHA") is { Length: > 0 } sha) return sha;
        try { var r = await proc.RunAsync("git", ["rev-parse", "HEAD"], repoRoot, ct, 30); return r.ExitCode == 0 ? r.StdOut.Trim() : null; }
        catch (Exception) { return null; }
    }
}
