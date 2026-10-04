using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Composition;

// secagent-eval: golden-set evaluation of the Security Triage & Fix Agent. See docs/evaluation.md.
//   run   [--mode replay|live|record] [--case ID|CATEGORY|PREFIX*]... [--parallel N] [--out DIR] [--baseline FILE] [--gates FILE]
//         [--update-baseline] [--keep-workspaces] [--work DIR] [--cases DIR] [--rules DIR]
//   list  print the cases
//   stamp replay and write the current prompt hashes into the recordings (after an intentional prompt change)
// Exit codes: 0 = gate passed, 1 = gate failed, 2 = usage or configuration error.

var verb = args.Length > 0 && !args[0].StartsWith("--") ? args[0] : "run";
var rest = args.SkipWhile(a => a == verb).ToArray();
if (verb is "-h" or "--help" or "help") { Console.WriteLine(Usage); return 0; }
if (verb is not ("run" or "list" or "stamp")) { Console.Error.WriteLine($"unknown command '{verb}'\n{Usage}"); return 2; }

var opts = new EvalOptions();
try
{
    for (int i = 0; i < rest.Length; i++)
    {
        string Next() => i + 1 < rest.Length ? rest[++i] : throw new ArgumentException($"{rest[i]} needs a value");
        switch (rest[i])
        {
            case "--mode": opts.Mode = Next(); break;
            case "--case": opts.CaseFilter.Add(Next()); break;
            case "--parallel": opts.MaxParallel = int.Parse(Next()); break;
            case "--out": opts.OutputDir = Path.GetFullPath(Next()); break;
            case "--baseline": opts.BaselinePath = Path.GetFullPath(Next()); break;
            case "--gates": opts.GatesPath = Path.GetFullPath(Next()); break;
            case "--cases": opts.CasesRoot = Path.GetFullPath(Next()); break;
            case "--rules": opts.RulesRoot = Path.GetFullPath(Next()); break;
            case "--work": opts.WorkRoot = Path.GetFullPath(Next()); break;
            case "--update-baseline": opts.UpdateBaseline = true; break;
            case "--keep-workspaces": opts.KeepWorkspaces = true; break;
            default: throw new ArgumentException($"unknown option {rest[i]}");
        }
    }
    if (verb == "stamp") opts.Mode = EvalModes.Stamp;
}
catch (Exception e) when (e is ArgumentException or FormatException) { Console.Error.WriteLine(e.Message + "\n" + Usage); return 2; }

opts.RepoRoot = FindRepoRoot() ?? Directory.GetCurrentDirectory();
// Synthetic secrets are located by HMAC like the pipeline does; outside the dev box no key is configured, so use a process-local test key.
if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SECAGENT_HMAC_KEY"))) Environment.SetEnvironmentVariable("SECAGENT_HMAC_KEY", "secagent-eval-test-only-hmac-key");

var services = new ServiceCollection().AddSecAgentEval(o =>
{
    o.RepoRoot = opts.RepoRoot; o.Mode = opts.Mode; o.CaseFilter = opts.CaseFilter; o.MaxParallel = opts.MaxParallel; o.OutputDir = opts.OutputDir;
    o.BaselinePath = opts.BaselinePath; o.GatesPath = opts.GatesPath; o.CasesRoot = opts.CasesRoot; o.RulesRoot = opts.RulesRoot; o.WorkRoot = opts.WorkRoot;
    o.UpdateBaseline = opts.UpdateBaseline; o.KeepWorkspaces = opts.KeepWorkspaces;
});
await using var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
try
{
    _ = sp.GetRequiredService<IOptions<EvalOptions>>().Value;   // validate options before doing any work
    if (verb == "list")
    {
        foreach (var c in sp.GetRequiredService<ICaseSource>().Load(opts.CaseFilter))
            Console.WriteLine($"{c.Id,-40} {c.Category,-26} {(c.IsNegative ? "negative" : "positive"),-9} {c.Expected.Triage} → {c.Expected.Fixer ?? "none"} → {c.Expected.Outcome}");
        return 0;
    }
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
    var output = await sp.GetRequiredService<IEvalRunner>().RunAsync(cts.Token);
    var r = output.Report; var s = r.Summary;
    foreach (var c in r.Cases) Console.WriteLine($"{(c.Passed ? "PASS" : "FAIL")}  {c.Id,-40} {c.Actual.Triage ?? "-",-16} {c.Actual.Fixer,-15} {c.Actual.Outcome,-16} {c.FailureKind}");
    Console.WriteLine($"\n{r.Mode} mode: {s.Passed}/{s.Total} passed ({s.PassRate:P1}), {s.UnsafeOutcomes} unsafe, {s.Errors} errors · gate {(r.Gate.Passed ? "PASSED" : "FAILED")}");
    foreach (var g in r.Gate.Checks) Console.WriteLine($"  {(g.Passed ? "ok  " : "FAIL")} {g.Name}: {g.Detail}");
    foreach (var f in output.Files) Console.WriteLine($"wrote {f}");
    return r.Gate.Passed ? 0 : 1;
}
catch (OptionsValidationException e) { Console.Error.WriteLine("configuration error: " + string.Join("; ", e.Failures)); return 2; }

static string? FindRepoRoot()
{
    foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        for (var d = new DirectoryInfo(start); d != null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "SecAgent.slnx"))) return d.FullName;
    return null;
}

partial class Program
{
    const string Usage = """
        usage: secagent-eval [run|list|stamp] [options]
          --mode replay|live|record   replay (default) uses recorded answers: deterministic, free; live calls the provider from the
                                      provider switch (SECAGENT_MODEL_PROVIDER, key from its env var); record = live + save recordings
          --case ID|CATEGORY|PREFIX*  run a subset (repeatable)
          --parallel N                cases at a time (default 2)
          --out DIR                   report folder (default eval/out)
          --baseline FILE             baseline to compare with (default eval/golden/baseline.json)
          --gates FILE                gate thresholds (default eval/golden/gates.json)
          --update-baseline           write this run's results as the new baseline
          --keep-workspaces           keep the per-case git workspaces for inspection
        """;
}
