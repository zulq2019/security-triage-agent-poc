using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecAgent.Core;

namespace SecAgent.Agents.Scanners;

public sealed record ScanSet(List<Finding> Findings, List<(string Scanner, string Version, long Ms, int Count, string RawUri)> Runs, string SarifUri);

/// <summary>Runs registered scanner adapters, stores raw output (Blob stand-in, hashed), normalises to canonical findings,
/// validates against the canonical JSON Schema and writes a canonical SARIF 2.1.0 log.</summary>
public sealed class ScannerHub(ConfigSnapshot cfg, IEnumerable<IScannerAdapter> adapters, LocalBlobStore blob, SqlStore store, SchemaValidator validator)
{
    public IReadOnlyList<IScannerAdapter> Adapters { get; } = adapters.Where(a => cfg.Routing.Scanners.Contains(a.Id)).ToList();

    public async Task<ScanSet> ScanAsync(ScanTarget t, CancellationToken ct, Action<string, string>? onStart = null, Action<string, RawOutput, int>? onDone = null)
    {
        var tracked = BinaryCheckAdapter.GitFiles(t.Dir).ToHashSet();
        var tasks = Adapters.Select(async a =>
        {
            using var span = Telemetry.Source.StartActivity($"scan {a.Id}");
            span?.SetTag("secagent.scanner", a.Id); span?.SetTag("secagent.target", t.Label);
            onStart?.Invoke(a.Id, t.Label);
            var raw = await a.ScanAsync(t, ct);
            var findings = a.Normalise(raw, t, tracked);
            span?.SetTag("secagent.findings", findings.Count);
            onDone?.Invoke(a.Id, raw, findings.Count);
            return (a, raw, findings);
        }).ToList();
        var results = await Task.WhenAll(tasks);

        var all = new List<Finding>();
        var runs = new List<(string, string, long, int, string)>();
        foreach (var (a, raw, findings) in results)
        {
            var (uri, hash) = blob.Put("raw", $"{t.RunId}/{t.Label}/{a.Id}.json", raw.StoredContent);
            var ev = new Evidence { Type = "raw_scan", Uri = uri, Hash = hash, CreatedBy = "scanners", TraceId = Telemetry.TraceId, RelatedIds = [t.RunId] };
            store.InsertEvidence(ev);
            foreach (var f in findings) { f.RawEvidenceRef = uri; f.CreatedByRun = t.RunId; f.FilePath = f.FilePath?.Replace('\\', '/'); }
            // Validate the whole batch; an invalid batch is rejected (no partial records).
            var errors = findings.Select(f => validator.ValidateFinding(f)).Where(e => e != null).ToList();
            if (errors.Count > 0) throw new InvalidDataException($"{a.Id} output failed canonical schema validation: {errors[0]}");
            all.AddRange(findings);
            runs.Add((a.Id, raw.ScannerVersion, raw.ElapsedMs, findings.Count, uri));
        }
        for (int i = 0; i < all.Count; i++) all[i].SarifRef = $"{t.RunId}:{t.Label}#{i}";
        var sarifUri = blob.Put("raw", $"{t.RunId}/{t.Label}/canonical.sarif.json", Sarif(all, runs)).Uri;
        return new ScanSet(all, runs, sarifUri);
    }

    /// <summary>Canonical SARIF 2.1.0: fingerprint in result.fingerprints["secagent/v1"], extra fields in properties "secagent.*".</summary>
    static string Sarif(List<Finding> findings, List<(string Scanner, string Version, long Ms, int Count, string RawUri)> runs)
    {
        var runsArr = new JsonArray();
        foreach (var g in findings.GroupBy(f => f.SourceScanner))
        {
            var results = new JsonArray();
            foreach (var f in g)
            {
                var props = new JsonObject();
                foreach (var (k, v) in JsonSerializer.SerializeToNode(f, Schema.Json)!.AsObject())
                    if (k is not ("attributes" or "message")) props["secagent." + k] = v?.DeepClone();
                results.Add(new JsonObject
                {
                    ["ruleId"] = f.ScannerRuleId,
                    ["level"] = Schema.Rank(f.SeverityScanner) >= 3 ? "error" : Schema.Rank(f.SeverityScanner) == 2 ? "warning" : "note",
                    ["message"] = new JsonObject { ["text"] = f.Title },
                    ["locations"] = f.FilePath == null ? new JsonArray() : new JsonArray(new JsonObject
                    {
                        ["physicalLocation"] = new JsonObject
                        {
                            ["artifactLocation"] = new JsonObject { ["uri"] = f.FilePath },
                            ["region"] = f.LineStart == null ? null : new JsonObject { ["startLine"] = f.LineStart, ["endLine"] = f.LineEnd ?? f.LineStart },
                        },
                    }),
                    ["fingerprints"] = new JsonObject { ["secagent/v1"] = f.Fingerprint },
                    ["properties"] = props,
                });
            }
            var r = runs.First(x => x.Scanner == g.Key);
            runsArr.Add(new JsonObject { ["tool"] = new JsonObject { ["driver"] = new JsonObject { ["name"] = g.Key, ["version"] = r.Version } }, ["results"] = results });
        }
        return new JsonObject { ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json", ["version"] = "2.1.0", ["runs"] = runsArr }
            .ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}
