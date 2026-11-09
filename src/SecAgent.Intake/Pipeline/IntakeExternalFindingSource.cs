using System.Text;
using System.Text.Json;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Pipeline;

/// <summary>Implements the pipeline's <see cref="IExternalFindingSource"/> port: every queued/started intake for this repo at exactly this
/// head SHA (latest per scanner + format, so a re-run replaces, not doubles). Each call returns fresh copies, so a run can mutate them freely.</summary>
public sealed class IntakeExternalFindingSource(IIntakeRecordQuery records, IRawFindingStore raw, TimeProvider clock) : IExternalFindingSource
{
    public IReadOnlyList<ExternalFindingBatch> ForHead(string repo, string headSha) => records.All()
        .Where(r => r.Meta != null && r.CanonicalUri != null && r.Status is IntakeStatus.Queued or IntakeStatus.RunStarted
                    && string.Equals(r.Meta.Repo, repo, StringComparison.OrdinalIgnoreCase) && string.Equals(r.Meta.HeadSha, headSha, StringComparison.OrdinalIgnoreCase))
        .GroupBy(r => (r.Meta!.Scanner, r.Meta.Format)).Select(g => g.OrderByDescending(r => r.ReceivedAt).First())   // re-runs of one scanner: latest wins
        .Select(r => new ExternalFindingBatch(r.IntakeId, r.Meta!.Scanner, r.ScannerVersion ?? "", r.RawUri ?? "",
            (JsonSerializer.Deserialize<List<Finding>>(Encoding.UTF8.GetString(raw.Get(r.CanonicalUri!)), Schema.Json) ?? [])
                .Select(f => { f.FindingId = Guid.NewGuid(); f.LastSeen = clock.GetUtcNow().UtcDateTime; return f; }).ToList()))
        .ToList();
}
