using SecAgent.Core;

namespace SecAgent.Abstractions;

/// <summary>Findings pushed by an external scanner (e.g. Black Duck via the intake) for one commit. The pipeline's scanners step
/// asks this port, so the pipeline does not know where the findings come from (implemented by SecAgent.Intake).</summary>
public interface IExternalFindingSource
{
    /// <summary>Canonical findings received for this repo at this exact head commit (empty when none). Findings for an older head SHA are not returned.</summary>
    IReadOnlyList<ExternalFindingBatch> ForHead(string repo, string headSha);
}

public sealed record ExternalFindingBatch(string IntakeId, string Scanner, string ScannerVersion, string RawEvidenceRef, List<Finding> Findings);

/// <summary>Null Object: no external scanner is connected (CLI runs, tests).</summary>
public sealed class NoExternalFindingSource : IExternalFindingSource
{
    public IReadOnlyList<ExternalFindingBatch> ForHead(string repo, string headSha) => [];
}

/// <summary>Verifier policy for findings that came from an external scanner. The local rescan (gitleaks/Trivy/Semgrep) cannot prove a
/// Black Duck finding is gone (different rule ids, BDSA advisories, component naming), so the verifier never reports such a fix as verified.
/// Pure functions over the finding's attributes (no state, nothing to inject).</summary>
public static class ExternalFindingPolicy
{
    public const string IntakeIdAttribute = "intake_id";
    public static bool IsExternal(Finding f) => f.Attributes.ContainsKey(IntakeIdAttribute);
    public static List<Finding> NotLocallyVerifiable(IEnumerable<Finding> findings) => findings.Where(IsExternal).ToList();
}

/// <summary>Validates a canonical finding against rules/schema/finding.schema.json. Returns null when valid, else the first error.</summary>
public interface IFindingSchemaValidator
{
    string? ValidateFinding(Finding finding);
}

/// <summary>Starts a PR run exactly like POST /api/runs (implemented by the host over the pipeline's RunService).</summary>
public interface IPrRunLauncher
{
    /// <param name="expectedHeadSha">The commit the run is for (pushed findings are about one exact commit). The run starts only if the
    /// PR head still equals it, checked on the same PR snapshot the run uses; otherwise nothing starts and the result is superseded.
    /// Null = whatever the head is now (manual runs).</param>
    Task<PrRunStart> StartPrRunAsync(string repo, int prNumber, string? expectedHeadSha, CancellationToken ct);
}

/// <summary>Outcome of <see cref="IPrRunLauncher.StartPrRunAsync"/>: a started run, or "superseded" (the PR head moved past the
/// expected commit; <see cref="CurrentHeadSha"/> is the new head).</summary>
public sealed record PrRunStart(Guid? RunId, string CurrentHeadSha)
{
    public bool Started => RunId is not null;
    public static PrRunStart Run(Guid runId, string headSha) => new(runId, headSha);
    public static PrRunStart Superseded(string currentHeadSha) => new(null, currentHeadSha);
}

/// <summary>Whether a new run may start now (false while a run is active or the kill switch is on).</summary>
public interface IRunAdmission
{
    bool CanStartRun { get; }
}
