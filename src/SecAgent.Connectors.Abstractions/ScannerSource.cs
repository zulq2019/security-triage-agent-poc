namespace SecAgent.Connectors;

// Scanner source (Black Duck today): read-only pull of findings for backlog mode and of remediation guidance.
// It can never change policies, ignore or remediate anything in the scanner.

public sealed record ScannerProjectVersion(string ProjectId, string ProjectName, string VersionId, string VersionName);

public sealed record ComponentVersionRef(string ComponentId, string ComponentVersionId, string? ComponentName = null, string? Version = null, string? OriginId = null);

/// <param name="Severity">Lower case: critical | high | medium | low | info.</param>
/// <param name="RelatedIds">Related advisory ids, e.g. the CVE for a BDSA.</param>
public sealed record ScannerVulnerability(
    string VulnerabilityId,
    string Severity,
    double? Score,
    string ComponentName,
    string ComponentVersion,
    ComponentVersionRef? Component,
    string? Description,
    string? RemediationStatus,
    IReadOnlyList<string> RelatedIds,
    string? CweId,
    string? SourceUrl);

public sealed record RemediationGuidance(string ComponentName, string CurrentVersion, string? ShortTermVersion, string? LongTermVersion, string? Notes = null);

public interface IScannerProjectLocator
{
    Task<ScannerProjectVersion?> FindProjectVersionAsync(string projectName, string versionName, CancellationToken ct);
}

public interface IVulnerabilityBacklogReader
{
    /// <summary>All vulnerable components of one project version (backlog mode). Paged internally.</summary>
    Task<IReadOnlyList<ScannerVulnerability>> ListVulnerabilitiesAsync(ScannerProjectVersion version, CancellationToken ct);
}

public interface IRemediationGuidanceReader
{
    Task<RemediationGuidance?> GetRemediationGuidanceAsync(ComponentVersionRef component, CancellationToken ct);
}

public interface IScannerSourceClient : IScannerProjectLocator, IVulnerabilityBacklogReader, IRemediationGuidanceReader;
