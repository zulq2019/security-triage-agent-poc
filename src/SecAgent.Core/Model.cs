using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecAgent.Core;

/// <summary>Canonical schema constants (PRD section 7). Values are stored as snake_case strings.</summary>
public static class Schema
{
    public const string Version = "1.1.0";
    public static readonly string[] Severities = ["critical", "high", "medium", "low", "info"];
    public static int Rank(string? sev) => sev switch { "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0 };
    public static string MaxSeverity(string a, string b) => Rank(a) >= Rank(b) ? a : b;

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };
    public static readonly JsonSerializerOptions JsonIndented = new(Json) { WriteIndented = true };
}

public static class IssueTypes
{
    public const string Secret = "secret", VulnerableDependency = "vulnerable_dependency", UnsafeCode = "unsafe_code",
        BinaryArtefact = "binary_artefact", Licence = "licence";
}

public static class Status
{
    public const string New = "NEW", Triaged = "TRIAGED", Duplicate = "DUPLICATE", FixQueued = "FIX_QUEUED",
        FixInProgress = "FIX_IN_PROGRESS", FixProposed = "FIX_PROPOSED", Verified = "VERIFIED", VerifyFailed = "VERIFY_FAILED",
        Resolved = "RESOLVED", AcceptPending = "ACCEPT_PENDING", RiskAccepted = "RISK_ACCEPTED", SuppressPending = "SUPPRESS_PENDING",
        Suppressed = "SUPPRESSED", NeedsHuman = "NEEDS_HUMAN", Reopened = "REOPENED";
}

public static class Buckets
{
    public const string FixNow = "fix_now", FixBatch = "fix_batch", AcceptDefer = "accept_defer", Suppress = "suppress";
}

/// <summary>Canonical Finding (section 7.2). SARIF-based; extra fields live in result.properties["secagent.*"].</summary>
public sealed class Finding
{
    public Guid FindingId { get; set; } = Guid.NewGuid();
    public string SchemaVersion { get; set; } = Schema.Version;
    public string SourceScanner { get; set; } = "";
    public string ScannerVersion { get; set; } = "";
    public string ScannerRuleId { get; set; } = "";
    public string IssueType { get; set; } = "";
    public string Title { get; set; } = "";
    public List<string> CveIds { get; set; } = [];
    public List<string> CweIds { get; set; } = [];
    public string SeverityScanner { get; set; } = "medium";
    public string? SeverityEffective { get; set; }
    public string Repo { get; set; } = "";
    public string Branch { get; set; } = "";
    public int? PrNumber { get; set; }
    public string CommitSha { get; set; } = "";
    public string? FilePath { get; set; }
    public int? LineStart { get; set; }
    public int? LineEnd { get; set; }
    public string? ComponentName { get; set; }
    public string? ComponentVersion { get; set; }
    public string? FixedVersion { get; set; }
    public string? DirectOrTransitive { get; set; }
    public string? LicenceId { get; set; }
    public string? Reachability { get; set; } = "unknown";
    public string? Exposure { get; set; } = "unknown";
    public string Fingerprint { get; set; } = "";
    public string? FixGroupKey { get; set; }
    public int OccurrenceCount { get; set; } = 1;
    public string Status { get; set; } = Core.Status.New;
    public string? Bucket { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public string? OwnerTeam { get; set; }
    public string Classification { get; set; } = "confidential";
    public string? SecretHash { get; set; }
    public string? CodeSnippetRef { get; set; }
    public string RawEvidenceRef { get; set; } = "";
    public string SarifRef { get; set; } = "";
    public Guid CreatedByRun { get; set; }
    public bool InjectionFlag { get; set; }
    public string? Message { get; set; }
    /// <summary>Adapter attributes used by rule packs (never secret values), e.g. test_key_prefix, enclosing_symbol.</summary>
    public Dictionary<string, string> Attributes { get; set; } = [];
    /// <summary>Other locations folded into this finding (same fingerprint).</summary>
    public List<string> OtherLocations { get; set; } = [];

    public string Short => Fingerprint.Length >= 8 ? Fingerprint[..8] : Fingerprint;
}

public sealed class TriageDecision
{
    public Guid DecisionId { get; set; } = Guid.NewGuid();
    public string SchemaVersion { get; set; } = Schema.Version;
    public Guid FindingId { get; set; }
    public string? FixGroupKey { get; set; }
    public string Decision { get; set; } = "";
    public string Bucket { get; set; } = "";
    public string SeverityEffective { get; set; } = "";
    public string Reason { get; set; } = "";
    public double Confidence { get; set; }
    public List<Guid> EvidenceRefs { get; set; } = [];
    public string AgentId { get; set; } = "triage-agent";
    public string ModelId { get; set; } = "";
    public string ModelVersion { get; set; } = "";
    public string PromptVersion { get; set; } = "";
    public string RulePackVersion { get; set; } = "";
    public DateTime DecidedAt { get; set; } = DateTime.UtcNow;
    public bool NeedsHuman { get; set; }
    public string TraceId { get; set; } = "";
    public Guid? ContextPackId { get; set; }
    public Guid? RoutingId { get; set; }
    public string IdempotencyKey { get; set; } = "";
    public string? PolicyNotes { get; set; }
    public string? ProposedDecision { get; set; }
    public Guid RunId { get; set; }
}

public sealed class FixAttempt
{
    public Guid FixId { get; set; } = Guid.NewGuid();
    public List<Guid> FindingIds { get; set; } = [];
    public string? FixGroupKey { get; set; }
    public string FixerType { get; set; } = "";
    public string FixerVersion { get; set; } = "";
    public string Branch { get; set; } = "";
    public string? PrUrl { get; set; }
    public int AttemptNo { get; set; } = 1;
    public string VerificationResult { get; set; } = "pending";
    public List<Guid> VerificationEvidenceRefs { get; set; } = [];
    public int TokensIn { get; set; }
    public int TokensOut { get; set; }
    public decimal Cost { get; set; }
    public string IdempotencyKey { get; set; } = "";
    public Guid? ContextPackId { get; set; }
    public Guid? RoutingId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public Guid RunId { get; set; }
    public string? CommitSha { get; set; }
    public string? FailureReason { get; set; }
    public int Additions { get; set; }
    public int Deletions { get; set; }
    public int FilesChanged { get; set; }
}

public sealed class Evidence
{
    public Guid EvidenceId { get; set; } = Guid.NewGuid();
    public string Type { get; set; } = "";
    public string Uri { get; set; } = "";
    public string Hash { get; set; } = "";
    public List<Guid> RelatedIds { get; set; } = [];
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? TraceId { get; set; }
}

public sealed class RunRecord
{
    public Guid RunId { get; set; } = Guid.NewGuid();
    public string TriggerType { get; set; } = "pr";
    public string ScopeJson { get; set; } = "{}";
    public string BudgetJson { get; set; } = "{}";
    public int Tokens { get; set; }
    public decimal Cost { get; set; }
    public string Status { get; set; } = "running";
    public string ConfigSnapshot { get; set; } = "";
    public string TraceId { get; set; } = "";
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? EndedAt { get; set; }
    public string? SummaryJson { get; set; }
}

public sealed class ContextComponent
{
    public string Type { get; set; } = "";
    public string SourceRef { get; set; } = "";
    public int TokenCount { get; set; }
    public bool Included { get; set; } = true;
    public string? TrimReason { get; set; }
    [JsonIgnore] public string Content { get; set; } = "";
    [JsonIgnore] public bool Required { get; set; }
}

public sealed class ContextPack
{
    public Guid ContextPackId { get; set; } = Guid.NewGuid();
    public string SchemaVersion { get; set; } = Schema.Version;
    public Guid RunId { get; set; }
    public Guid? FindingId { get; set; }
    public string? FixGroupKey { get; set; }
    public string AgentId { get; set; } = "";
    public string Purpose { get; set; } = "";
    public string PromptId { get; set; } = "";
    public string PromptVersion { get; set; } = "";
    public List<ContextComponent> Components { get; set; } = [];
    public int TokenBudget { get; set; }
    public int TokenTotal { get; set; }
    public bool MaskingApplied { get; set; }
    public string ContentHash { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? ContentRef { get; set; }
    public bool OverBudget { get; set; }
    [JsonIgnore] public string SystemText { get; set; } = "";
    [JsonIgnore] public string UserText { get; set; } = "";
}

public sealed class RoutingDecision
{
    public Guid RoutingId { get; set; } = Guid.NewGuid();
    public Guid ContextPackId { get; set; }
    public Guid RunId { get; set; }
    public string TaskType { get; set; } = "";
    public string RequiredQuality { get; set; } = "standard";
    public int ContextTokens { get; set; }
    public int LatencyTargetMs { get; set; }
    public string BudgetRemainingJson { get; set; } = "{}";
    public List<string> CandidateModels { get; set; } = [];
    public string ChosenModelId { get; set; } = "";
    public string ModelVersion { get; set; } = "";
    public string Deployment { get; set; } = "";
    public string Tier { get; set; } = "";
    public string Reason { get; set; } = "";
    public bool FallbackUsed { get; set; }
    public string GatewayRequestId { get; set; } = "";
    public int TokensIn { get; set; }
    public int TokensOut { get; set; }
    public decimal Cost { get; set; }
    public int LatencyMs { get; set; }
    public DateTime DecidedAt { get; set; } = DateTime.UtcNow;
    public string TraceId { get; set; } = "";
    public string SpanId { get; set; } = "";
    public string Outcome { get; set; } = "pending";
    public int SchemaAttempts { get; set; }
}

public sealed class HumanTask
{
    public Guid TaskId { get; set; } = Guid.NewGuid();
    public Guid RunId { get; set; }
    public string Type { get; set; } = "";       // rotation | licence_decision | suppress_signoff | fix_failed | review
    public string Title { get; set; } = "";
    public string Details { get; set; } = "";
    public List<Guid> FindingIds { get; set; } = [];
    public string Owner { get; set; } = "[owner team]";
    public string Status { get; set; } = "open";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
