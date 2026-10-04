namespace SecAgent.Abstractions.Agents;

// Message contracts between agent containers (bodies of the worker host's AgentMessage envelope). DTOs only, no behaviour.
// Queue names and who may send what live in deploy/agents.json (mirrored by infra/agents.bicep in PR #3).

public static class AgentMessageTypes
{
    public const string ScanRequest = "scan-request";
    public const string StepRequest = "step-request";
    public const string WorkResult = "work-result";
    public const string RunEvent = "run-event";
}

/// <summary>Ask the scanner agent to scan one ref of a repository. <paramref name="LocalPath"/> is for local synthetic demos only and is
/// accepted only under the scanner's configured Agent:Scanner:LocalReposRoot.</summary>
public sealed record ScanRequest(Guid RunId, string Repo, string Ref, string Label = "head", string? LocalPath = null);

/// <summary>Generic step request for the triage / fixer / verifier queues (payload reference only: large data stays in Blob, claim check).</summary>
public sealed record StepRequest(Guid RunId, string Step, string? PayloadRef = null);

public static class WorkResultStatus
{
    public const string Completed = "completed";
    public const string Failed = "failed";
    /// <summary>The step still runs inside the orchestrator's in-process workflow (POC); the container acknowledged the message.</summary>
    public const string Deferred = "deferred";
}

/// <summary>Reply on the results queue.</summary>
public sealed record WorkResult(Guid RunId, string Agent, string Status, string? Detail = null, IReadOnlyDictionary<string, string>? Data = null);
