using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecAgent.Agents;
using SecAgent.Core;

namespace SecAgent.Intake;

public sealed record IntakeResult(int StatusCode, object Body);

/// <summary>The intake pipeline, shared by the webhook and the Blob path (authentication happens before, at the edge):
/// validate metadata → parse + validate (SARIF 2.1.0 / rapid JSON) → canonical-schema check → claim idempotency key → store raw (redacted) +
/// canonical findings (write-once) → enqueue a run. Nothing is stored for a rejected payload.</summary>
public sealed partial class IntakeService(IntakeOptions options, IEnumerable<IFindingParser> parsers, IRawFindingStore raw, IIntakeLedger ledger,
    IRunStarter runs, SchemaValidator validator, Action<string>? log = null)
{
    readonly Dictionary<string, IFindingParser> _parsers = parsers.ToDictionary(p => p.Format, StringComparer.OrdinalIgnoreCase);
    public IntakeOptions Options => options;
    public IIntakeLedger Ledger => ledger;
    public IRawFindingStore Raw => raw;

    [GeneratedRegex(@"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9._-]{1,100}$")] private static partial Regex RepoRe();
    [GeneratedRegex(@"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")] private static partial Regex ShaRe();
    [GeneratedRegex(@"^[a-z0-9][a-z0-9_-]{0,39}$")] private static partial Regex ScannerRe();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")] private static partial Regex RunIdRe();
    [GeneratedRegex(@"^[A-Za-z0-9._/@+-]{1,200}$")] private static partial Regex RefRe();

    /// <summary>Header names used by the webhook (and blob metadata keys without the X-SecAgent- prefix).</summary>
    public static class Headers
    {
        public const string Repo = "X-SecAgent-Repo", Pr = "X-SecAgent-Pr", Ref = "X-SecAgent-Ref", HeadSha = "X-SecAgent-Head-Sha",
            Scanner = "X-SecAgent-Scanner", RunId = "X-SecAgent-Run-Id";
    }

    /// <summary>Builds and validates metadata from header-like key/values ("X-SecAgent-Repo" or "repo"). Throws 400 on anything malformed.</summary>
    public IntakeMetadata ReadMetadata(string format, IReadOnlyDictionary<string, string> values)
    {
        string? V(string header) => values.TryGetValue(header, out var v) || values.TryGetValue(header["X-SecAgent-".Length..].Replace("-", "_").ToLowerInvariant(), out v)
            || values.TryGetValue(header["X-SecAgent-".Length..].ToLowerInvariant(), out v) ? v?.Trim() : null;
        if (!_parsers.ContainsKey(format)) throw new IntakeRejectedException(404, $"unknown intake format '{format}' (expected {string.Join(" | ", _parsers.Keys)})");
        var repo = V(Headers.Repo) ?? throw Bad($"{Headers.Repo} is required (owner/name)");
        if (!RepoRe().IsMatch(repo)) throw Bad($"{Headers.Repo} must look like owner/name");
        if (!options.RepoAllowed(repo)) throw new IntakeRejectedException(403, $"repo {repo} is not in Intake:AllowedRepos");
        var sha = (V(Headers.HeadSha) ?? throw Bad($"{Headers.HeadSha} is required (full commit SHA)")).ToLowerInvariant();
        if (!ShaRe().IsMatch(sha)) throw Bad($"{Headers.HeadSha} must be a full 40- or 64-character hex commit SHA");
        var scanner = (V(Headers.Scanner) ?? throw Bad($"{Headers.Scanner} is required")).ToLowerInvariant();
        if (!ScannerRe().IsMatch(scanner) || !options.AllowedScanners.Contains(scanner, StringComparer.OrdinalIgnoreCase))
            throw Bad($"{Headers.Scanner} '{scanner}' is not accepted (Intake:AllowedScanners: {string.Join(", ", options.AllowedScanners)})");
        var runId = V(Headers.RunId) ?? throw Bad($"{Headers.RunId} is required (e.g. <github.run_id>-<github.run_attempt>)");
        if (!RunIdRe().IsMatch(runId)) throw Bad($"{Headers.RunId} has invalid characters");
        int? pr = null;
        if (V(Headers.Pr) is { Length: > 0 } p)
        {
            if (!int.TryParse(p, out var n) || n <= 0) throw Bad($"{Headers.Pr} must be a positive integer (omit it for backlog/branch scans)");
            pr = n;
        }
        var gitRef = V(Headers.Ref) is { Length: > 0 } r ? r : null;
        if (gitRef != null && (!RefRe().IsMatch(gitRef) || gitRef.Contains(".."))) throw Bad($"{Headers.Ref} is not a valid branch name");
        return new IntakeMetadata { Format = format.ToLowerInvariant(), Repo = repo, PrNumber = pr, Ref = gitRef, HeadSha = sha, Scanner = scanner, RunId = runId };
    }

    public async Task<IntakeResult> AcceptAsync(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via, CancellationToken ct)
    {
        try { return await AcceptCoreAsync(meta, body, via, ct); }
        catch (IntakeRejectedException e)
        {
            log?.Invoke($"intake rejected ({e.StatusCode}) {meta.Repo}@{meta.HeadSha[..7]} {meta.Scanner} run {meta.RunId}: {e.Message}");
            return Reject(e.StatusCode, e.Message);
        }
    }

    async Task<IntakeResult> AcceptCoreAsync(IntakeMetadata meta, ReadOnlyMemory<byte> body, string via, CancellationToken ct)
    {
        if (body.Length == 0) throw new IntakeRejectedException(400, "empty body");
        if (body.Length > options.MaxBodyBytes) throw new IntakeRejectedException(413, $"payload is {body.Length} bytes; the limit is {options.MaxBodyBytes} (Intake:MaxBodyBytes)");
        var bodySha = Hashing.Sha256(body.ToArray());
        var key = meta.IdempotencyKey;

        // Fast path for a re-delivery of something already queued (no re-parse).
        if (ledger.Get(key) is { } prior && prior.Status != IntakeStatus.Claimed) return Duplicate(prior, bodySha);

        var parser = _parsers[meta.Format];
        var parsed = parser.Parse(body, meta);
        var intakeId = Guid.NewGuid();
        var record = new IntakeRecord { IntakeId = intakeId.ToString("N"), Key = key, BodySha256 = bodySha, Meta = meta, Findings = parsed.Findings.Count, ScannerVersion = parsed.ToolVersion };
        if (!ledger.TryClaim(record, out var existing))
        {
            // Another delivery holds the key. Only a claim older than the lease (that attempt crashed before queueing) is resumed;
            // a fresh claim means a concurrent identical delivery is in progress, so this one is the duplicate.
            var stale = DateTime.UtcNow - existing.UpdatedAt > TimeSpan.FromSeconds(options.ClaimLeaseSeconds);
            if (existing.Status != IntakeStatus.Claimed || existing.BodySha256 != bodySha || !stale) return Duplicate(existing, bodySha);
            record = existing;   // resume: writes are idempotent (deterministic paths, write-once store, queue dedupe by MessageId)
            intakeId = Guid.Parse(record.IntakeId);
            ledger.Update(record);   // renew the lease
        }

        // Raw (redacted) + canonical findings, write-once. Paths are deterministic so a resumed attempt rewrites identical bytes.
        var basePath = $"intake/{meta.Repo}/{meta.HeadSha}/{meta.Scanner}-{meta.RunId}";
        var rawRef = raw.Put($"{basePath}.{(meta.Format == IntakeFormats.Sarif ? "sarif.json" : "rapid.json")}", parser.Redact(body, parsed));
        for (int i = 0; i < parsed.Findings.Count; i++)
        {
            var f = parsed.Findings[i];
            f.RawEvidenceRef = rawRef.Uri; f.CreatedByRun = intakeId;
            f.SarifRef = $"intake:{record.IntakeId}#{(string.IsNullOrEmpty(f.SarifRef) ? i.ToString() : f.SarifRef)}";
            f.FindingId = StableId(record.IntakeId, f.Fingerprint, i);
            f.Attributes[ExternalFindingPolicy.IntakeIdAttribute] = record.IntakeId;
            if (validator.ValidateFinding(f) is { } err)
                throw new IntakeRejectedException(422, $"finding {i} ({f.ScannerRuleId}) failed canonical schema validation: {err}");
        }
        var canonical = raw.Put($"{basePath}.canonical.json", Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parsed.Findings, Schema.JsonIndented)));
        record.RawUri = rawRef.Uri; record.RawHash = rawRef.Hash; record.CanonicalUri = canonical.Uri;
        record.Detail = parsed.Notes.Count > 0 ? string.Join(" | ", parsed.Notes) : null;
        ledger.Update(record);

        var ticket = await runs.EnqueueAsync(new IntakeRunRequest(record.IntakeId, key, meta.Repo, meta.PrNumber, meta.Ref, meta.HeadSha, meta.Scanner, meta.Mode, parsed.Findings.Count), ct);
        record.Status = IntakeStatus.Queued; record.RunTicket = ticket.Ticket;
        ledger.Update(record);
        log?.Invoke($"intake {record.IntakeId} via {via}: {meta.Repo}@{meta.HeadSha[..7]} {meta.Scanner} ({meta.Format}) → {parsed.Findings.Count} findings, queued {ticket.Ticket}");
        return new IntakeResult(202, new
        {
            status = "accepted", intake_id = record.IntakeId, idempotency_key = key, mode = meta.Mode, findings = parsed.Findings.Count,
            by_issue_type = parsed.Findings.GroupBy(f => f.IssueType).ToDictionary(g => g.Key, g => g.Count()),
            tool = parsed.ToolName, tool_version = parsed.ToolVersion, raw = rawRef.Uri, raw_sha256 = rawRef.Hash, run_ticket = ticket.Ticket, notes = parsed.Notes,
        });
    }

    static Guid StableId(string intakeId, string fingerprint, int i) =>
        new(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes($"{intakeId}|{fingerprint}|{i}")).AsSpan(0, 16));

    static IntakeResult Duplicate(IntakeRecord existing, string bodySha) => existing.BodySha256 == bodySha
        ? new IntakeResult(200, new { status = "duplicate", intake_id = existing.IntakeId, idempotency_key = existing.Key, previous_status = existing.Status, run_ticket = existing.RunTicket })
        : Reject(409, "a different payload was already accepted for this repo + head SHA + scanner + run id; send a new run id (include github.run_attempt)");

    static IntakeResult Reject(int code, string error) => new(code, new { status = "rejected", error });
    static IntakeRejectedException Bad(string m) => new(400, m);
}
