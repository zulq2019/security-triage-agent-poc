using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;

namespace SecAgent.Intake.Application.Steps;

/// <summary>Step order constants (gaps leave room for custom steps).</summary>
public static class IntakeStepOrder
{
    public const int Limits = 100, DuplicateFastPath = 200, Parse = 300, Claim = 400, StoreRaw = 500, CanonicalFindings = 600, Enqueue = 700;
}

/// <summary>Empty body → 400, over Intake:MaxBodyBytes → 413. Computes the body hash used by the later steps.</summary>
public sealed class PayloadLimitsStep(IOptions<IntakeOptions> options) : IIntakeStep
{
    public int Order => IntakeStepOrder.Limits;
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        var max = options.Value.MaxBodyBytes;
        if (ctx.Body.Length == 0) throw new IntakeRejectedException(400, "empty body");
        if (ctx.Body.Length > max) throw new IntakeRejectedException(413, $"payload is {ctx.Body.Length} bytes; the limit is {max} (Intake:MaxBodyBytes)");
        ctx.BodySha256 = Hashing.Sha256(ctx.Body.ToArray());
        return Task.FromResult<IntakeResult?>(null);
    }
}

/// <summary>Re-delivery of something already queued: answer from the ledger without re-parsing.</summary>
public sealed class DuplicateFastPathStep(IIntakeLedger ledger) : IIntakeStep
{
    public int Order => IntakeStepOrder.DuplicateFastPath;
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct) =>
        Task.FromResult(ledger.Get(ctx.Key) is { } prior && prior.Status != IntakeStatus.Claimed ? IntakeResult.Duplicate(prior, ctx.BodySha256) : null);
}

/// <summary>Selects the parser strategy for the format and parses (structure errors → 400/413/422 from the parser).</summary>
public sealed class ParseStep(IFindingParserRegistry parsers) : IIntakeStep
{
    public int Order => IntakeStepOrder.Parse;
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        if (!parsers.TryGet(ctx.Meta.Format, out var parser)) throw new IntakeRejectedException(404, $"unknown intake format '{ctx.Meta.Format}'");
        ctx.Parser = parser;
        ctx.Parsed = parser.Parse(ctx.Body, ctx.Meta);
        return Task.FromResult<IntakeResult?>(null);
    }
}

/// <summary>Claims the idempotency key atomically. Another delivery holding the key wins, unless its claim is older than the lease
/// (that attempt crashed before queueing): then this delivery resumes it. Writes after this point are idempotent
/// (deterministic paths, write-once store, queue dedupe by MessageId).</summary>
public sealed class ClaimStep(IIntakeLedger ledger, IOptions<IntakeOptions> options, TimeProvider clock) : IIntakeStep
{
    public int Order => IntakeStepOrder.Claim;
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        var parsed = ctx.Require(ctx.Parsed, "parse outcome");
        var now = clock.GetUtcNow().UtcDateTime;
        var record = new IntakeRecord
        {
            IntakeId = Guid.NewGuid().ToString("N"), Key = ctx.Key, BodySha256 = ctx.BodySha256, Meta = ctx.Meta, Findings = parsed.Findings.Count,
            ScannerVersion = parsed.ToolVersion, ReceivedAt = now, UpdatedAt = now,
        };
        if (!ledger.TryClaim(record, out var existing))
        {
            var stale = now - existing.UpdatedAt > TimeSpan.FromSeconds(options.Value.ClaimLeaseSeconds);
            if (existing.Status != IntakeStatus.Claimed || existing.BodySha256 != ctx.BodySha256 || !stale)
                return Task.FromResult<IntakeResult?>(IntakeResult.Duplicate(existing, ctx.BodySha256));
            record = existing;
            ledger.Update(record);   // renew the lease
        }
        ctx.Record = record;
        return Task.FromResult<IntakeResult?>(null);
    }
}

/// <summary>Stores the raw payload (redacted by its parser) write-once at intake/{repo}/{sha}/{scanner}-{run}.{ext}.</summary>
public sealed class StoreRawStep(IRawFindingStore raw) : IIntakeStep
{
    public int Order => IntakeStepOrder.StoreRaw;
    public static string BasePath(IntakeMetadata m) => $"intake/{m.Repo}/{m.HeadSha}/{m.Scanner}-{m.RunId}";
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        var parser = ctx.Require(ctx.Parser, "parser");
        ctx.Raw = raw.Put($"{BasePath(ctx.Meta)}.{parser.RawFileExtension}", parser.Redact(ctx.Body, ctx.Require(ctx.Parsed, "parse outcome")));
        return Task.FromResult<IntakeResult?>(null);
    }
}

/// <summary>Stamps the parsed findings with intake provenance and stable ids, validates each against the canonical schema (422), and stores
/// them next to the raw file as .canonical.json.</summary>
public sealed class CanonicalFindingsStep(IRawFindingStore raw, IFindingSchemaValidator validator, IIntakeLedger ledger) : IIntakeStep
{
    public int Order => IntakeStepOrder.CanonicalFindings;
    public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        var parsed = ctx.Require(ctx.Parsed, "parse outcome");
        var record = ctx.Require(ctx.Record, "claimed record");
        var rawRef = ctx.Require(ctx.Raw, "raw reference");
        var intakeId = Guid.Parse(record.IntakeId);
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
        var canonical = raw.Put($"{StoreRawStep.BasePath(ctx.Meta)}.canonical.json", Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parsed.Findings, Schema.JsonIndented)));
        record.RawUri = rawRef.Uri; record.RawHash = rawRef.Hash; record.CanonicalUri = canonical.Uri;
        record.Detail = parsed.Notes.Count > 0 ? string.Join(" | ", parsed.Notes) : null;
        ledger.Update(record);
        return Task.FromResult<IntakeResult?>(null);
    }

    static Guid StableId(string intakeId, string fingerprint, int i) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes($"{intakeId}|{fingerprint}|{i}")).AsSpan(0, 16));
}

/// <summary>Asks for a pipeline run (<see cref="IRunStarter"/> port), marks the record queued and returns 202.</summary>
public sealed class EnqueueRunStep(IRunStarter runs, IIntakeLedger ledger, ILogger<EnqueueRunStep> log) : IIntakeStep
{
    public int Order => IntakeStepOrder.Enqueue;
    public async Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct)
    {
        var parsed = ctx.Require(ctx.Parsed, "parse outcome");
        var record = ctx.Require(ctx.Record, "claimed record");
        var rawRef = ctx.Require(ctx.Raw, "raw reference");
        var m = ctx.Meta;
        var ticket = await runs.EnqueueAsync(new IntakeRunRequest(record.IntakeId, ctx.Key, m.Repo, m.PrNumber, m.Ref, m.HeadSha, m.Scanner, m.Mode, parsed.Findings.Count), ct);
        ctx.Ticket = ticket;
        record.Status = IntakeStatus.Queued; record.RunTicket = ticket.Ticket;
        ledger.Update(record);
        log.LogInformation("intake {IntakeId} via {Via}: {Repo}@{Sha} {Scanner} ({Format}) → {Findings} findings, queued {Ticket}",
            record.IntakeId, ctx.Via, m.Repo, m.HeadSha[..7], m.Scanner, m.Format, parsed.Findings.Count, ticket.Ticket);
        return new IntakeResult(202, new
        {
            status = "accepted", intake_id = record.IntakeId, idempotency_key = ctx.Key, mode = m.Mode, findings = parsed.Findings.Count,
            by_issue_type = parsed.Findings.GroupBy(f => f.IssueType).ToDictionary(g => g.Key, g => g.Count()),
            tool = parsed.ToolName, tool_version = parsed.ToolVersion, raw = rawRef.Uri, raw_sha256 = rawRef.Hash, run_ticket = ticket.Ticket, notes = parsed.Notes,
        });
    }
}
