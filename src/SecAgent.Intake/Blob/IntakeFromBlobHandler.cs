using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Application;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;

namespace SecAgent.Intake.Blob;

/// <summary>Entry point for "a blob was created" (Event Grid BlobCreated in Azure, the local drop folder in dev).</summary>
public interface IBlobIntakeHandler
{
    Task<IntakeResult> HandleAsync(BlobCreatedEvent evt, CancellationToken ct);
}

/// <summary>Blob path: GitHub Action uploads the SARIF to a private intake container (OIDC → Azure, no shared secret) → Event Grid
/// BlobCreated → this handler → the same <see cref="IIntakeAcceptor"/> as the webhook. Trust comes from who can write to the container
/// (RBAC) and from Event Grid delivery auth (Entra ID-protected webhook or an Azure Function trigger), so no HMAC check here.
/// The Event Grid webhook endpoint itself (subscription validation handshake + Entra token check) is a TODO: see docs/intake.md.</summary>
public sealed class IntakeFromBlobHandler(IOptions<IntakeOptions> options, IIntakeMetadataReader metadata, IIntakeAcceptor acceptor,
    IBlobReader reader, IFindingParserRegistry parsers) : IBlobIntakeHandler
{
    public async Task<IntakeResult> HandleAsync(BlobCreatedEvent evt, CancellationToken ct)
    {
        var o = options.Value;
        if (evt.ContentLength > o.MaxBodyBytes) return IntakeResult.Rejected(413, $"blob is {evt.ContentLength} bytes; the limit is {o.MaxBodyBytes}");
        var format = evt.Metadata.TryGetValue("format", out var fm) && fm.Length > 0 ? fm.ToLowerInvariant()
            : parsers.InferFormat(evt.Name) ?? o.DefaultBlobFormat;
        IntakeMetadata meta;
        try { meta = metadata.Read(format, evt.Metadata); }
        catch (IntakeRejectedException e) { return IntakeResult.Rejected(e.StatusCode, e.Message); }
        var body = await reader.ReadAsync(evt, o.MaxBodyBytes, ct);
        return await acceptor.AcceptAsync(meta, body, "blob", ct);
    }
}
