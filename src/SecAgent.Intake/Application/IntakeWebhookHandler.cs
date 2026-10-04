using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Application;

/// <summary>Application service behind POST /api/intake/{format}: availability → authenticate → metadata → accept pipeline.
/// HTTP specifics (reading the body under the size limit) stay in the endpoint; this class has no ASP.NET dependency.</summary>
public interface IIntakeWebhookHandler
{
    long MaxBodyBytes { get; }
    /// <summary>Checks that can run before the body is read: 503 (disabled / secret not configured), 413 (declared length over the limit).</summary>
    IntakeResult? Precheck(long? declaredLength);
    Task<IntakeResult> HandleAsync(string format, IReadOnlyDictionary<string, string> headers, ReadOnlyMemory<byte> body, CancellationToken ct);
}

public sealed class IntakeWebhookHandler(IOptions<IntakeOptions> options, IIntakeSecretProvider secrets, IIntakeAuthenticator auth,
    IIntakeMetadataReader metadata, IIntakeAcceptor acceptor) : IIntakeWebhookHandler
{
    public long MaxBodyBytes => options.Value.MaxBodyBytes;

    public IntakeResult? Precheck(long? declaredLength)
    {
        var o = options.Value;
        if (!o.Enabled) return IntakeResult.Rejected(503, "intake is disabled (Intake:Enabled)");
        if (secrets.GetSecret() == null) return IntakeResult.Rejected(503, $"intake is not configured: set {o.HmacSecretEnv}");
        if (declaredLength is { } len && len > o.MaxBodyBytes) return IntakeResult.Rejected(413, $"payload is {len} bytes; the limit is {o.MaxBodyBytes}");
        return null;
    }

    public async Task<IntakeResult> HandleAsync(string format, IReadOnlyDictionary<string, string> headers, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        if (Precheck(null) is { } unavailable) return unavailable;
        var a = auth.Authenticate(format, headers, body.Span);
        if (!a.Ok) return IntakeResult.Rejected(401, "unauthorized: " + a.Error);
        IntakeMetadata meta;
        try { meta = metadata.Read(format, headers); }
        catch (IntakeRejectedException e) { return IntakeResult.Rejected(e.StatusCode, e.Message); }
        return await acceptor.AcceptAsync(meta, body, "webhook", ct);
    }
}
