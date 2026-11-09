using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Application;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Security;

/// <summary>Decides whether a read of intake records (GET /api/intake) is allowed. Asks every configured
/// <see cref="IIntakeReadCredential"/>; the first grant wins. No credential configured → 503 (the listing never runs open), configured
/// but none presented or valid → 401.</summary>
public interface IIntakeReadAuthorizer
{
    /// <summary>Null when the read is allowed; otherwise the 401 / 503 result to return.</summary>
    IntakeResult? Authorize(IntakeReadRequest request);
}

public sealed class IntakeReadAuthorizer(IEnumerable<IIntakeReadCredential> credentials, IOptions<IntakeOptions> options) : IIntakeReadAuthorizer
{
    public IntakeResult? Authorize(IntakeReadRequest request)
    {
        var configured = credentials.Where(c => c.IsConfigured).ToList();
        if (configured.Count == 0)
            return IntakeResult.Rejected(503, $"intake listing is not configured: set {options.Value.AdminTokenEnv} (Authorization: Bearer) or {options.Value.HmacSecretEnv} (signed request)");
        string? error = null;
        foreach (var c in configured)
        {
            if (c.Check(request) is not { } r) continue;
            if (r.Ok) return null;
            error ??= $"{c.Name}: {r.Error}";
        }
        return IntakeResult.Rejected(401, "unauthorized: " + (error ?? "credentials required (" + string.Join(" or ", configured.Select(c => c.Name)) + ")"));
    }
}

/// <summary>Where the intake admin token comes from (environment variable named by Intake:AdminTokenEnv; a Key Vault reference in Azure).</summary>
public interface IIntakeAdminTokenProvider
{
    string? GetToken();
}

public sealed class EnvironmentIntakeAdminTokenProvider(IOptions<IntakeOptions> options) : IIntakeAdminTokenProvider
{
    public string? GetToken() => Environment.GetEnvironmentVariable(options.Value.AdminTokenEnv) is { Length: > 0 } t ? t : null;
}

/// <summary>Operators / tools: <c>Authorization: Bearer &lt;admin token&gt;</c>. Compared in constant time (hashes of equal length).</summary>
public sealed class AdminTokenReadCredential(IIntakeAdminTokenProvider tokens) : IIntakeReadCredential
{
    public string Name => "admin token";
    public bool IsConfigured => tokens.GetToken() != null;

    public IntakeAuthResult? Check(IntakeReadRequest request)
    {
        if (!request.Headers.TryGetValue("Authorization", out var auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var expected = tokens.GetToken();
        if (expected == null) return IntakeAuthResult.Fail("not configured");
        var ok = CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(auth[7..].Trim())), SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
        return ok ? IntakeAuthResult.Success : IntakeAuthResult.Fail("invalid token");
    }
}

/// <summary>CI tools that already hold the intake HMAC secret: the same secagent-intake-v1 signature, over the scope
/// <see cref="Scope"/> instead of a payload format and an empty body (timestamp window applies). Holders of the secret can already push
/// findings, so reading the intake metadata adds no privilege. Disable with Intake:ListingAcceptsHmac=false.</summary>
public sealed class HmacSignedReadCredential(IIntakeAuthenticator auth, IIntakeSecretProvider secrets, IOptions<IntakeOptions> options) : IIntakeReadCredential
{
    /// <summary>Signed in place of the format. Never a parser format (those are letters, digits and dashes), so a payload signature
    /// cannot be reused as a read signature.</summary>
    public const string Scope = "_list";
    public string Name => "signed request";
    public bool IsConfigured => options.Value.ListingAcceptsHmac && secrets.GetSecret() != null;

    public IntakeAuthResult? Check(IntakeReadRequest request) =>
        request.Headers.ContainsKey(IntakeHeaders.Signature) ? auth.Authenticate(Scope, request.Headers, ReadOnlySpan<byte>.Empty) : null;
}

/// <summary>Dev convenience, off unless Intake:ListingAllowsLoopback=true: a caller on this machine with no proxy headers may list
/// without credentials. Do not enable behind a tunnel or reverse proxy on the same host (it would make the listing public).</summary>
public sealed class LoopbackReadCredential(IOptions<IntakeOptions> options) : IIntakeReadCredential
{
    public string Name => "loopback (dev)";
    public bool IsConfigured => options.Value.ListingAllowsLoopback;
    public IntakeAuthResult? Check(IntakeReadRequest request) => request.IsDirectLoopback ? IntakeAuthResult.Success : null;
}
