using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Security;

/// <summary>Server side of <see cref="IntakeSignature"/> (scheme secagent-intake-v1): constant-time HMAC check plus a timestamp window.
/// Time comes from the injected <see cref="TimeProvider"/>, the secret from <see cref="IIntakeSecretProvider"/>.
/// Signing the metadata means a captured body cannot be replayed against another repo/PR/commit; the window plus the idempotency key
/// make replays inside the window a no-op.
/// <para>Option (documented TODO in docs/intake.md): GitHub OIDC instead of a shared secret: a second <see cref="IIntakeAuthenticator"/>
/// validates the Actions id-token against https://token.actions.githubusercontent.com/.well-known/jwks, checks aud, iss, and that the
/// repository / sha / run_id claims equal the signed headers. Register it instead of this class; nothing else changes.</para></summary>
public sealed class HmacIntakeAuthenticator(IIntakeSecretProvider secrets, IOptions<IntakeOptions> options, TimeProvider clock) : IIntakeAuthenticator
{
    public IntakeAuthResult Authenticate(string format, IReadOnlyDictionary<string, string> headers, ReadOnlySpan<byte> body)
    {
        var key = secrets.GetSecret();
        var tolerance = options.Value.TimestampToleranceSeconds;
        if (string.IsNullOrEmpty(key)) return IntakeAuthResult.Fail("intake HMAC secret is not configured on the server");
        if (!headers.TryGetValue(IntakeHeaders.Signature, out var sig) || !sig.Trim().StartsWith("sha256=", StringComparison.OrdinalIgnoreCase))
            return IntakeAuthResult.Fail($"missing or malformed {IntakeHeaders.Signature} (expected sha256=<hex>)");
        if (!headers.TryGetValue(IntakeHeaders.Timestamp, out var ts) || !long.TryParse(ts, NumberStyles.None, CultureInfo.InvariantCulture, out var unix))
            return IntakeAuthResult.Fail($"missing or malformed {IntakeHeaders.Timestamp} (unix seconds)");
        var skew = Math.Abs(clock.GetUtcNow().ToUnixTimeSeconds() - unix);
        if (skew > tolerance) return IntakeAuthResult.Fail($"timestamp outside the {tolerance}s window (skew {skew}s)");
        var expected = Encoding.ASCII.GetBytes(IntakeSignature.Sign(key, format, headers, ts, body));
        var given = Encoding.ASCII.GetBytes(sig.Trim().ToLowerInvariant());
        // Constant-time comparison: no early exit on the first differing byte.
        return CryptographicOperations.FixedTimeEquals(expected, given) ? IntakeAuthResult.Success : IntakeAuthResult.Fail("signature mismatch");
    }
}

/// <summary>Adapter: reads the secret from the environment variable named by Intake:HmacSecretEnv (an App Service Key Vault reference
/// resolves into the same variable in Azure). Replace with a SecretClient-based provider to read Key Vault directly.</summary>
public sealed class EnvironmentIntakeSecretProvider(IOptions<IntakeOptions> options) : IIntakeSecretProvider
{
    public string? GetSecret() => Environment.GetEnvironmentVariable(options.Value.HmacSecretEnv) is { Length: > 0 } s ? s : null;
}
