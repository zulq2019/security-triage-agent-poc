using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SecAgent.Intake;

/// <summary>Request signing, scheme "secagent-intake-v1" (GitHub-webhook style, but the metadata is signed too, not just the body):
/// <code>
/// X-SecAgent-Timestamp:     unix seconds
/// X-SecAgent-Signature-256: sha256=hex( HMAC-SHA256(secret, canonical) )
/// canonical = "secagent-intake-v1\n{timestamp}\n{format}\n{repo}\n{pr}\n{ref}\n{head_sha}\n{scanner}\n{run_id}\n{sha256hex(body)}"
/// </code>
/// Header values are used exactly as sent (missing = empty string); format is the URL segment, lower case.
/// Signing the metadata means a captured body cannot be replayed against another repo/PR/commit, and the timestamp window plus the
/// idempotency key make replays inside the window a no-op.
/// <para>Option (documented TODO in docs/intake.md): GitHub OIDC instead of a shared secret: the workflow requests an id-token
/// (permissions: id-token: write, audience = our intake URL); a second <see cref="IIntakeAuthenticator"/> validates the JWT against
/// https://token.actions.githubusercontent.com/.well-known/jwks, checks aud, iss, and that the repository / sha / run_id claims
/// equal the signed headers. No shared secret to rotate.</para></summary>
public sealed class HmacIntakeAuthenticator(Func<string?> secret, int toleranceSeconds = 300) : IIntakeAuthenticator
{
    public const string Scheme = "secagent-intake-v1";
    public const string SignatureHeader = "X-SecAgent-Signature-256";
    public const string TimestampHeader = "X-SecAgent-Timestamp";
    static readonly string[] Signed = [IntakeService.Headers.Repo, IntakeService.Headers.Pr, IntakeService.Headers.Ref, IntakeService.Headers.HeadSha,
        IntakeService.Headers.Scanner, IntakeService.Headers.RunId];

    public static string Canonical(string format, IReadOnlyDictionary<string, string> headers, string timestamp, ReadOnlySpan<byte> body) =>
        string.Join('\n', new[] { Scheme, timestamp, format.ToLowerInvariant() }
            .Concat(Signed.Select(h => headers.TryGetValue(h, out var v) ? v : ""))
            .Append(Convert.ToHexStringLower(SHA256.HashData(body))));

    public static string Sign(string secret, string format, IReadOnlyDictionary<string, string> headers, string timestamp, ReadOnlySpan<byte> body)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return "sha256=" + Convert.ToHexStringLower(h.ComputeHash(Encoding.UTF8.GetBytes(Canonical(format, headers, timestamp, body))));
    }

    /// <summary>The header values a client sends for this metadata (used by tests and the local push tool).</summary>
    public static Dictionary<string, string> HeadersFor(IntakeMetadata m)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [IntakeService.Headers.Repo] = m.Repo, [IntakeService.Headers.HeadSha] = m.HeadSha, [IntakeService.Headers.Scanner] = m.Scanner, [IntakeService.Headers.RunId] = m.RunId,
        };
        if (m.PrNumber is { } pr) d[IntakeService.Headers.Pr] = pr.ToString(CultureInfo.InvariantCulture);
        if (m.Ref is { } r) d[IntakeService.Headers.Ref] = r;
        return d;
    }

    public IntakeAuthResult Authenticate(string format, IReadOnlyDictionary<string, string> headers, ReadOnlySpan<byte> body, DateTimeOffset now)
    {
        var key = secret();
        if (string.IsNullOrEmpty(key)) return IntakeAuthResult.Fail("intake HMAC secret is not configured on the server");
        if (!headers.TryGetValue(SignatureHeader, out var sig) || !sig.Trim().StartsWith("sha256=", StringComparison.OrdinalIgnoreCase))
            return IntakeAuthResult.Fail($"missing or malformed {SignatureHeader} (expected sha256=<hex>)");
        if (!headers.TryGetValue(TimestampHeader, out var ts) || !long.TryParse(ts, NumberStyles.None, CultureInfo.InvariantCulture, out var unix))
            return IntakeAuthResult.Fail($"missing or malformed {TimestampHeader} (unix seconds)");
        var skew = Math.Abs(now.ToUnixTimeSeconds() - unix);
        if (skew > toleranceSeconds) return IntakeAuthResult.Fail($"timestamp outside the {toleranceSeconds}s window (skew {skew}s)");
        var expected = Encoding.ASCII.GetBytes(Sign(key, format, headers, ts, body));
        var given = Encoding.ASCII.GetBytes(sig.Trim().ToLowerInvariant());
        // Constant-time comparison: no early exit on the first differing byte.
        return CryptographicOperations.FixedTimeEquals(expected, given) ? IntakeAuthResult.Success : IntakeAuthResult.Fail("signature mismatch");
    }
}
