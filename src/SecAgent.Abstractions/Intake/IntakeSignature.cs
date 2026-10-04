using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SecAgent.Abstractions.Intake;

/// <summary>Header names of the webhook protocol (blob metadata uses the same names without the X-SecAgent- prefix, snake_case).</summary>
public static class IntakeHeaders
{
    public const string Repo = "X-SecAgent-Repo", Pr = "X-SecAgent-Pr", Ref = "X-SecAgent-Ref", HeadSha = "X-SecAgent-Head-Sha",
        Scanner = "X-SecAgent-Scanner", RunId = "X-SecAgent-Run-Id";
    public const string Timestamp = "X-SecAgent-Timestamp", Signature = "X-SecAgent-Signature-256";
    public const string Prefix = "X-SecAgent-";
}

/// <summary>Request signing, scheme "secagent-intake-v1" (GitHub-webhook style, but the metadata is signed too, not just the body):
/// <code>
/// X-SecAgent-Timestamp:     unix seconds
/// X-SecAgent-Signature-256: sha256=hex( HMAC-SHA256(secret, canonical) )
/// canonical = "secagent-intake-v1\n{timestamp}\n{format}\n{repo}\n{pr}\n{ref}\n{head_sha}\n{scanner}\n{run_id}\n{sha256hex(body)}"
/// </code>
/// Header values are used exactly as sent (missing = empty string); format is the URL segment, lower case.
/// Pure protocol functions shared by the server-side authenticator and clients (tests, tools); the bash/python step in
/// .github/workflows/examples/blackduck-push.yml is the same algorithm.</summary>
public static class IntakeSignature
{
    public const string Scheme = "secagent-intake-v1";
    static readonly string[] Signed = [IntakeHeaders.Repo, IntakeHeaders.Pr, IntakeHeaders.Ref, IntakeHeaders.HeadSha, IntakeHeaders.Scanner, IntakeHeaders.RunId];

    public static string Canonical(string format, IReadOnlyDictionary<string, string> headers, string timestamp, ReadOnlySpan<byte> body) =>
        string.Join('\n', new[] { Scheme, timestamp, format.ToLowerInvariant() }
            .Concat(Signed.Select(h => headers.TryGetValue(h, out var v) ? v : ""))
            .Append(Convert.ToHexStringLower(SHA256.HashData(body))));

    public static string Sign(string secret, string format, IReadOnlyDictionary<string, string> headers, string timestamp, ReadOnlySpan<byte> body)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return "sha256=" + Convert.ToHexStringLower(h.ComputeHash(Encoding.UTF8.GetBytes(Canonical(format, headers, timestamp, body))));
    }

    /// <summary>The metadata header values a client sends for this metadata.</summary>
    public static Dictionary<string, string> HeadersFor(IntakeMetadata m)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [IntakeHeaders.Repo] = m.Repo, [IntakeHeaders.HeadSha] = m.HeadSha, [IntakeHeaders.Scanner] = m.Scanner, [IntakeHeaders.RunId] = m.RunId,
        };
        if (m.PrNumber is { } pr) d[IntakeHeaders.Pr] = pr.ToString(CultureInfo.InvariantCulture);
        if (m.Ref is { } r) d[IntakeHeaders.Ref] = r;
        return d;
    }
}
