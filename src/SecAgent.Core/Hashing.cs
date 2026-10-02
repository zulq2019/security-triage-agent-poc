using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecAgent.Core;

public static class Hashing
{
    public static string Sha256(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    public static string Sha256(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));

    /// <summary>HMAC-SHA256 of a secret value. The key stands in for a Key Vault-held HMAC key (section 5.10).</summary>
    public static string Hmac(string value)
    {
        var key = Environment.GetEnvironmentVariable("SECAGENT_HMAC_KEY");
        if (string.IsNullOrEmpty(key)) throw new InvalidOperationException("SECAGENT_HMAC_KEY is not set (load ~/.secagent/secagent.env)");
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return "hmac:" + Convert.ToHexStringLower(h.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
}

/// <summary>Fingerprints per PRD section 7.10 (no line numbers).</summary>
public static class Fingerprints
{
    static string N(string? s) => (s ?? "").Trim().ToLowerInvariant();
    static string H(params string?[] parts) => Hashing.Sha256(string.Join("|", parts.Select(N)));

    public static string VulnerableDependency(string repo, string purlName, string version, string vulnId, string manifestPath) =>
        H("vulnerable_dependency", repo, purlName, version, vulnId, manifestPath);
    public static string Secret(string repo, string filePath, string detector, string secretHmac) =>
        H("secret", repo, filePath, detector, secretHmac);
    public static string UnsafeCode(string repo, string filePath, string ruleOrCwe, string enclosingSymbol, string snippet) =>
        H("unsafe_code", repo, filePath, ruleOrCwe, enclosingSymbol, NormalisedSnippetHash(snippet));
    public static string Binary(string repo, string filePath, string contentHash) => H("binary_artefact", repo, filePath, contentHash);
    public static string Licence(string repo, string purl, string version, string spdx) => H("licence", repo, purl, version, spdx);
    public static string FixGroupKey(string purlName, string version, string vulnId) => H("fix_group", purlName, version, vulnId);

    /// <summary>Snippet hash with whitespace and comments stripped.</summary>
    public static string NormalisedSnippetHash(string snippet)
    {
        var noBlock = Regex.Replace(snippet, @"/\*.*?\*/", "", RegexOptions.Singleline);
        var noLine = Regex.Replace(noBlock, @"//[^\n]*", "");
        var noWs = Regex.Replace(noLine, @"\s+", "");
        return Hashing.Sha256(noWs);
    }
}
