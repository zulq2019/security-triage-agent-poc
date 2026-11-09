using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Parsers;

/// <summary>Shared mapping helpers for intake parsers (severity, vulnerability ids, CWE tags, Black Duck component ids → purl, column limits).</summary>
public static partial class ParserUtil
{
    [GeneratedRegex(@"\b(CVE-\d{4}-\d{4,}|BDSA-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b", RegexOptions.IgnoreCase)]
    private static partial Regex VulnIdRe();
    [GeneratedRegex(@"\bcwe[-_/:]?\s*(\d{1,5})\b", RegexOptions.IgnoreCase)]
    private static partial Regex CweRe();

    public static JsonNode ParseJson(ReadOnlyMemory<byte> payload, int maxDepth)
    {
        try
        {
            var span = payload.Span;
            if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF) payload = payload[3..];   // UTF-8 BOM
            return JsonNode.Parse(payload.Span, documentOptions: new JsonDocumentOptions { MaxDepth = maxDepth, CommentHandling = JsonCommentHandling.Disallow })
                   ?? throw new IntakeRejectedException(400, "payload is JSON null");
        }
        catch (JsonException e) { throw new IntakeRejectedException(400, $"payload is not valid JSON: {Trunc(e.Message, 160)}"); }
        catch (InvalidOperationException e) { throw new IntakeRejectedException(400, $"payload is not valid JSON: {Trunc(e.Message, 160)}"); }
    }

    /// <summary>First present property among candidate names (case-insensitive). Returns null for JSON null.</summary>
    public static JsonNode? Get(JsonNode? node, IEnumerable<string> names)
    {
        if (node is not JsonObject o) return null;
        foreach (var n in names)
        {
            if (o.TryGetPropertyValue(n, out var v) && v != null) return v;
            foreach (var kv in o) if (kv.Value != null && string.Equals(kv.Key, n, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        }
        return null;
    }
    public static JsonNode? Get(JsonNode? node, params string[] names) => Get(node, (IEnumerable<string>)names);

    /// <summary>String value of the first present candidate (numbers/bools are stringified). Empty → null.</summary>
    public static string? Str(JsonNode? node, IEnumerable<string> names) => Get(node, names) is JsonValue v ? AsString(v) : null;
    public static string? Str(JsonNode? node, params string[] names) => Str(node, (IEnumerable<string>)names);

    public static string? AsString(JsonNode? v)
    {
        if (v is not JsonValue jv) return null;
        var s = jv.GetValueKind() switch
        {
            JsonValueKind.String => jv.GetValue<string>(),
            JsonValueKind.Number => jv.ToJsonString(),
            JsonValueKind.True => "true", JsonValueKind.False => "false",
            _ => null,
        };
        return string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    public static double? Num(JsonNode? node, IEnumerable<string> names) =>
        Str(node, names) is { } s && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    public static JsonArray Arr(JsonNode? node, IEnumerable<string> names) => Get(node, names) as JsonArray ?? [];
    public static JsonArray Arr(JsonNode? node, params string[] names) => Arr(node, (IEnumerable<string>)names);

    /// <summary>Strings of an array property, or a single string / comma-separated value.</summary>
    public static List<string> Strings(JsonNode? node, IEnumerable<string> names) => Get(node, names) switch
    {
        JsonArray a => a.Select(AsString).Where(x => x != null).Select(x => x!).ToList(),
        JsonValue v when AsString(v) is { } s => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
        _ => [],
    };

    /// <summary>CVSS-style score (GitHub "security-severity" convention) → canonical severity. 0 / missing → null (caller falls back).</summary>
    public static string? SeverityFromScore(double? score) => score switch
    {
        null or <= 0 => null,
        >= 9.0 => "critical", >= 7.0 => "high", >= 4.0 => "medium", _ => "low",
    };

    /// <summary>Severity words from scanners (critical/high/…, SARIF levels error/warning/note/none, Black Duck CRITICAL/HIGH/MEDIUM/LOW/OK/UNSCORED).
    /// Reuses the scanner adapters' mapping (FindingNormalisation.Severity); unknown words → null so the caller can fall back.</summary>
    public static string? SeverityFromWord(string? word)
    {
        var w = (word ?? "").Trim().ToLowerInvariant();
        if (w.Length == 0) return null;
        if (w is "none" or "ok" or "informational" or "unscored" or "trivial") return "info";
        var known = new[] { "critical", "high", "error", "medium", "moderate", "warning", "low", "note", "info", "negligible" };
        return known.Contains(w) ? FindingNormalisation.Severity(w) : null;
    }

    public static List<string> VulnIds(params string?[] texts)
    {
        var ids = new List<string>();
        foreach (var t in texts)
            if (!string.IsNullOrEmpty(t))
                foreach (Match m in VulnIdRe().Matches(t))
                {
                    var id = m.Value.StartsWith("GHSA", StringComparison.OrdinalIgnoreCase) ? "GHSA" + m.Value[4..].ToLowerInvariant() : m.Value.ToUpperInvariant();
                    if (!ids.Contains(id)) ids.Add(id);
                }
        return ids;
    }

    /// <summary>"external/cwe/cwe-552", "CWE-89: SQL Injection", "cwe:79" → "CWE-552", "CWE-89", "CWE-79".</summary>
    public static List<string> Cwes(IEnumerable<string> values)
    {
        var list = new List<string>();
        foreach (var v in values)
            foreach (Match m in CweRe().Matches(v))
                if (!list.Contains("CWE-" + m.Groups[1].Value)) list.Add("CWE-" + m.Groups[1].Value);
        return list;
    }

    /// <summary>Black Duck external id / component identifier → (purl-style name, version).
    /// ASSUMPTION (from public Detect output samples: "maven:org.apache.pdfbox:pdfbox:2.0.12", "npmjs:handlebars/4.0.11"):
    /// "forge:name/version" for most forges, "forge:group:artifact:version" for maven. Unknown forges keep "forge:name".</summary>
    public static (string Name, string? Version)? FromBlackDuckId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        id = id.Trim();
        var colon = id.IndexOf(':');
        if (colon <= 0) return null;
        var forge = id[..colon].ToLowerInvariant();
        var rest = id[(colon + 1)..];
        string name; string? version = null;
        if (forge is "maven" or "gradle")
        {
            var parts = rest.Split(':');
            if (parts.Length >= 3) { name = $"{parts[0]}/{parts[1]}"; version = parts[2]; }
            else if (parts.Length == 2) name = $"{parts[0]}/{parts[1]}";
            else name = rest;
        }
        else
        {
            var slash = rest.LastIndexOf('/');
            if (slash > 0) { name = rest[..slash]; version = rest[(slash + 1)..]; } else name = rest;
        }
        var type = forge switch
        {
            "maven" or "gradle" => "maven", "npmjs" or "npm" => "npm", "nuget" => "nuget", "pypi" => "pypi", "rubygems" => "gem",
            "golang" or "go" => "golang", "crates" or "cargo" => "cargo", "packagist" => "composer", "cocoapods" => "cocoapods", "hex" => "hex",
            _ => null,
        };
        return (type == null ? $"{forge}:{name}" : $"pkg:{type}/{name}", string.IsNullOrWhiteSpace(version) ? null : version);
    }

    public static (string Name, string? Version) FromPurl(string purl)
    {
        var p = purl.Split('?', '#')[0];
        var at = p.LastIndexOf('@');
        return at > 0 ? (p[..at], Uri.UnescapeDataString(p[(at + 1)..])) : (p, null);
    }

    /// <summary>"v0.28.0" → "0.28.0"; "-" / "n/a" / "none" → null.</summary>
    public static string? CleanVersion(string? v)
    {
        v = v?.Trim();
        if (string.IsNullOrEmpty(v) || v is "-" or "—" || v.Equals("n/a", StringComparison.OrdinalIgnoreCase) || v.Equals("none", StringComparison.OrdinalIgnoreCase)) return null;
        return v.Length > 1 && (v[0] == 'v' || v[0] == 'V') && char.IsDigit(v[1]) ? v[1..] : v;
    }

    /// <summary>File URIs from scanners → repo-relative path. Black Duck's "file://unknown-file" placeholder → null.</summary>
    public static string? RelPath(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return null;
        var u = uri.Trim();
        if (u.Contains("unknown-file", StringComparison.OrdinalIgnoreCase)) return null;
        if (u.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) u = Uri.UnescapeDataString(u[7..]);
        u = FindingNormalisation.RepoRelativePath(u);
        return u.Length == 0 ? null : u;
    }

    public static string Trunc(string? s, int n) => s == null ? "" : s.Length <= n ? s : s[..(n - 1)] + "…";

    /// <summary>Clip to the canonical store's column sizes (db/schema.sql) so one long scanner string cannot fail the batch insert.</summary>
    public static Finding Clip(Finding f)
    {
        f.ScannerVersion = Trunc(f.ScannerVersion, 40); f.ScannerRuleId = Trunc(f.ScannerRuleId, 200); f.Title = Trunc(f.Title, 400);
        f.Branch = Trunc(f.Branch, 200); f.FilePath = f.FilePath == null ? null : Trunc(f.FilePath, 500);
        f.ComponentName = f.ComponentName == null ? null : Trunc(f.ComponentName, 300);
        f.ComponentVersion = f.ComponentVersion == null ? null : Trunc(f.ComponentVersion, 100);
        f.FixedVersion = f.FixedVersion == null ? null : Trunc(f.FixedVersion, 100);
        f.LicenceId = f.LicenceId == null ? null : Trunc(f.LicenceId, 100);
        f.Message = f.Message == null ? null : Trunc(f.Message, 1000);
        foreach (var k in f.Attributes.Keys.ToList()) f.Attributes[k] = Trunc(f.Attributes[k], 2000);
        return f;
    }

    public static byte[] MaskSecrets(ReadOnlySpan<byte> payload, SecretMasker masker)
    {
        var text = Encoding.UTF8.GetString(payload);
        return masker.ContainsSecret(text) ? Encoding.UTF8.GetBytes(masker.Mask(text)) : payload.ToArray();
    }
}
