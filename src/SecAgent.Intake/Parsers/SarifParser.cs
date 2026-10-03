using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecAgent.Core;

namespace SecAgent.Intake.Parsers;

/// <summary>Generic SARIF 2.1.0 → canonical Finding. One SARIF result = one canonical finding (the producer's grouping is kept:
/// Black Duck SCA SARIF groups by component by default, so one finding = "component X version Y has these vulnerabilities").
/// <list type="bullet">
/// <item>rules: driver.rules and tool.extensions[].rules, resolved by ruleIndex, rule.index, ruleId or rule.id.</item>
/// <item>severity: properties["security-severity"] (CVSS, GitHub convention) → else properties severity word → else result/rule level.
/// For Black Duck SCA SARIF the per-advisory markers in fullDescription ("[:orange_circle:] BDSA-…") are also read and the maximum kept.</item>
/// <item>CVE / BDSA / GHSA ids: properties (cve, cveIds, vulnerabilityIds …) → else text of rule id, short/full description, message.</item>
/// <item>component/version: properties (componentName, packageName, purl, componentVersion …) → else Black Duck SCA rule text heuristics (marked ASSUMPTION).</item>
/// <item>issue type: secret (tags/rule id) → vulnerable_dependency (advisory id / component / SCA tags) → licence (licence property) → unsafe_code.</item>
/// </list>
/// Results with kind pass/notApplicable, baselineState "absent", or a producer suppression are skipped and counted in Notes.</summary>
public sealed partial class SarifParser(IntakeOptions options, SecretMasker masker) : IFindingParser
{
    public string Format => IntakeFormats.Sarif;

    static readonly string[] CveProps = ["cve", "cves", "cveId", "cveIds", "cve_ids", "secagent.cve_ids"];
    static readonly string[] VulnIdProps = ["vulnerabilityId", "vulnerabilityIds", "vulnerabilities", "advisoryId", "advisories", "bdsa"];
    static readonly string[] ComponentProps = ["componentName", "component", "packageName", "package", "dependency", "library", "secagent.component_name"];
    static readonly string[] VersionProps = ["componentVersion", "packageVersion", "installedVersion", "version", "secagent.component_version"];
    static readonly string[] PurlProps = ["purl", "packageUrl", "package_url"];
    static readonly string[] FixedProps = ["fixedVersion", "fixVersion", "fixed_version", "patchedVersion", "remediationVersion", "secagent.fixed_version"];
    static readonly string[] LicenceProps = ["licenseId", "licenceId", "spdxId", "license", "licence", "licenseName", "secagent.licence_id"];
    static readonly string[] SeverityProps = ["severity", "Severity", "issueSeverity", "secagent.severity_scanner"];
    static readonly string[] CweProps = ["cwe", "cwes", "cweIds", "cwe_ids", "secagent.cwe_ids"];
    static readonly string[] ScaTags = ["open_source_analysis", "sca", "dependency", "dependencies", "vulnerable_dependency", "supply-chain", "component"];

    public ParseOutcome Parse(ReadOnlyMemory<byte> payload, IntakeMetadata meta)
    {
        var root = ParserUtil.ParseJson(payload, options.MaxJsonDepth) as JsonObject ?? throw Bad("SARIF root must be a JSON object");
        var version = ParserUtil.AsString(root["version"]);
        if (version != "2.1.0") throw Bad($"unsupported SARIF version '{version ?? "(missing)"}': only 2.1.0 is accepted");
        if (root["runs"] is not JsonArray runs) throw Bad("SARIF 'runs' must be an array");
        var total = runs.Sum(r => (r?["results"] as JsonArray)?.Count ?? 0);
        if (total > options.MaxResults) throw new IntakeRejectedException(413, $"SARIF has {total} results; the limit is {options.MaxResults} (Intake:MaxResults)");

        var findings = new List<Finding>();
        var notes = new List<string>();
        int skipped = 0;
        string toolName = "", toolVersion = "";
        for (int ri = 0; ri < runs.Count; ri++)
        {
            var run = runs[ri] as JsonObject ?? throw Bad($"runs[{ri}] must be an object");
            var driver = run["tool"]?["driver"] as JsonObject ?? throw Bad($"runs[{ri}].tool.driver is required");
            var name = ParserUtil.AsString(driver["name"]) ?? throw Bad($"runs[{ri}].tool.driver.name is required");
            var ver = ParserUtil.AsString(driver["version"]) ?? ParserUtil.AsString(driver["semanticVersion"]) ?? "unknown";
            if (toolName == "") { toolName = name; toolVersion = ver; }
            var isBlackDuck = (name + " " + ParserUtil.AsString(driver["organization"])).Contains("Black Duck", StringComparison.OrdinalIgnoreCase)
                              || name.Contains("Synopsys", StringComparison.OrdinalIgnoreCase) || name.Contains("blackduck", StringComparison.OrdinalIgnoreCase);
            var rules = (driver["rules"] as JsonArray ?? []).ToList();
            var byId = new Dictionary<string, JsonNode>(StringComparer.Ordinal);
            foreach (var r in rules.Concat((run["tool"]?["extensions"] as JsonArray ?? []).SelectMany(x => x?["rules"] as JsonArray ?? [])))
                if (ParserUtil.AsString(r?["id"]) is { } id) byId.TryAdd(id, r!);
            if (run["results"] is null) continue;   // SARIF allows null/absent results (tool did not run analysis)
            if (run["results"] is not JsonArray results) throw Bad($"runs[{ri}].results must be an array");
            for (int i = 0; i < results.Count; i++)
            {
                var res = results[i] as JsonObject ?? throw Bad($"runs[{ri}].results[{i}] must be an object");
                if (res["message"] is not JsonObject msgObj || (ParserUtil.AsString(msgObj["text"]) == null && ParserUtil.AsString(msgObj["id"]) == null && ParserUtil.AsString(msgObj["markdown"]) == null))
                    throw Bad($"runs[{ri}].results[{i}].message must be an object with text, markdown or id (SARIF 2.1.0 §3.27.11)");
                var kind = ParserUtil.AsString(res["kind"]) ?? "fail";
                var baseline = ParserUtil.AsString(res["baselineState"]);
                var suppressed = res["suppressions"] is JsonArray sup && sup.Any(s => ParserUtil.AsString(s?["status"]) is null or "accepted");
                if (kind is "pass" or "notApplicable" || baseline == "absent" || suppressed) { skipped++; continue; }
                var f = Map(meta, res, Rule(res, rules, byId), name, ver, isBlackDuck);
                f.SarifRef = $"run{ri}#{i}";
                findings.Add(ParserUtil.Clip(f));
            }
        }
        if (skipped > 0) notes.Add($"{skipped} result(s) skipped (kind pass/notApplicable, baselineState absent, or suppressed by the producer)");
        if (findings.Count == 0) notes.Add("no actionable results in this SARIF log");
        return new ParseOutcome(findings, toolName, toolVersion, notes);
    }

    static JsonNode? Rule(JsonObject res, List<JsonNode?> rules, Dictionary<string, JsonNode> byId)
    {
        int? idx = res["ruleIndex"] is JsonValue v && v.TryGetValue<int>(out var n) ? n : res["rule"]?["index"] is JsonValue v2 && v2.TryGetValue<int>(out var n2) ? n2 : null;
        if (idx is >= 0 && idx < rules.Count) return rules[idx.Value];
        var id = ParserUtil.AsString(res["ruleId"]) ?? ParserUtil.AsString(res["rule"]?["id"]);
        return id != null && byId.TryGetValue(id, out var r) ? r : null;
    }

    Finding Map(IntakeMetadata meta, JsonObject res, JsonNode? rule, string tool, string toolVersion, bool isBlackDuck)
    {
        var ruleId = ParserUtil.AsString(res["ruleId"]) ?? ParserUtil.AsString(res["rule"]?["id"]) ?? ParserUtil.AsString(rule?["id"]) ?? $"{tool}.result";
        var ruleShort = ParserUtil.AsString(rule?["shortDescription"]?["text"]);
        var ruleFull = ParserUtil.AsString(rule?["fullDescription"]?["text"]);
        var helpMd = ParserUtil.AsString(rule?["help"]?["markdown"]) ?? ParserUtil.AsString(rule?["help"]?["text"]);
        var msg = ParserUtil.AsString(res["message"]?["text"]) ?? ParserUtil.AsString(res["message"]?["markdown"]) ?? ParserUtil.AsString(res["message"]?["id"]) ?? "";

        // result.properties override rule.properties
        var props = new JsonObject();
        foreach (var src in new[] { rule?["properties"] as JsonObject, res["properties"] as JsonObject })
            if (src != null) foreach (var (k, v) in src) props[k] = v?.DeepClone();
        var tags = ParserUtil.Strings(props, ["tags"]);
        bool Tag(params string[] t) => tags.Any(x => t.Any(y => x.Equals(y, StringComparison.OrdinalIgnoreCase)));

        // location
        var loc = (res["locations"] as JsonArray)?.FirstOrDefault()?["physicalLocation"];
        var file = ParserUtil.RelPath(ParserUtil.AsString(loc?["artifactLocation"]?["uri"]));
        int? line = file == null ? null : loc?["region"]?["startLine"] is JsonValue sl && sl.TryGetValue<int>(out var l1) ? l1 : null;
        int? lineEnd = line == null ? null : loc?["region"]?["endLine"] is JsonValue el && el.TryGetValue<int>(out var l2) ? l2 : line;
        var snippet = ParserUtil.AsString(loc?["region"]?["snippet"]?["text"]);
        var partialFp = (res["partialFingerprints"] as JsonObject)?.Select(kv => ParserUtil.AsString(kv.Value)).FirstOrDefault(x => x != null)
                        ?? (res["fingerprints"] as JsonObject)?.Select(kv => ParserUtil.AsString(kv.Value)).FirstOrDefault(x => x != null);

        // identifiers
        var ids = ParserUtil.Strings(props, CveProps).Concat(ParserUtil.Strings(props, VulnIdProps)).SelectMany(x => ParserUtil.VulnIds(x)).Distinct().ToList();
        if (ids.Count == 0) ids = ParserUtil.VulnIds(ruleId, ruleShort, ruleFull, msg);
        var cves = ids.Where(x => x.StartsWith("CVE-")).ToList();
        var advisories = ids.Where(x => !x.StartsWith("CVE-")).ToList();
        var cwes = ParserUtil.Cwes(tags.Concat(ParserUtil.Strings(props, CweProps)));

        // component
        string? component = null, version = null, display = null;
        if (ParserUtil.Str(props, PurlProps) is { } purl) (component, version) = ParserUtil.FromPurl(purl);
        component ??= ParserUtil.Str(props, ComponentProps);
        version ??= ParserUtil.Str(props, VersionProps);
        string? direct = Tag("direct_dependency", "direct") ? "direct" : Tag("transitive_dependency", "transitive") ? "transitive" : null;
        var blackDuckSca = isBlackDuck && BlackDuckSarifHints.LooksLikeSca(tags, ids.Count > 0, ruleShort, ruleFull);
        if (component == null && blackDuckSca && BlackDuckSarifHints.Component(ruleId, ruleShort, ruleFull) is { } hint)
        {
            (component, version, display) = hint;
            direct ??= BlackDuckSarifHints.DirectOrTransitive(ruleId, ruleShort, helpMd);
        }
        var fixedV = ParserUtil.CleanVersion(ParserUtil.Str(props, FixedProps));
        string? longTerm = null;
        if (fixedV == null && blackDuckSca && BlackDuckSarifHints.UpgradeGuidance(helpMd) is { } ug) (fixedV, longTerm) = ug;
        var licence = ParserUtil.Str(props, LicenceProps);

        // issue type
        var issueType =
            Tag("secret", "secrets", "credential", "credentials") || ruleId.Contains("secret", StringComparison.OrdinalIgnoreCase)
                || tool.Contains("gitleaks", StringComparison.OrdinalIgnoreCase) || tool.Contains("trufflehog", StringComparison.OrdinalIgnoreCase) ? IssueTypes.Secret
            : ids.Count > 0 || component != null || Tag(ScaTags) ? (licence != null && ids.Count == 0 ? IssueTypes.Licence : IssueTypes.VulnerableDependency)
            : licence != null || Tag("license", "licence", "license_violation") ? IssueTypes.Licence
            : IssueTypes.UnsafeCode;

        // severity
        var level = ParserUtil.AsString(res["level"]) ?? ParserUtil.AsString(rule?["defaultConfiguration"]?["level"]) ?? "warning";
        string sev; string sevSource;
        if (ParserUtil.SeverityFromScore(ParserUtil.Num(props, ["security-severity", "securitySeverity", "cvss", "cvssScore", "overallScore"])) is { } s1) { sev = s1; sevSource = "security-severity"; }
        else if (ParserUtil.SeverityFromWord(ParserUtil.Str(props, SeverityProps)) is { } s2) { sev = s2; sevSource = "severity property"; }
        else { sev = ParserUtil.SeverityFromWord(level) ?? "medium"; sevSource = "level"; }
        if (isBlackDuck && BlackDuckSarifHints.MaxMarkerSeverity(ruleFull) is { } s3 && Schema.Rank(s3) > Schema.Rank(sev)) { sev = s3; sevSource = "blackduck advisory marker"; }

        var f = new Finding
        {
            SourceScanner = meta.Scanner, ScannerVersion = toolVersion, ScannerRuleId = ruleId, IssueType = issueType,
            CveIds = cves, CweIds = cwes, SeverityScanner = sev, Repo = meta.Repo, Branch = meta.Branch, PrNumber = meta.PrNumber, CommitSha = meta.HeadSha,
            FilePath = file, LineStart = line, LineEnd = lineEnd, Message = masker.Mask(FirstLines(msg, 6), false),
            Attributes = new() { ["sarif_tool"] = tool, ["severity_source"] = sevSource, ["intake_format"] = Format },
        };
        if (advisories.Count > 0) f.Attributes["advisory_ids"] = string.Join(",", advisories);
        if (ids.Count > 0) f.Attributes["vulnerability_ids"] = string.Join(",", ids);
        if (display != null) f.Attributes["component_display"] = display;
        if (longTerm != null) f.Attributes["long_term_version"] = longTerm;

        var where = file != null ? $" in {file}" : "";
        switch (issueType)
        {
            case IssueTypes.VulnerableDependency:
            {
                var key = component ?? ruleId;
                f.ComponentName = component ?? display ?? ruleId; f.ComponentVersion = version; f.FixedVersion = fixedV; f.DirectOrTransitive = direct;
                if (component?.StartsWith("pkg:nuget/") == true) f.Attributes["package"] = component["pkg:nuget/".Length..];
                f.Title = $"{display ?? $"{key} {version}".Trim()}: " + (ids.Count == 0 ? (ruleShort ?? "vulnerable dependency") : string.Join(", ", ids.Take(3)) + (ids.Count > 3 ? $" +{ids.Count - 3} more" : ""));
                f.Fingerprint = Fingerprints.VulnerableDependency(meta.Repo, key, version ?? "-", ruleId, file ?? "");
                f.FixGroupKey = Fingerprints.FixGroupKey(key, version ?? "-", ruleId);
                break;
            }
            case IssueTypes.Licence:
                f.ComponentName = component ?? file ?? ruleId; f.ComponentVersion = version ?? "-"; f.LicenceId = licence ?? ruleId;
                f.Title = $"{f.LicenceId} licence in {f.ComponentName}";
                f.Fingerprint = Fingerprints.Licence(meta.Repo, f.ComponentName, f.ComponentVersion, f.LicenceId);
                break;
            case IssueTypes.Secret:
            {
                // The matched value may be in region.snippet: only its HMAC is kept (D-08); the raw copy at rest has snippets removed (Redact).
                var basis = snippet ?? partialFp ?? $"{ruleId}|{file}|{line}";
                if (snippet != null) masker.Register(snippet.Trim());
                f.SecretHash = Hashing.Hmac(basis); f.Classification = "restricted"; f.CweIds = cwes.Count > 0 ? cwes : ["CWE-798"];
                f.Title = $"{ruleShort ?? ruleId}{where}";
                f.Message = masker.Mask(f.Message, false);
                f.Fingerprint = Fingerprints.Secret(meta.Repo, file ?? "", ruleId, f.SecretHash);
                break;
            }
            default:
                f.Title = $"{ruleShort ?? FirstLines(msg, 1)}{where}";
                f.Fingerprint = Fingerprints.UnsafeCode(meta.Repo, file ?? "", ruleId, "", partialFp ?? snippet ?? msg);
                break;
        }
        if (string.IsNullOrWhiteSpace(f.Title)) f.Title = ruleId;
        f.InjectionFlag = InjectionDetector.Scan(f.Title + "\n" + msg).Count > 0;
        return f;
    }

    static string FirstLines(string s, int n) => string.Join('\n', s.Replace("\r", "").Split('\n').Where(l => l.Trim().Length > 0).Take(n));

    static IntakeRejectedException Bad(string m) => new(422, m);

    /// <summary>Raw copy at rest: known secret patterns masked; if any result was a secret, every region snippet is removed.</summary>
    public byte[] Redact(ReadOnlyMemory<byte> payload, ParseOutcome parsed)
    {
        if (!parsed.Findings.Any(f => f.IssueType == IssueTypes.Secret)) return ParserUtil.MaskSecrets(payload.Span, masker);
        var root = ParserUtil.ParseJson(payload, options.MaxJsonDepth);
        Strip(root);
        return ParserUtil.MaskSecrets(Encoding.UTF8.GetBytes(root.ToJsonString()), masker);
        static void Strip(JsonNode? n)
        {
            if (n is JsonObject o)
            {
                foreach (var key in o.Select(kv => kv.Key).Where(k => k is "snippet").ToList()) o[key] = new JsonObject { ["text"] = "[secagent: snippet removed at intake]" };
                foreach (var kv in o.ToList()) Strip(kv.Value);
            }
            else if (n is JsonArray a) foreach (var x in a) Strip(x);
        }
    }
}

/// <summary>Black Duck SCA SARIF text layout (Bridge CLI / black-duck-security-scan action, and the older Synopsys scan action).
/// ASSUMPTIONS, from public sample reports (not a documented contract): adjust here when the customer's real SARIF arrives.
/// <list type="bullet">
/// <item>rule id: "docker-buildx 0.17.0-1.fc41", "direct: go.googlesource.com net#v0.40.0", "Nimbus-JOSE-JWT 9.37.3: com.nimbusds" (name, version, optional ": group").</item>
/// <item>fullDescription: "&lt;name version&gt; has the following vulnerabilities: [:orange_circle:] BDSA-2025-5774, [:yellow_circle:] …".</item>
/// <item>older action: shortDescription "The direct dependency 'cheerio/0.22.0' has …".</item>
/// <item>help.markdown: "| Affected Dependency | Recommended short term version | Recommended long term version |" table, first data row.</item>
/// <item>markers: red = critical, orange = high, yellow = medium, white/green/blue = low.</item>
/// </list></summary>
public static partial class BlackDuckSarifHints
{
    [GeneratedRegex(@"^(?<cv>.+?) has the following vulnerabilities", RegexOptions.Singleline)]
    private static partial Regex HasVulnsRe();
    [GeneratedRegex(@"dependency '(?<n>[^'/]+(?:/[^'/]+)*?)/(?<v>[^'/]+)'", RegexOptions.IgnoreCase)]
    private static partial Regex QuotedDepRe();
    [GeneratedRegex(@"Recommended short term version\**\s*\|[^\n]*\n\s*\|[^\n]*\n\s*\|[^|\n]*\|\s*(?<s>[^|\n]*?)\s*\|\s*(?<l>[^|\n]*?)\s*\|", RegexOptions.IgnoreCase)]
    private static partial Regex UpgradeRe();
    [GeneratedRegex(@"\[:(?<c>red|orange|yellow|white|green|blue)_circle:\]", RegexOptions.IgnoreCase)]
    private static partial Regex MarkerRe();

    /// <summary>Only SCA-shaped Black Duck rules get the text heuristics (Polaris SAST rules in the same SARIF are left alone).</summary>
    public static bool LooksLikeSca(List<string> tags, bool hasAdvisoryIds, string? shortDesc, string? fullDesc) =>
        tags.Any(t => t.Equals("open_source_analysis", StringComparison.OrdinalIgnoreCase)) || hasAdvisoryIds
        || (fullDesc != null && HasVulnsRe().IsMatch(fullDesc)) || (shortDesc != null && QuotedDepRe().IsMatch(shortDesc));

    public static (string Name, string? Version, string Display)? Component(string ruleId, string? shortDesc, string? fullDesc)
    {
        if (shortDesc != null && QuotedDepRe().Match(shortDesc) is { Success: true } q)
            return (q.Groups["n"].Value, q.Groups["v"].Value, $"{q.Groups["n"].Value} {q.Groups["v"].Value}");
        var cv = fullDesc != null && HasVulnsRe().Match(fullDesc) is { Success: true } m ? m.Groups["cv"].Value.Trim() : ruleId.Trim();
        cv = Regex.Replace(cv, @"^(direct|transitive)\s*:\s*", "", RegexOptions.IgnoreCase);
        var colon = cv.LastIndexOf(": ", StringComparison.Ordinal);
        if (colon > 0) cv = cv[..colon];
        int cut = cv.LastIndexOf('#') is var h and > 0 ? h : cv.LastIndexOf(' ');
        if (cut <= 0) return null;   // no version part: not a component-shaped rule (e.g. SAST)
        var name = cv[..cut].Trim(); var version = ParserUtil.CleanVersion(cv[(cut + 1)..]);
        if (name.Length == 0 || version == null || !version.Any(char.IsDigit)) return null;
        return (name, version, $"{name} {version}");
    }

    public static string? DirectOrTransitive(string ruleId, string? shortDesc, string? helpMd)
    {
        var s = (ruleId + " " + shortDesc).ToLowerInvariant();
        if (s.StartsWith("direct:") || s.Contains("direct dependency")) return "direct";
        if (s.StartsWith("transitive:") || s.Contains("transitive dependency") || (helpMd?.Contains("### Transitive Dependency", StringComparison.OrdinalIgnoreCase) ?? false)) return "transitive";
        return null;
    }

    public static (string? ShortTerm, string? LongTerm)? UpgradeGuidance(string? helpMd)
    {
        if (helpMd == null || UpgradeRe().Match(helpMd) is not { Success: true } m) return null;
        var st = ParserUtil.CleanVersion(m.Groups["s"].Value); var lt = ParserUtil.CleanVersion(m.Groups["l"].Value);
        return st == null && lt == null ? null : (st ?? lt, lt);
    }

    public static string? MaxMarkerSeverity(string? fullDesc)
    {
        if (fullDesc == null) return null;
        string? best = null;
        foreach (Match m in MarkerRe().Matches(fullDesc))
        {
            var s = m.Groups["c"].Value.ToLowerInvariant() switch { "red" => "critical", "orange" => "high", "yellow" => "medium", _ => "low" };
            if (best == null || Schema.Rank(s) > Schema.Rank(best)) best = s;
        }
        return best;
    }
}
