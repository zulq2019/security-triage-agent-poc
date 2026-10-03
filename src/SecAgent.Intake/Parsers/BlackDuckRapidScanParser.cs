using System.Globalization;
using System.Text.Json.Nodes;
using SecAgent.Core;

namespace SecAgent.Intake.Parsers;

/// <summary>Where each canonical field is read from in Black Duck rapid / stateless scan JSON. Every entry is a list of candidate
/// property names (first present wins, case-insensitive). THIS IS THE ONE PLACE TO ADJUST when the customer's real sample arrives.
/// <para>Built from public sources, not from a customer sample:</para>
/// <list type="bullet">
/// <item>Detect writes "&lt;project&gt;_&lt;version&gt;_BlackDuck_DeveloperMode_Result.json" as gson of List&lt;DeveloperScansScanView&gt;
/// (blackducksoftware/detect RapidModeGenerateJsonOperation) → a top-level JSON ARRAY of component items.</item>
/// <item>Item fields (blackduck-common-api DeveloperScansScanView): componentName, versionName, componentIdentifier, externalId, filePath,
/// policyViolationVulnerabilities[{name, vulnSeverity, overallScore, cweIds, description, solution, workaround, source, violatingPolicies[{policyName, policySeverity}]}],
/// policyViolationLicenses[{name, licenseFamilyName, violatingPolicies}], shortTermUpgradeGuidance / longTermUpgradeGuidance {versionName, version, externalId},
/// transitiveUpgradeGuidance[], dependencyTrees[[…]], violatingPolicies[{policyName, policySeverity}]. Older servers: violatingPolicyNames[].</item>
/// <item>The /api/developer-scans/{id}/full-result response wraps items in {"items": […]}; also accepted.</item>
/// <item>Detect's component-location-analysis file (components-with-locations.json: componentList[{groupID, artifactID, version, metadata{…},
/// declarationLocation{fileLocations[{filePath, lineLocations[{lineNumber}]}]}}]) is accepted too; it carries manifest file + line.</item>
/// </list></summary>
public sealed record BlackDuckRapidFieldMap
{
    public IReadOnlyList<string> ItemsWrapper { get; init; } = ["items", "results"];
    public IReadOnlyList<string> LocationComponentList { get; init; } = ["componentList"];
    public IReadOnlyList<string> ComponentName { get; init; } = ["componentName", "artifactID", "name"];
    public IReadOnlyList<string> ComponentGroup { get; init; } = ["groupID"];
    public IReadOnlyList<string> ComponentVersion { get; init; } = ["versionName", "version"];
    public IReadOnlyList<string> ComponentId { get; init; } = ["componentIdentifier", "externalId"];
    public IReadOnlyList<string> Purl { get; init; } = ["packageUrl", "purl"];          // only with BLACKDUCK_RAPID_SCAN_EXTENDED_DATA=true (field name ASSUMED)
    public IReadOnlyList<string> FilePath { get; init; } = ["filePath"];                 // ASSUMPTION: declaring manifest; may be the scan root on some versions
    public IReadOnlyList<string> Metadata { get; init; } = ["metadata"];                 // component-location-analysis nests the fields below here
    public IReadOnlyList<string> Vulnerabilities { get; init; } = ["policyViolationVulnerabilities", "allVulnerabilities", "vulnerabilities"];
    public IReadOnlyList<string> VulnId { get; init; } = ["name", "vulnerabilityId", "id"];
    public IReadOnlyList<string> VulnSeverity { get; init; } = ["vulnSeverity", "severity"];
    public IReadOnlyList<string> VulnScore { get; init; } = ["overallScore", "baseScore", "cvssScore"];
    public IReadOnlyList<string> VulnCwes { get; init; } = ["cweIds", "cweId", "cwes"];
    public IReadOnlyList<string> VulnDescription { get; init; } = ["description", "summary"];
    public IReadOnlyList<string> VulnRelatedCve { get; init; } = ["relatedVulnerability", "relatedVulnerabilityId", "cveId"];   // ASSUMED; BDSA → CVE link if present
    public IReadOnlyList<string> Licences { get; init; } = ["policyViolationLicenses"];
    public IReadOnlyList<string> LicenceId { get; init; } = ["spdxId", "spdxLicenseId", "licenseSpdxId", "name", "licenseName"];   // SPDX field names ASSUMED (extended data)
    public IReadOnlyList<string> LicenceFamily { get; init; } = ["licenseFamilyName"];
    public IReadOnlyList<string> ShortTermUpgrade { get; init; } = ["shortTermUpgradeGuidance"];
    public IReadOnlyList<string> LongTermUpgrade { get; init; } = ["longTermUpgradeGuidance"];
    public IReadOnlyList<string> UpgradeVersion { get; init; } = ["versionName", "version"];
    public IReadOnlyList<string> TransitiveUpgrade { get; init; } = ["transitiveUpgradeGuidance"];
    public IReadOnlyList<string> DependencyTrees { get; init; } = ["dependencyTrees"];
    public IReadOnlyList<string> ViolatingPolicies { get; init; } = ["violatingPolicies", "componentViolatingPolicies"];
    public IReadOnlyList<string> PolicyName { get; init; } = ["policyName", "name"];
    public IReadOnlyList<string> PolicySeverity { get; init; } = ["policySeverity", "severity"];
    public IReadOnlyList<string> PolicyNames { get; init; } = ["violatingPolicyNames"];
    public IReadOnlyList<string> ErrorMessage { get; init; } = ["errorMessage"];
    public IReadOnlyList<string> DeclarationFiles { get; init; } = ["declarationLocation"];

    /// <summary>Black Duck policy severity → canonical (licence findings). ASSUMPTION: BLOCKER &gt; CRITICAL &gt; MAJOR &gt; MINOR &gt; TRIVIAL.</summary>
    public IReadOnlyDictionary<string, string> PolicySeverityMap { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["BLOCKER"] = "critical", ["CRITICAL"] = "high", ["MAJOR"] = "medium", ["MINOR"] = "low", ["TRIVIAL"] = "info", ["UNSPECIFIED"] = "medium",
    };

    public static readonly BlackDuckRapidFieldMap Default = new();
}

/// <summary>Black Duck rapid / stateless scan JSON → canonical findings, behind the same <see cref="IFindingParser"/> as SARIF.
/// One component item with policy-violating vulnerabilities = ONE vulnerable_dependency finding (same grouping as Black Duck's default
/// grouped SARIF: "upgrade component X fixes these advisories"); each policy-violating licence = one licence finding.
/// Component-only policy violations (e.g. "unknown version") carry no vulnerability or licence detail and are counted in Notes, not mapped.</summary>
public sealed class BlackDuckRapidScanParser(IntakeOptions options, SecretMasker masker, BlackDuckRapidFieldMap? map = null) : IFindingParser
{
    readonly BlackDuckRapidFieldMap M = map ?? BlackDuckRapidFieldMap.Default;
    public string Format => IntakeFormats.BlackDuckRapid;
    public const string ToolVersion = "rapid-scan";

    public ParseOutcome Parse(ReadOnlyMemory<byte> payload, IntakeMetadata meta)
    {
        var root = ParserUtil.ParseJson(payload, options.MaxJsonDepth);
        JsonArray items; bool locationFile = false;
        if (root is JsonArray a) items = a;
        else if (root is JsonObject o && ParserUtil.Get(o, M.ItemsWrapper) is JsonArray wrapped) items = wrapped;
        else if (root is JsonObject o2 && ParserUtil.Get(o2, M.LocationComponentList) is JsonArray cl) { items = cl; locationFile = true; }
        else throw new IntakeRejectedException(422, "Black Duck rapid-scan JSON must be an array of component results, {\"items\": […]}, or a component-location-analysis {\"componentList\": […]}");
        if (items.Count > options.MaxResults) throw new IntakeRejectedException(413, $"rapid-scan JSON has {items.Count} components; the limit is {options.MaxResults} (Intake:MaxResults)");

        var findings = new List<Finding>();
        var notes = new List<string>();
        int policyOnly = 0, errors = 0;
        for (int i = 0; i < items.Count; i++)
        {
            var item = items[i] as JsonObject ?? throw new IntakeRejectedException(422, $"component result [{i}] must be an object");
            var md = locationFile ? ParserUtil.Get(item, M.Metadata) as JsonObject ?? new JsonObject() : item;
            if (ParserUtil.Str(item, M.ErrorMessage) is { } err) { errors++; notes.Add($"component [{i}] error from Black Duck: {ParserUtil.Trunc(masker.Mask(err, false), 160)}"); }

            var group = ParserUtil.Str(item, M.ComponentGroup);
            var displayName = ParserUtil.Str(item, M.ComponentName) ?? throw new IntakeRejectedException(422, $"component result [{i}] has no component name ({string.Join("/", M.ComponentName)})");
            var version = ParserUtil.Str(item, M.ComponentVersion);
            var idText = ParserUtil.Str(item, M.ComponentId);
            (string Name, string? Version)? id = ParserUtil.Str(item, M.Purl) is { } purl ? ParserUtil.FromPurl(purl) : ParserUtil.FromBlackDuckId(idText);
            if (id == null && locationFile && group != null) id = ($"pkg:maven/{group}/{displayName}", version);   // ASSUMPTION: groupID present ⇒ maven-style coordinates
            var component = id?.Name ?? displayName;
            version ??= id?.Version;
            var (file, line) = Location(item);

            var vulns = ParserUtil.Arr(md, M.Vulnerabilities).OfType<JsonObject>().ToList();
            var licences = ParserUtil.Arr(md, M.Licences).OfType<JsonObject>().ToList();
            var policies = ParserUtil.Arr(md, M.ViolatingPolicies).OfType<JsonObject>().Select(p => ParserUtil.Str(p, M.PolicyName)).Where(x => x != null).Select(x => x!)
                .Concat(ParserUtil.Strings(md, M.PolicyNames)).Distinct().ToList();
            var shortTerm = ParserUtil.CleanVersion(ParserUtil.Str(ParserUtil.Get(md, M.ShortTermUpgrade), M.UpgradeVersion));
            var longTerm = ParserUtil.CleanVersion(ParserUtil.Str(ParserUtil.Get(md, M.LongTermUpgrade), M.UpgradeVersion));
            var direct = DirectOrTransitive(md);
            var displayLabel = $"{displayName} {version}".Trim();

            if (vulns.Count > 0)
            {
                var ids = new List<string>(); var detail = new List<string>(); var cwes = new List<string>();
                string sev = "info";
                foreach (var v in vulns)
                {
                    var vid = ParserUtil.Str(v, M.VulnId) ?? "unknown";
                    var vs = ParserUtil.SeverityFromWord(ParserUtil.Str(v, M.VulnSeverity)) ?? ParserUtil.SeverityFromScore(ParserUtil.Num(v, M.VulnScore)) ?? "medium";
                    sev = Schema.MaxSeverity(sev, vs);
                    foreach (var x in ParserUtil.VulnIds(vid).Concat(ParserUtil.VulnIds(ParserUtil.Str(v, M.VulnRelatedCve)))) if (!ids.Contains(x)) ids.Add(x);
                    if (ParserUtil.VulnIds(vid).Count == 0 && !ids.Contains(vid)) ids.Add(vid);
                    foreach (var c in ParserUtil.Cwes(ParserUtil.Strings(v, M.VulnCwes))) if (!cwes.Contains(c)) cwes.Add(c);
                    detail.Add($"{vid}:{vs}:{ParserUtil.Num(v, M.VulnScore)?.ToString("0.0", CultureInfo.InvariantCulture) ?? "-"}");
                }
                var cves = ids.Where(x => x.StartsWith("CVE-")).ToList();
                var f = Base(meta, component, version, file, line);
                f.IssueType = IssueTypes.VulnerableDependency; f.ScannerRuleId = idText ?? component; f.SeverityScanner = sev; f.CveIds = cves; f.CweIds = cwes;
                f.FixedVersion = shortTerm ?? longTerm; f.DirectOrTransitive = direct;
                f.Title = $"{displayLabel}: {string.Join(", ", ids.Take(3))}{(ids.Count > 3 ? $" +{ids.Count - 3} more" : "")}";
                f.Message = masker.Mask(ParserUtil.Trunc(ParserUtil.Str(vulns[0], M.VulnDescription), 600), false);
                f.Attributes["vulnerability_ids"] = string.Join(",", ids);
                f.Attributes["vulnerabilities"] = string.Join(";", detail);   // id:severity:score
                if (ids.Any(x => !x.StartsWith("CVE-"))) f.Attributes["advisory_ids"] = string.Join(",", ids.Where(x => !x.StartsWith("CVE-")));
                if (longTerm != null) f.Attributes["long_term_version"] = longTerm;
                if (policies.Count > 0) f.Attributes["violated_policies"] = string.Join("; ", policies);
                f.Fingerprint = Fingerprints.VulnerableDependency(meta.Repo, component, version ?? "-", "blackduck:component", file ?? "");
                f.FixGroupKey = Fingerprints.FixGroupKey(component, version ?? "-", "blackduck:component");
                findings.Add(Done(f, displayLabel));
            }
            foreach (var l in licences)
            {
                var lic = ParserUtil.Str(l, M.LicenceId) ?? "unknown-licence";
                var lpol = ParserUtil.Arr(l, M.ViolatingPolicies).OfType<JsonObject>().ToList();
                var sev = lpol.Select(p => ParserUtil.Str(p, M.PolicySeverity)).Where(x => x != null && M.PolicySeverityMap.ContainsKey(x!))
                    .Select(x => M.PolicySeverityMap[x!]).DefaultIfEmpty("medium").Aggregate(Schema.MaxSeverity);
                var f = Base(meta, component, version ?? "-", file, line);
                f.IssueType = IssueTypes.Licence; f.ScannerRuleId = $"license:{lic}"; f.SeverityScanner = sev; f.LicenceId = lic;
                f.Title = $"{lic} licence in {displayLabel}";
                f.Message = $"Black Duck policy violation: {string.Join("; ", lpol.Select(p => ParserUtil.Str(p, M.PolicyName)).Where(x => x != null).DefaultIfEmpty(string.Join("; ", policies)))}";
                if (ParserUtil.Str(l, M.LicenceFamily) is { } fam) f.Attributes["licence_family"] = fam;
                f.Fingerprint = Fingerprints.Licence(meta.Repo, component, version ?? "-", lic);
                findings.Add(Done(f, displayLabel));
            }
            if (vulns.Count == 0 && licences.Count == 0 && policies.Count > 0) policyOnly++;
        }
        if (policyOnly > 0) notes.Add($"{policyOnly} component(s) violate a policy with no vulnerability or licence detail (e.g. component/version policies): not mapped to findings");
        if (errors > 0) notes.Add($"{errors} component result(s) carried an errorMessage");
        if (findings.Count == 0) notes.Add("no policy-violating vulnerabilities or licences in this rapid-scan result (rapid scan only reports policy violations)");
        return new ParseOutcome(findings, "Black Duck rapid scan", ToolVersion, notes);
    }

    Finding Base(IntakeMetadata meta, string component, string? version, string? file, int? line) => new()
    {
        SourceScanner = meta.Scanner, ScannerVersion = ToolVersion, Repo = meta.Repo, Branch = meta.Branch, PrNumber = meta.PrNumber, CommitSha = meta.HeadSha,
        ComponentName = component, ComponentVersion = version, FilePath = file, LineStart = line, LineEnd = line,
        Attributes = new() { ["intake_format"] = Format, ["sarif_tool"] = "Black Duck rapid scan" },
    };

    Finding Done(Finding f, string display)
    {
        f.Attributes["component_display"] = display;
        if (f.ComponentName?.StartsWith("pkg:nuget/") == true) f.Attributes["package"] = f.ComponentName["pkg:nuget/".Length..];
        f.InjectionFlag = InjectionDetector.Scan(f.Title + "\n" + f.Message).Count > 0;
        return ParserUtil.Clip(f);
    }

    (string? File, int? Line) Location(JsonObject item)
    {
        var decl = ParserUtil.Get(item, M.DeclarationFiles);
        if (ParserUtil.Arr(decl, "fileLocations").FirstOrDefault() is JsonObject fl)
            return (ParserUtil.RelPath(ParserUtil.Str(fl, "filePath")), ParserUtil.Arr(fl, "lineLocations").FirstOrDefault() is JsonObject ll && ParserUtil.Num(ll, ["lineNumber"]) is { } n ? (int)n : null);
        return (ParserUtil.RelPath(ParserUtil.Str(item, M.FilePath)), null);
    }

    /// <summary>ASSUMPTION: transitiveUpgradeGuidance present ⇒ transitive; each dependencyTrees entry is the path from a direct dependency
    /// down to this component, so a one-element tree ⇒ direct. Otherwise unknown (null).</summary>
    string? DirectOrTransitive(JsonNode md)
    {
        if (ParserUtil.Arr(md, M.TransitiveUpgrade).Count > 0) return "transitive";
        var trees = ParserUtil.Arr(md, M.DependencyTrees).OfType<JsonArray>().ToList();
        if (trees.Count == 0) return null;
        return trees.Any(t => t.Count <= 1) ? "direct" : "transitive";
    }

    public byte[] Redact(ReadOnlyMemory<byte> payload, ParseOutcome parsed) => ParserUtil.MaskSecrets(payload.Span, masker);
}
