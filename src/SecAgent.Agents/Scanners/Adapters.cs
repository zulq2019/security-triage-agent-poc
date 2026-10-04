using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecAgent.Core;

namespace SecAgent.Agents.Scanners;

static class Common
{
    public static string Sev(string? s) => FindingNormalisation.Severity(s);
    public static string Rel(string p) => FindingNormalisation.RepoRelativePath(p);
    public static string TempFile(string ext) => Path.Combine(Path.GetTempPath(), "secagent-" + Guid.NewGuid().ToString("N") + ext);
}

public sealed class GitleaksAdapter(SecretMasker masker, ConfigSnapshot cfg) : IScannerAdapter
{
    public string Id => "gitleaks";
    public string Version { get; private set; } = "";
    public bool Supports(string t) => t == IssueTypes.Secret;

    public async Task<RawOutput> ScanAsync(ScanTarget t, CancellationToken ct)
    {
        var bin = Proc.Which("gitleaks");
        if (Version == "") Version = (await Proc.RunAsync(bin, ["version"], ct: ct)).StdOut.Trim();
        var outFile = Common.TempFile(".json");
        string[] args = ["dir", ".", "--report-format", "json", "--report-path", outFile, "--no-banner", "--exit-code", "0", "--log-level", "error"];
        var r = await Proc.RunAsync(bin, args, t.Dir, ct);
        if (r.ExitCode != 0) throw new InvalidOperationException("gitleaks failed: " + masker.Mask(r.StdErr));
        var content = await File.ReadAllTextAsync(outFile, ct);
        File.Delete(outFile);
        // Raw output is kept, but secret values are never stored (D-08): redact Secret/Match before it reaches Blob.
        var arr = JsonNode.Parse(content)?.AsArray() ?? [];
        foreach (var n in arr)
        {
            var secret = n?["Secret"]?.GetValue<string>() ?? "";
            masker.Register(secret);
            if (n is JsonObject o)
            {
                o["Secret"] = SecretMasker.MaskOf(secret);
                o["Match"] = masker.Mask(o["Match"]?.GetValue<string>() ?? "", count: false);
                o["Line"] = masker.Mask(o["Line"]?.GetValue<string>() ?? "", count: false);
                o["SecretHmac"] = secret.Length > 0 ? Hashing.Hmac(secret) : "";
                o["TestKeyPrefix"] = Regex.IsMatch(secret, @"^(sk|rk|pk)_test_|^test_|_test_") ? "true" : "false";
            }
        }
        var stored = arr.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        return new RawOutput(Id, Version, stored, stored, r.ElapsedMs, string.Join(' ', args));
    }

    public List<Finding> Normalise(RawOutput raw, ScanTarget t, HashSet<string> tracked)
    {
        var map = cfg.RulePacks.TryGetValue("secret", out var rp) ? rp.SeverityMap : new();
        var list = new List<Finding>();
        foreach (var n in JsonNode.Parse(raw.Content)!.AsArray())
        {
            var file = Common.Rel(n!["File"]!.GetValue<string>());
            if (!tracked.Contains(file)) continue; // only git-tracked content (ignores bin/obj build outputs)
            var rule = n["RuleID"]!.GetValue<string>();
            var hmac = n["SecretHmac"]!.GetValue<string>();
            var sev = map.TryGetValue(rule, out var s) ? s : map.GetValueOrDefault("default", "high");
            list.Add(new Finding
            {
                SourceScanner = Id, ScannerVersion = raw.ScannerVersion, ScannerRuleId = rule, IssueType = IssueTypes.Secret,
                Title = $"{n["Description"]?.GetValue<string>() ?? rule} in {Path.GetFileName(file)}",
                SeverityScanner = sev, Repo = t.Repo, Branch = t.Branch, PrNumber = t.PrNumber, CommitSha = t.CommitSha,
                FilePath = file, LineStart = n["StartLine"]?.GetValue<int>(), LineEnd = n["EndLine"]?.GetValue<int>(),
                Classification = "restricted", SecretHash = hmac, CweIds = ["CWE-798"],
                Fingerprint = Fingerprints.Secret(t.Repo, file, rule, hmac),
                Message = $"Detector {rule} matched {n["Secret"]?.GetValue<string>()} (masked)",
                Attributes = new() { ["test_key_prefix"] = n["TestKeyPrefix"]?.GetValue<string>() ?? "false", ["masked_value"] = n["Secret"]?.GetValue<string>() ?? "" },
            });
        }
        return list;
    }
}

public sealed class TrivyAdapter : IScannerAdapter
{
    public string Id => "trivy";
    public string Version { get; private set; } = "";
    public bool Supports(string t) => t is IssueTypes.VulnerableDependency or IssueTypes.Licence;

    public async Task<RawOutput> ScanAsync(ScanTarget t, CancellationToken ct)
    {
        var bin = Proc.Which("trivy");
        var outFile = Common.TempFile(".json");
        var dbExists = Directory.Exists(Path.Combine(Environment.GetEnvironmentVariable("HOME") ?? "", ".cache/trivy/db"));
        var args = new List<string> { "fs", "--scanners", "vuln,license", "--license-full", "--format", "json", "--output", outFile, "--quiet",
            "--skip-dirs", "**/bin", "--skip-dirs", "**/obj", "--skip-dirs", ".git", "--cache-backend", "memory" };
        if (dbExists) args.Add("--skip-db-update");
        args.Add(".");
        var r = await Proc.RunAsync(bin, args, t.Dir, ct);
        if (r.ExitCode != 0) throw new InvalidOperationException("trivy failed: " + r.StdErr);
        var content = await File.ReadAllTextAsync(outFile, ct);
        File.Delete(outFile);
        Version = JsonNode.Parse(content)?["Trivy"]?["Version"]?.GetValue<string>() ?? "unknown";
        return new RawOutput(Id, Version, content, content, r.ElapsedMs, string.Join(' ', args));
    }

    public List<Finding> Normalise(RawOutput raw, ScanTarget t, HashSet<string> tracked)
    {
        var list = new List<Finding>();
        var doc = JsonNode.Parse(raw.Content)!;
        foreach (var res in doc["Results"]?.AsArray() ?? [])
        {
            var target = Common.Rel(res!["Target"]!.GetValue<string>());
            var directs = DirectDeps(t.Dir, target);
            foreach (var v in res["Vulnerabilities"]?.AsArray() ?? [])
            {
                var pkg = v!["PkgName"]!.GetValue<string>();
                var ver = v["InstalledVersion"]!.GetValue<string>();
                var id = v["VulnerabilityID"]!.GetValue<string>();
                var purl = v["PkgIdentifier"]?["PURL"]?.GetValue<string>() ?? $"pkg:nuget/{pkg}@{ver}";
                var purlName = purl.Split('@')[0];
                list.Add(new Finding
                {
                    SourceScanner = Id, ScannerVersion = raw.ScannerVersion, ScannerRuleId = id, IssueType = IssueTypes.VulnerableDependency,
                    Title = $"{pkg} {ver}: {v["Title"]?.GetValue<string>() ?? id}", CveIds = id.StartsWith("CVE-") ? [id] : [],
                    CweIds = v["CweIDs"]?.AsArray().Select(x => x!.GetValue<string>()).ToList() ?? [],
                    SeverityScanner = Common.Sev(v["Severity"]?.GetValue<string>()), Repo = t.Repo, Branch = t.Branch, PrNumber = t.PrNumber,
                    CommitSha = t.CommitSha, FilePath = target, ComponentName = purlName, ComponentVersion = ver,
                    FixedVersion = v["FixedVersion"]?.GetValue<string>() is { Length: > 0 } fv ? fv.Split(',')[0].Trim() : null,
                    DirectOrTransitive = directs.Contains(pkg) ? "direct" : "transitive",
                    Fingerprint = Fingerprints.VulnerableDependency(t.Repo, purlName, ver, id, target),
                    FixGroupKey = Fingerprints.FixGroupKey(purlName, ver, id),
                    Message = (v["Description"]?.GetValue<string>() ?? "").Split('\n')[0],
                    Attributes = new() { ["package"] = pkg, ["primary_url"] = v["PrimaryURL"]?.GetValue<string>() ?? "" },
                });
            }
            foreach (var l in res["Licenses"]?.AsArray() ?? [])
            {
                var sev = Common.Sev(l!["Severity"]?.GetValue<string>());
                if (Schema.Rank(sev) < Schema.Rank("medium")) continue; // notice/permissive licences are not findings
                var spdx = l["Name"]!.GetValue<string>();
                var file = Common.Rel(l["FilePath"]?.GetValue<string>() ?? target);
                var pkgName = l["PkgName"]?.GetValue<string>();
                var component = string.IsNullOrEmpty(pkgName) ? "file:" + Path.GetDirectoryName(file)!.Replace('\\', '/') : "pkg:nuget/" + pkgName;
                var version = "-";
                if (!string.IsNullOrEmpty(pkgName) == false && !tracked.Contains(file)) continue;
                var fp = Fingerprints.Licence(t.Repo, component, version, spdx);
                var existing = list.FirstOrDefault(x => x.Fingerprint == fp);
                if (existing != null) { existing.OtherLocations.Add(file); continue; } // same component+licence: one finding, extra location
                list.Add(new Finding
                {
                    SourceScanner = Id, ScannerVersion = raw.ScannerVersion, ScannerRuleId = $"license:{spdx}", IssueType = IssueTypes.Licence,
                    Title = $"{spdx} ({l["Category"]?.GetValue<string>()}) licence in {component.Replace("file:", "")}", SeverityScanner = sev,
                    Repo = t.Repo, Branch = t.Branch, PrNumber = t.PrNumber, CommitSha = t.CommitSha, FilePath = file, ComponentName = component,
                    ComponentVersion = version, LicenceId = spdx, Fingerprint = fp,
                    Message = $"Trivy licence scanner: {spdx}, category {l["Category"]?.GetValue<string>()}, confidence {l["Confidence"]?.GetValue<double>()}",
                    Attributes = new() { ["category"] = l["Category"]?.GetValue<string>() ?? "" },
                });
            }
        }
        return list;
    }

    static HashSet<string> DirectDeps(string dir, string target)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var path = Path.Combine(dir, target);
            if (!target.EndsWith("packages.lock.json") || !File.Exists(path)) return set;
            foreach (var fw in JsonNode.Parse(File.ReadAllText(path))!["dependencies"]!.AsObject())
                foreach (var dep in fw.Value!.AsObject())
                    if (dep.Value?["type"]?.GetValue<string>() == "Direct") set.Add(dep.Key);
        }
        catch { }
        return set;
    }
}

public sealed class SemgrepAdapter(ConfigSnapshot cfg) : IScannerAdapter
{
    public string Id => "semgrep";
    public string Version { get; private set; } = "";
    public bool Supports(string t) => t == IssueTypes.UnsafeCode;

    public async Task<RawOutput> ScanAsync(ScanTarget t, CancellationToken ct)
    {
        var bin = Proc.Which("semgrep");
        if (Version == "") Version = (await Proc.RunAsync(bin, ["--version", "--disable-version-check"], ct: ct)).StdOut.Trim();
        var outFile = Common.TempFile(".sarif");
        var args = new List<string> { "scan", "--sarif", "-o", outFile, "--metrics=off", "--disable-version-check", "-q", "--exclude", "bin", "--exclude", "obj" };
        foreach (var rp in cfg.RulePacks.Values)
            foreach (var r in rp.ScannerRules) { args.Add("--config"); args.Add(Path.Combine(rp.Directory, r)); }
        args.Add(".");
        var res = await Proc.RunAsync(bin, args, t.Dir, ct);
        if (res.ExitCode is not (0 or 1)) throw new InvalidOperationException("semgrep failed: " + res.StdErr);
        var content = await File.ReadAllTextAsync(outFile, ct);
        File.Delete(outFile);
        return new RawOutput(Id, Version, content, content, res.ElapsedMs, string.Join(' ', args.Select(a => a.Contains(cfg.RulesRoot) ? Path.GetRelativePath(cfg.RulesRoot, a) : a)));
    }

    public List<Finding> Normalise(RawOutput raw, ScanTarget t, HashSet<string> tracked)
    {
        var list = new List<Finding>();
        var run = JsonNode.Parse(raw.Content)!["runs"]![0]!;
        var rules = (run["tool"]?["driver"]?["rules"]?.AsArray() ?? []).ToDictionary(r => r!["id"]!.GetValue<string>(), r => r!);
        foreach (var r in run["results"]?.AsArray() ?? [])
        {
            var ruleIdRaw = r!["ruleId"]!.GetValue<string>();
            var ruleId = ruleIdRaw.Contains("secagent.") ? ruleIdRaw[ruleIdRaw.IndexOf("secagent.", StringComparison.Ordinal)..] : ruleIdRaw;
            var loc = r["locations"]![0]!["physicalLocation"]!;
            var file = Common.Rel(loc["artifactLocation"]!["uri"]!.GetValue<string>());
            if (!tracked.Contains(file)) continue;
            int start = loc["region"]!["startLine"]!.GetValue<int>(), end = loc["region"]?["endLine"]?.GetValue<int>() ?? start;
            var lines = File.ReadAllLines(Path.Combine(t.Dir, file));
            var (symbol, fStart, fEnd) = CodeNav.EnclosingMethod(lines, start);
            var matched = string.Join('\n', lines[(start - 1)..end]);
            var tags = rules.TryGetValue(ruleIdRaw, out var rule) ? rule["properties"]?["tags"]?.AsArray().Select(x => x!.GetValue<string>()).ToList() ?? [] : [];
            var cwes = tags.Where(x => x.StartsWith("CWE-")).Select(x => x.Split(':')[0].Trim()).Distinct().ToList();
            var level = r["level"]?.GetValue<string>() ?? rule?["defaultConfiguration"]?["level"]?.GetValue<string>() ?? "warning";
            list.Add(new Finding
            {
                SourceScanner = Id, ScannerVersion = raw.ScannerVersion, ScannerRuleId = ruleId, IssueType = IssueTypes.UnsafeCode,
                Title = $"SQL injection risk in {symbol}()", CweIds = cwes.Count > 0 ? cwes : ["CWE-89"], SeverityScanner = Common.Sev(level),
                Repo = t.Repo, Branch = t.Branch, PrNumber = t.PrNumber, CommitSha = t.CommitSha, FilePath = file, LineStart = start, LineEnd = end,
                Fingerprint = Fingerprints.UnsafeCode(t.Repo, file, ruleId, symbol, matched),
                Message = r["message"]?["text"]?.GetValue<string>(),
                Attributes = new() { ["enclosing_symbol"] = symbol, ["function_start"] = fStart.ToString(), ["function_end"] = fEnd.ToString() },
            });
        }
        return list;
    }
}

public sealed class BinaryCheckAdapter(ConfigSnapshot cfg) : IScannerAdapter
{
    public string Id => "binary_check";
    public string Version => "secagent-binary-check@0.1.0";
    public bool Supports(string t) => t == IssueTypes.BinaryArtefact;

    public Task<RawOutput> ScanAsync(ScanTarget t, CancellationToken ct)
    {
        var rp = cfg.RulePacks["binary_artefact"];
        var exts = rp.GetList(rp.Detect, "extensions");
        var magics = rp.GetList(rp.Detect, "magic").Select(Convert.FromHexString).ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var hits = new JsonArray();
        foreach (var file in GitFiles(t.Dir))
        {
            var full = Path.Combine(t.Dir, file);
            if (!File.Exists(full)) continue;
            var head = new byte[8];
            int n;
            using (var fs = File.OpenRead(full)) n = fs.Read(head, 0, head.Length);
            var magic = magics.FirstOrDefault(m => n >= m.Length && head.AsSpan(0, m.Length).SequenceEqual(m));
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (magic == null && !exts.Contains(ext)) continue;
            var bytes = File.ReadAllBytes(full);
            hits.Add(new JsonObject
            {
                ["file"] = file, ["size"] = bytes.Length, ["sha256"] = Hashing.Sha256(bytes), ["extension"] = ext,
                ["magic"] = magic == null ? null : Convert.ToHexString(magic), ["kind"] = magic is { Length: 2 } ? "PE (Windows/.NET binary)" : magic == null ? "by extension" : "binary",
            });
        }
        var json = new JsonObject { ["tool"] = Version, ["results"] = hits }.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        return Task.FromResult(new RawOutput(Id, Version, json, json, sw.ElapsedMilliseconds, "git ls-files | magic/extension check"));
    }

    public List<Finding> Normalise(RawOutput raw, ScanTarget t, HashSet<string> tracked)
    {
        var rp = cfg.RulePacks["binary_artefact"];
        var sev = rp.Detect.TryGetValue("severity", out var s) ? s.ToString()! : "medium";
        return JsonNode.Parse(raw.Content)!["results"]!.AsArray().Select(h => new Finding
        {
            SourceScanner = Id, ScannerVersion = Version, ScannerRuleId = "secagent.binary.committed", IssueType = IssueTypes.BinaryArtefact,
            Title = $"Committed binary {h!["file"]} ({h["kind"]}, {h["size"]} bytes)", SeverityScanner = sev, Repo = t.Repo, Branch = t.Branch,
            PrNumber = t.PrNumber, CommitSha = t.CommitSha, FilePath = h["file"]!.GetValue<string>(), CweIds = ["CWE-506"],
            Fingerprint = Fingerprints.Binary(t.Repo, h["file"]!.GetValue<string>(), h["sha256"]!.GetValue<string>()),
            Message = $"Binary content committed to source control (sha256 {h["sha256"]!.GetValue<string>()[..12]}…)",
            Attributes = new() { ["sha256"] = h["sha256"]!.GetValue<string>(), ["size"] = h["size"]!.ToString() },
        }).ToList();
    }

    public static List<string> GitFiles(string dir)
    {
        var r = Proc.RunAsync("git", ["ls-files", "-z"], dir).GetAwaiter().GetResult();
        return r.StdOut.Split('\0', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}

public static class CodeNav
{
    static readonly Regex MethodSig = new(@"^\s*(?:(?:public|private|internal|protected|static|async|override|virtual|sealed)\s+)+[\w<>\[\],\s\?]+\s+(\w+)\s*\(", RegexOptions.Compiled);

    /// <summary>Finds the enclosing C# method of a 1-based line: (name, startLine, endLine), both 1-based inclusive.</summary>
    public static (string Name, int Start, int End) EnclosingMethod(string[] lines, int line)
    {
        for (int i = Math.Min(line - 1, lines.Length - 1); i >= 0; i--)
        {
            var m = MethodSig.Match(lines[i]);
            if (!m.Success) continue;
            int depth = 0; bool opened = false;
            for (int j = i; j < lines.Length; j++)
            {
                foreach (var ch in lines[j]) { if (ch == '{') { depth++; opened = true; } else if (ch == '}') depth--; }
                if (opened && depth == 0) return (m.Groups[1].Value, i + 1, j + 1);
                if (!opened && lines[j].TrimEnd().EndsWith(';')) break; // expression-bodied / abstract
            }
            return (m.Groups[1].Value, i + 1, Math.Min(lines.Length, line + 5));
        }
        return ("<file>", Math.Max(1, line - 5), Math.Min(lines.Length, line + 5));
    }
}
