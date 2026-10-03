using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Agents;
using SecAgent.Core;
using SecAgent.Intake;
using SecAgent.Intake.Application;
using SecAgent.Intake.Blob;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;
using SecAgent.Intake.Runs;
using SecAgent.Intake.Security;
using SecAgent.Intake.Storage;
using Xunit;

namespace SecAgent.Tests;

/// <summary>Records what the intake asked the pipeline to start (stands in for the queue + RunService).</summary>
public sealed class FakeRunStarter : IRunStarter
{
    public ConcurrentQueue<IntakeRunRequest> Requests { get; } = new();
    public Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct)
    {
        Requests.Enqueue(request);
        return Task.FromResult(new RunTicket("fake/" + request.IntakeId, true));
    }
}

/// <summary>Stands in for the dashboard's RunService adapter.</summary>
public sealed class FakePrRunLauncher : IPrRunLauncher
{
    public List<(string Repo, int Pr)> Started { get; } = [];
    public Guid RunId { get; } = Guid.NewGuid();
    public Task<Guid> StartPrRunAsync(string repo, int prNumber, CancellationToken ct) { lock (Started) Started.Add((repo, prNumber)); return Task.FromResult(RunId); }
}

public sealed class FakeRunAdmission : IRunAdmission
{
    public volatile bool Open = true;
    public bool CanStartRun => Open;
}

/// <summary>Controllable clock for the HMAC window and lease checks.</summary>
public sealed class ManualClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class FixedSecret(string? secret) : IIntakeSecretProvider
{
    public string? GetSecret() => secret;
}

/// <summary>Temp data root + the intake wired through its real composition root (services.AddSecAgentIntake) with test doubles only for
/// the pipeline-side ports (run launcher, admission) and, by default, the run starter.</summary>
public sealed class IntakeKit : IDisposable
{
    public const string Secret = "synthetic-intake-test-secret";
    public const string Sha = "0123456789abcdef0123456789abcdef01234567";
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "secagent-intake-" + Guid.NewGuid().ToString("N")[..8]);
    readonly string _secretEnv = "SECAGENT_INTAKE_TEST_SECRET_" + Guid.NewGuid().ToString("N")[..6];
    public ServiceProvider Services { get; }
    public FakeRunStarter Runs { get; } = new();
    public FakePrRunLauncher Launcher { get; } = new();
    public FakeRunAdmission Admission { get; } = new();

    readonly Action<IntakeOptions>? _configure;
    readonly bool _fakeRunStarter;
    readonly Action<IServiceCollection>? _services;

    public IntakeKit(Action<IntakeOptions>? configure = null, bool fakeRunStarter = true, Action<IServiceCollection>? services = null)
    {
        _ = TestEnv.Cfg;   // loads SECAGENT_HMAC_KEY (secret findings are HMAC'd)
        Environment.SetEnvironmentVariable(_secretEnv, Secret);
        (_configure, _fakeRunStarter, _services) = (configure, fakeRunStarter, services);
        Configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Intake:StorageRoot"] = Root, ["Intake:HmacSecretEnv"] = _secretEnv,
        }).Build();
        var sc = new ServiceCollection();
        Wire(sc);
        Services = sc.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        Services.GetRequiredService<IStartupValidator>().Validate();   // what ValidateOnStart does in a host
    }

    public IConfiguration Configuration { get; }

    /// <summary>The registrations a host makes (pipeline-side ports as test doubles) + the intake's composition root. Also used by the HTTP tests.</summary>
    public void Wire(IServiceCollection sc)
    {
        sc.AddSingleton(TestEnv.Cfg);
        sc.AddSingleton<JsonSchemaCache>();
        sc.AddSingleton<IFindingSchemaValidator, SchemaValidator>();
        sc.AddSingleton<IPrRunLauncher>(Launcher);
        sc.AddSingleton<IRunAdmission>(Admission);
        sc.AddSecAgentIntake(Configuration);
        if (_configure != null) sc.Configure(_configure);
        if (_fakeRunStarter) sc.Replace(ServiceDescriptor.Singleton<IRunStarter>(Runs));
        _services?.Invoke(sc);
    }

    public IntakeOptions Options => Services.GetRequiredService<IOptions<IntakeOptions>>().Value;
    public IIntakeAcceptor Acceptor => Services.GetRequiredService<IIntakeAcceptor>();
    public IIntakeMetadataReader Metadata => Services.GetRequiredService<IIntakeMetadataReader>();
    public FileIntakeLedger Ledger => (FileIntakeLedger)Services.GetRequiredService<IIntakeLedger>();
    public LocalBlobStore Blob => Services.GetRequiredKeyedService<LocalBlobStore>(LocalRawFindingStore.BlobStoreKey);
    public SecretMasker Masker => Services.GetRequiredService<SecretMasker>();
    public static SchemaValidator NewValidator() => new(TestEnv.Cfg, new JsonSchemaCache());
    public static IOptions<IntakeOptions> Defaults(Action<IntakeOptions>? configure = null)
    {
        var o = new IntakeOptions();
        configure?.Invoke(o);
        return Microsoft.Extensions.Options.Options.Create(o);
    }

    public static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine(TestEnv.RepoRoot, "tests", "SecAgent.Tests", "Fixtures", "intake", name));

    public static IntakeMetadata Meta(string format = IntakeFormats.Sarif, int? pr = 7, string runId = "1001-1", string sha = Sha, string repo = "synthetic-org/sample-orders") =>
        new() { Format = format, Repo = repo, PrNumber = pr, Ref = pr == null ? "main" : "feature/synthetic", HeadSha = sha, Scanner = "blackduck", RunId = runId };

    public void Dispose()
    {
        Services.DisposeAsync().AsTask().GetAwaiter().GetResult();   // async: some adapters (Service Bus) are IAsyncDisposable only
        Environment.SetEnvironmentVariable(_secretEnv, null);
        try
        {
            foreach (var f in Directory.GetFiles(Root, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(Root, true);
        }
        catch { }
    }
}

public class SarifParserTests
{
    static ParseOutcome Parse(string fixture, IntakeMetadata? meta = null)
    {
        _ = TestEnv.Cfg;
        return new SarifParser(IntakeKit.Defaults(), new SecretMasker()).Parse(IntakeKit.Fixture(fixture), meta ?? IntakeKit.Meta());
    }

    [Fact]
    public void Black_duck_grouped_component_rule_maps_to_one_vulnerable_dependency()
    {
        var f = Parse("blackduck-sca.sarif.json").Findings.Single(x => x.ScannerRuleId == "direct: Synthetic.Json 12.0.1");
        Assert.Equal(IssueTypes.VulnerableDependency, f.IssueType);
        Assert.Equal("blackduck", f.SourceScanner);
        Assert.Equal("11.0.0", f.ScannerVersion);
        Assert.Equal("Synthetic.Json", f.ComponentName);
        Assert.Equal("12.0.1", f.ComponentVersion);
        Assert.Equal(["CVE-2099-10001"], f.CveIds);
        Assert.Equal("BDSA-2099-0001", f.Attributes["advisory_ids"]);
        Assert.Equal("critical", f.SeverityScanner);                  // security-severity 8.1 = high, but a [:red_circle:] advisory → critical
        Assert.Equal("blackduck advisory marker", f.Attributes["severity_source"]);
        Assert.Equal("12.0.4", f.FixedVersion);                       // short-term upgrade guidance ("v12.0.4")
        Assert.Equal("13.0.1", f.Attributes["long_term_version"]);
        Assert.Equal("direct", f.DirectOrTransitive);
        Assert.Equal(["CWE-502"], f.CweIds);
        Assert.Null(f.FilePath);                                      // "file://unknown-file" placeholder
        Assert.Null(f.LineStart);
        Assert.Equal(IntakeKit.Sha, f.CommitSha);
        Assert.Equal(7, f.PrNumber);
        Assert.Matches("^[0-9a-f]{64}$", f.Fingerprint);
    }

    [Fact]
    public void Black_duck_transitive_component_reads_guidance_and_location()
    {
        var f = Parse("blackduck-sca.sarif.json").Findings.Single(x => x.ScannerRuleId.StartsWith("Synthetic Http Client"));
        Assert.Equal(("Synthetic Http Client", "4.0.2"), (f.ComponentName, f.ComponentVersion));
        Assert.Equal("transitive", f.DirectOrTransitive);
        Assert.Equal("4.0.9", f.FixedVersion);
        Assert.Equal("medium", f.SeverityScanner);
        Assert.Equal("pom.xml", f.FilePath);
        Assert.Equal(["CWE-400"], f.CweIds);
        Assert.Empty(f.CveIds);
        Assert.Equal("BDSA-2099-0002", f.Attributes["vulnerability_ids"]);
    }

    [Fact]
    public void Generic_result_properties_win_purl_cve_score_fixed_version()
    {
        var f = Parse("blackduck-sca.sarif.json").Findings.Single(x => x.ScannerRuleId == "synthetic.generic.vuln");
        Assert.Equal(IssueTypes.VulnerableDependency, f.IssueType);
        Assert.Equal("pkg:nuget/Synthetic.Logging", f.ComponentName);
        Assert.Equal("1.2.3", f.ComponentVersion);
        Assert.Equal("1.2.4", f.FixedVersion);
        Assert.Equal(["CVE-2099-20002"], f.CveIds);
        Assert.Equal("critical", f.SeverityScanner);                  // 9.8
        Assert.Equal("Synthetic.Logging", f.Attributes["package"]);   // what the library fixer reads
        Assert.Equal("src/SampleOrders.Api/packages.lock.json", f.FilePath);
        Assert.NotNull(f.FixGroupKey);
    }

    [Fact]
    public void Sast_rule_maps_to_unsafe_code_with_cwe_and_location()
    {
        var all = Parse("blackduck-sca.sarif.json").Findings.Where(x => x.ScannerRuleId == "sigma.synthetic_sql_injection:csharp").ToList();
        var f = all.Single(x => x.FilePath!.EndsWith("OrdersRepository.cs"));
        Assert.Equal(IssueTypes.UnsafeCode, f.IssueType);
        Assert.Equal(["CWE-89"], f.CweIds);
        Assert.Equal("high", f.SeverityScanner);
        Assert.Equal((42, 43), (f.LineStart!.Value, f.LineEnd!.Value));
        Assert.Equal("SQL Injection in src/SampleOrders.Api/Data/OrdersRepository.cs", f.Title);
        Assert.Null(f.ComponentName);                                 // SAST rules never get the SCA component heuristics
    }

    [Fact]
    public void Licence_suppressed_and_injection_results()
    {
        var p = Parse("blackduck-sca.sarif.json");
        var lic = p.Findings.Single(x => x.IssueType == IssueTypes.Licence);
        Assert.Equal(("GPL-3.0-only", "pkg:npm/synthetic-left-pad", "high"), (lic.LicenceId, lic.ComponentName, lic.SeverityScanner));
        Assert.DoesNotContain(p.Findings, x => x.FilePath?.EndsWith("Legacy.cs") == true);   // suppressed by the producer
        Assert.Contains(p.Notes, n => n.Contains("1 result(s) skipped"));
        Assert.True(p.Findings.Single(x => x.FilePath?.EndsWith("ReportsRepository.cs") == true).InjectionFlag);
        Assert.Equal(6, p.Findings.Count);
        Assert.Equal(("Black Duck SCA (Intelligent)", "11.0.0"), (p.ToolName, p.ToolVersion));
    }

    [Fact]
    public void Secret_result_keeps_only_an_hmac_and_raw_copy_is_redacted()
    {
        var masker = new SecretMasker();
        _ = TestEnv.Cfg;
        var parser = new SarifParser(IntakeKit.Defaults(), masker);
        var body = IntakeKit.Fixture("secret.sarif.json");
        var p = parser.Parse(body, IntakeKit.Meta());
        var f = Assert.Single(p.Findings);
        Assert.Equal(IssueTypes.Secret, f.IssueType);
        Assert.Equal("restricted", f.Classification);
        Assert.Equal(Hashing.Hmac("AKIAIOSFODNN7EXAMPLE"), f.SecretHash);   // gitleaks:allow (AWS documentation example key, synthetic)
        var stored = Encoding.UTF8.GetString(parser.Redact(body, p));
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", stored);               // gitleaks:allow
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", JsonSerializer.Serialize(f, Schema.Json));   // gitleaks:allow
        Assert.Contains("snippet removed at intake", stored);
    }

    [Theory]
    [InlineData("{\"version\":\"2.0.0\",\"runs\":[]}", 422, "only 2.1.0")]
    [InlineData("{\"version\":\"2.1.0\"}", 422, "'runs' must be an array")]
    [InlineData("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{}}]}", 422, "tool.driver is required")]
    [InlineData("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"x\"}},\"results\":[{\"ruleId\":\"r\"}]}]}", 422, "message must be an object")]
    [InlineData("[1,2,3]", 422, "root must be a JSON object")]
    [InlineData("{\"version\":\"2.1.0\",", 400, "not valid JSON")]
    public void Invalid_sarif_is_rejected(string body, int code, string why)
    {
        var e = Assert.Throws<IntakeRejectedException>(() => new SarifParser(IntakeKit.Defaults(), new SecretMasker()).Parse(Encoding.UTF8.GetBytes(body), IntakeKit.Meta()));
        Assert.Equal(code, e.StatusCode);
        Assert.Contains(why, e.Message);
    }

    [Fact]
    public void Too_many_results_is_rejected_before_mapping()
    {
        var results = string.Join(",", Enumerable.Range(0, 6).Select(i => $"{{\"ruleId\":\"r{i}\",\"message\":{{\"text\":\"m\"}}}}"));
        var body = Encoding.UTF8.GetBytes($"{{\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"x\"}}}},\"results\":[{results}]}}]}}");
        var e = Assert.Throws<IntakeRejectedException>(() => new SarifParser(IntakeKit.Defaults(o => o.MaxResults = 5), new SecretMasker()).Parse(body, IntakeKit.Meta()));
        Assert.Equal(413, e.StatusCode);
    }

    [Fact]
    public void Every_sarif_fixture_finding_passes_the_canonical_schema()
    {
        var v = IntakeKit.NewValidator();
        foreach (var fx in new[] { "blackduck-sca.sarif.json", "secret.sarif.json" })
            foreach (var f in Parse(fx).Findings)
            {
                f.RawEvidenceRef = "blob://raw/test"; f.CreatedByRun = Guid.NewGuid();
                Assert.Null(v.ValidateFinding(f));
            }
    }
}

public class BlackDuckRapidParserTests
{
    static ParseOutcome Parse(string fixture) => new BlackDuckRapidScanParser(IntakeKit.Defaults(), new SecretMasker(), new BlackDuckRapidFieldMap()).Parse(IntakeKit.Fixture(fixture), IntakeKit.Meta(IntakeFormats.BlackDuckRapid));

    [Fact]
    public void Component_with_policy_vulnerabilities_maps_to_one_finding()
    {
        var p = Parse("blackduck-rapid.json");
        var f = p.Findings.Single(x => x.ComponentName == "pkg:nuget/Synthetic.Json");
        Assert.Equal(IssueTypes.VulnerableDependency, f.IssueType);
        Assert.Equal("12.0.1", f.ComponentVersion);
        Assert.Equal("critical", f.SeverityScanner);                  // max of HIGH and CRITICAL
        Assert.Equal(["CVE-2099-0102"], f.CveIds);
        Assert.Equal("BDSA-2099-0101", f.Attributes["advisory_ids"]);
        Assert.Equal(["CWE-400", "CWE-502"], f.CweIds);
        Assert.Equal("12.0.4", f.FixedVersion);
        Assert.Equal("13.0.1", f.Attributes["long_term_version"]);
        Assert.Equal("direct", f.DirectOrTransitive);                 // one-element dependency tree
        Assert.Equal("Synthetic.Json", f.Attributes["package"]);
        Assert.Equal("nuget:Synthetic.Json/12.0.1", f.ScannerRuleId);
        Assert.Contains("BDSA-2099-0101:high:7.5", f.Attributes["vulnerabilities"]);
        Assert.Equal("rapid-scan", f.ScannerVersion);
    }

    [Fact]
    public void Licence_violation_policy_only_and_error_components()
    {
        var p = Parse("blackduck-rapid.json");
        var lic = p.Findings.Single(x => x.IssueType == IssueTypes.Licence);
        Assert.Equal(("GPL-3.0-only", "pkg:npm/synthetic-left-pad", "critical"), (lic.LicenceId, lic.ComponentName, lic.SeverityScanner));   // BLOCKER
        Assert.Equal("Reciprocal", lic.Attributes["licence_family"]);
        Assert.DoesNotContain(p.Findings, x => x.ComponentName == "pkg:maven/org.synthetic/commons");   // component policy only
        Assert.Contains(p.Notes, n => n.Contains("1 component(s) violate a policy with no vulnerability or licence detail"));
        Assert.Contains(p.Notes, n => n.Contains("errorMessage"));
        var broken = p.Findings.Single(x => x.ComponentName == "pkg:pypi/synthetic-broken");
        Assert.Equal("medium", broken.SeverityScanner);               // no vulnSeverity: score 4.2 → medium
        Assert.Equal(3, p.Findings.Count);
    }

    [Fact]
    public void Items_wrapper_and_component_location_shapes_are_accepted()
    {
        var wrapped = Encoding.UTF8.GetBytes("{\"items\":" + Encoding.UTF8.GetString(IntakeKit.Fixture("blackduck-rapid.json")) + "}");
        Assert.Equal(3, new BlackDuckRapidScanParser(IntakeKit.Defaults(), new SecretMasker(), new BlackDuckRapidFieldMap()).Parse(wrapped, IntakeKit.Meta(IntakeFormats.BlackDuckRapid)).Findings.Count);
        var f = Assert.Single(Parse("blackduck-components-with-locations.json").Findings);
        Assert.Equal(("pkg:maven/org.synthetic/synthetic-yaml", "1.30", "1.33"), (f.ComponentName, f.ComponentVersion, f.FixedVersion));
        Assert.Equal(("build.gradle.kts", 12), (f.FilePath, f.LineStart!.Value));
        Assert.Equal("high", f.SeverityScanner);
    }

    [Theory]
    [InlineData("maven:org.apache.pdfbox:pdfbox:2.0.12", "pkg:maven/org.apache.pdfbox/pdfbox", "2.0.12")]
    [InlineData("npmjs:handlebars/4.0.11", "pkg:npm/handlebars", "4.0.11")]
    [InlineData("nuget:Newtonsoft.Json/12.0.1", "pkg:nuget/Newtonsoft.Json", "12.0.1")]
    [InlineData("npmjs:@scope/pkg/1.0.0", "pkg:npm/@scope/pkg", "1.0.0")]
    [InlineData("someforge:thing/2", "someforge:thing", "2")]
    public void Black_duck_ids_become_purl_style_names(string id, string name, string version) =>
        Assert.Equal((name, version), ParserUtil.FromBlackDuckId(id)!.Value);

    [Fact]
    public void Non_array_payload_is_rejected()
    {
        var e = Assert.Throws<IntakeRejectedException>(() => new BlackDuckRapidScanParser(IntakeKit.Defaults(), new SecretMasker(), new BlackDuckRapidFieldMap()).Parse(Encoding.UTF8.GetBytes("{\"version\":\"2.1.0\"}"), IntakeKit.Meta(IntakeFormats.BlackDuckRapid)));
        Assert.Equal(422, e.StatusCode);
    }
}

public class IntakeHmacTests
{
    static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"version\":\"2.1.0\",\"runs\":[]}");
    static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_790_000_000);

    static Dictionary<string, string> Signed(IntakeMetadata m, byte[] body, string secret = IntakeKit.Secret, long? ts = null)
    {
        var h = IntakeSignature.HeadersFor(m);
        var t = (ts ?? Now.ToUnixTimeSeconds()).ToString();
        h[IntakeHeaders.Timestamp] = t;
        h[IntakeHeaders.Signature] = IntakeSignature.Sign(secret, m.Format, h, t, body);
        return h;
    }
    static HmacIntakeAuthenticator Auth(string? secret = IntakeKit.Secret) => new(new FixedSecret(secret), IntakeKit.Defaults(), new ManualClock(Now));

    [Fact]
    public void Valid_signature_is_accepted() => Assert.True(Auth().Authenticate("sarif", Signed(IntakeKit.Meta(), Body), Body).Ok);

    [Fact]
    public void Tampered_body_is_rejected()
    {
        var h = Signed(IntakeKit.Meta(), Body);
        var r = Auth().Authenticate("sarif", h, Encoding.UTF8.GetBytes("{\"version\":\"2.1.0\",\"runs\":[{}]}"));
        Assert.False(r.Ok); Assert.Contains("mismatch", r.Error);
    }

    [Theory]
    [InlineData("X-SecAgent-Pr", "8")]
    [InlineData("X-SecAgent-Repo", "other-org/sample-orders")]
    [InlineData("X-SecAgent-Head-Sha", "ffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("X-SecAgent-Run-Id", "1001-2")]
    public void Tampered_metadata_is_rejected(string header, string value)
    {
        var h = Signed(IntakeKit.Meta(), Body);
        h[header] = value;
        Assert.False(Auth().Authenticate("sarif", h, Body).Ok);
    }

    [Fact]
    public void Format_is_part_of_the_signature() => Assert.False(Auth().Authenticate("blackduck-rapid", Signed(IntakeKit.Meta(), Body), Body).Ok);

    [Fact]
    public void Wrong_secret_stale_timestamp_missing_headers_and_unconfigured_server_are_rejected()
    {
        Assert.False(Auth().Authenticate("sarif", Signed(IntakeKit.Meta(), Body, secret: "another-secret"), Body).Ok);
        var stale = Auth().Authenticate("sarif", Signed(IntakeKit.Meta(), Body, ts: Now.ToUnixTimeSeconds() - 301), Body);
        Assert.False(stale.Ok); Assert.Contains("window", stale.Error);
        var noSig = Signed(IntakeKit.Meta(), Body); noSig.Remove(IntakeHeaders.Signature);
        Assert.False(Auth().Authenticate("sarif", noSig, Body).Ok);
        var noTs = Signed(IntakeKit.Meta(), Body); noTs.Remove(IntakeHeaders.Timestamp);
        Assert.False(Auth().Authenticate("sarif", noTs, Body).Ok);
        Assert.Contains("not configured", Auth(null).Authenticate("sarif", Signed(IntakeKit.Meta(), Body), Body).Error);
    }

    [Fact]
    public void Upper_case_hex_signature_is_accepted()
    {
        var h = Signed(IntakeKit.Meta(), Body);
        h[IntakeHeaders.Signature] = "sha256=" + h[IntakeHeaders.Signature][7..].ToUpperInvariant();
        Assert.True(Auth().Authenticate("sarif", h, Body).Ok);
    }
}

public class IntakeServiceTests
{
    static string Status(IntakeResult r) => JsonSerializer.SerializeToElement(r.Body, Schema.Json).GetProperty("status").GetString()!;

    [Fact]
    public async Task Accepts_stores_raw_and_canonical_and_enqueues_once()
    {
        using var k = new IntakeKit();
        var r = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("blackduck-sca.sarif.json"), "test", default);
        Assert.Equal(202, r.StatusCode);
        var req = Assert.Single(k.Runs.Requests);
        Assert.Equal(("synthetic-org/sample-orders", 7, "pr", 6), (req.Repo, req.PrNumber!.Value, req.Mode, req.Findings));
        var rec = k.Ledger.Get(IntakeKit.Meta().IdempotencyKey)!;
        Assert.Equal(IntakeStatus.Queued, rec.Status);
        Assert.StartsWith("blob://raw/intake/synthetic-org/sample-orders/" + IntakeKit.Sha + "/blackduck-1001-1", rec.RawUri);
        Assert.True(k.Blob.Verify(rec.RawUri!, rec.RawHash!));
        var canonical = JsonSerializer.Deserialize<List<Finding>>(k.Blob.Read(rec.CanonicalUri!), Schema.Json)!;
        Assert.Equal(6, canonical.Count);
        Assert.All(canonical, f => { Assert.Equal(rec.RawUri, f.RawEvidenceRef); Assert.Equal(rec.IntakeId, f.Attributes[ExternalFindingPolicy.IntakeIdAttribute]); });
        Assert.All(canonical, f => Assert.Null(IntakeKit.NewValidator().ValidateFinding(f)));
    }

    [Fact]
    public async Task Same_payload_again_is_a_duplicate_and_does_not_enqueue()
    {
        using var k = new IntakeKit();
        var body = IntakeKit.Fixture("blackduck-sca.sarif.json");
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(), body, "test", default)).StatusCode);
        var again = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), body, "test", default);
        Assert.Equal((200, "duplicate"), (again.StatusCode, Status(again)));
        Assert.Single(k.Runs.Requests);
        // A GitHub re-run has a new run attempt → new key → processed.
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(runId: "1001-2"), body, "test", default)).StatusCode);
        Assert.Equal(2, k.Runs.Requests.Count);
    }

    [Fact]
    public async Task Different_payload_under_the_same_key_is_a_conflict()
    {
        using var k = new IntakeKit();
        await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("blackduck-sca.sarif.json"), "test", default);
        var r = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("secret.sarif.json"), "test", default);
        Assert.Equal(409, r.StatusCode);
        Assert.Single(k.Runs.Requests);
    }

    [Fact]
    public async Task Parallel_identical_deliveries_are_accepted_exactly_once()
    {
        using var k = new IntakeKit();
        var body = IntakeKit.Fixture("blackduck-rapid.json");
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => k.Acceptor.AcceptAsync(IntakeKit.Meta(IntakeFormats.BlackDuckRapid), body, "test", default))));
        Assert.Single(k.Runs.Requests);
        Assert.Equal(1, results.Count(r => r.StatusCode == 202));
        Assert.All(results, r => Assert.Contains(r.StatusCode, new[] { 200, 202 }));
    }

    [Fact]
    public async Task Oversize_and_invalid_payloads_are_rejected_and_store_nothing()
    {
        using var k = new IntakeKit(o => o.MaxBodyBytes = 1024);
        var big = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("blackduck-sca.sarif.json"), "test", default);
        Assert.Equal(413, big.StatusCode);
        var bad = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), Encoding.UTF8.GetBytes("{\"version\":\"1.0\",\"runs\":[]}"), "test", default);
        Assert.Equal((422, "rejected"), (bad.StatusCode, Status(bad)));
        var empty = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), Array.Empty<byte>(), "test", default);
        Assert.Equal(400, empty.StatusCode);
        Assert.Empty(k.Runs.Requests);
        Assert.Empty(k.Ledger.All());                                   // a rejected payload does not burn the idempotency key
        Assert.False(Directory.Exists(Path.Combine(k.Root, "blob", "raw")));
        // the same key still works with a valid payload
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("secret.sarif.json"), "test", default)).StatusCode);
    }

    [Fact]
    public async Task Secret_value_never_reaches_disk()
    {
        using var k = new IntakeKit();
        Assert.Equal(202, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(), IntakeKit.Fixture("secret.sarif.json"), "test", default)).StatusCode);
        foreach (var f in Directory.GetFiles(k.Root, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", File.ReadAllText(f));   // gitleaks:allow (synthetic)
    }

    [Theory]
    [InlineData("X-SecAgent-Head-Sha", "abc123", 400)]
    [InlineData("X-SecAgent-Repo", "not a repo", 400)]
    [InlineData("X-SecAgent-Repo", "outside-org/repo", 403)]
    [InlineData("X-SecAgent-Scanner", "codeql", 400)]
    [InlineData("X-SecAgent-Pr", "-3", 400)]
    [InlineData("X-SecAgent-Ref", "bad..ref", 400)]
    [InlineData("X-SecAgent-Run-Id", "", 400)]
    public void Metadata_is_validated(string header, string value, int code)
    {
        using var k = new IntakeKit(o => o.AllowedRepos = ["synthetic-org/*"]);
        var h = IntakeSignature.HeadersFor(IntakeKit.Meta());
        h[header] = value;
        var e = Assert.Throws<IntakeRejectedException>(() => k.Metadata.Read("sarif", h));
        Assert.Equal(code, e.StatusCode);
    }

    [Fact]
    public void Unknown_format_is_404_and_backlog_mode_has_no_pr()
    {
        using var k = new IntakeKit();
        Assert.Equal(404, Assert.Throws<IntakeRejectedException>(() => k.Metadata.Read("cyclonedx", IntakeSignature.HeadersFor(IntakeKit.Meta()))).StatusCode);
        var m = k.Metadata.Read("sarif", IntakeSignature.HeadersFor(IntakeKit.Meta(pr: null)));
        Assert.Equal(("backlog", "main"), (m.Mode, m.Branch));
    }

    [Fact]
    public async Task Interrupted_claim_is_resumed_by_a_retry()
    {
        using var k = new IntakeKit();
        var body = IntakeKit.Fixture("blackduck-rapid.json");
        var meta = IntakeKit.Meta(IntakeFormats.BlackDuckRapid);
        // simulate a crash after the key was claimed but before anything was queued
        k.Ledger.TryClaim(new IntakeRecord { Key = meta.IdempotencyKey, BodySha256 = Hashing.Sha256(body), Meta = meta, UpdatedAt = DateTime.UtcNow.AddMinutes(-10) }, out _);
        var inProgress = new IntakeRecord { Key = IntakeKit.Meta(IntakeFormats.BlackDuckRapid, runId: "9-1").IdempotencyKey, BodySha256 = Hashing.Sha256(body) };
        k.Ledger.TryClaim(inProgress, out _);   // fresh claim held by a concurrent delivery
        Assert.Equal(200, (await k.Acceptor.AcceptAsync(IntakeKit.Meta(IntakeFormats.BlackDuckRapid, runId: "9-1"), body, "test", default)).StatusCode);
        var r = await k.Acceptor.AcceptAsync(meta, body, "test", default);
        Assert.Equal(202, r.StatusCode);
        Assert.Single(k.Runs.Requests);
        Assert.Equal(IntakeStatus.Queued, k.Ledger.Get(meta.IdempotencyKey)!.Status);
    }
}

public class IntakeRunPathTests
{
    [Fact]
    public async Task External_findings_are_served_for_the_exact_head_sha_latest_run_wins()
    {
        using var k = new IntakeKit();
        await k.Acceptor.AcceptAsync(IntakeKit.Meta(IntakeFormats.BlackDuckRapid, runId: "1-1"), IntakeKit.Fixture("blackduck-rapid.json"), "test", default);
        await Task.Delay(20);
        await k.Acceptor.AcceptAsync(IntakeKit.Meta(IntakeFormats.BlackDuckRapid, runId: "1-2"), IntakeKit.Fixture("blackduck-components-with-locations.json"), "test", default);
        var src = k.Services.GetRequiredService<IExternalFindingSource>();
        var batch = Assert.Single(src.ForHead("Synthetic-Org/Sample-Orders", IntakeKit.Sha.ToUpperInvariant()));
        Assert.Equal("blackduck", batch.Scanner);
        Assert.Single(batch.Findings);                                  // run attempt 2 replaced attempt 1
        Assert.True(ExternalFindingPolicy.IsExternal(batch.Findings[0]));
        Assert.Empty(src.ForHead("synthetic-org/sample-orders", new string('e', 40)));   // PR moved on: stale results are not used
        var again = src.ForHead("synthetic-org/sample-orders", IntakeKit.Sha);
        Assert.NotEqual(batch.Findings[0].FindingId, again[0].Findings[0].FindingId); // fresh copies per run
    }

    [Fact]
    public void Verifier_never_treats_external_findings_as_locally_verifiable()
    {
        var local = new Finding { SourceScanner = "trivy" };
        var external = new Finding { SourceScanner = "blackduck", Attributes = new() { [ExternalFindingPolicy.IntakeIdAttribute] = "x" } };
        Assert.Equal([external], ExternalFindingPolicy.NotLocallyVerifiable([local, external]));
    }

    [Fact]
    public async Task Queue_dispatcher_starts_pr_runs_and_parks_backlog_mode()
    {
        using var k = new IntakeKit(fakeRunStarter: false);   // real local run queue (in-process IMessageQueue)
        var meta = IntakeKit.Meta(IntakeFormats.BlackDuckRapid);
        var backlog = IntakeKit.Meta(IntakeFormats.BlackDuckRapid, pr: null, runId: "2002-1");
        await k.Acceptor.AcceptAsync(meta, IntakeKit.Fixture("blackduck-rapid.json"), "test", default);
        await k.Acceptor.AcceptAsync(backlog, IntakeKit.Fixture("blackduck-rapid.json"), "test", default);
        // MessageId = idempotency key: a second publish of the same request is dropped by duplicate detection
        Assert.False(k.Services.GetRequiredService<IMessageQueue>().Publish(LocalIntakeRunQueue.QueueName, meta.IdempotencyKey, "dup"));

        var source = k.Services.GetRequiredService<IIntakeRunSource>();
        var d = k.Services.GetRequiredService<IntakeRunDispatcher>();
        k.Admission.Open = false;
        var first = await source.ReceiveAsync(default);
        var pending = d.HandleAsync(first!, default);
        await Task.Delay(300);
        Assert.Empty(k.Launcher.Started);                               // a run is active / kill switch on: wait
        k.Admission.Open = true;
        await pending;
        await d.HandleAsync((await source.ReceiveAsync(default))!, default);
        Assert.Null(await source.ReceiveAsync(default));                // both completed
        Assert.Equal(("synthetic-org/sample-orders", 7), Assert.Single(k.Launcher.Started));
        var rec = k.Ledger.Get(meta.IdempotencyKey)!;
        Assert.Equal((IntakeStatus.RunStarted, k.Launcher.RunId), (rec.Status, rec.RunId!.Value));
        Assert.Equal(IntakeStatus.BacklogPending, k.Ledger.Get(backlog.IdempotencyKey)!.Status);
    }

    [Fact]
    public async Task Local_drop_folder_feeds_the_blob_handler()
    {
        using var k = new IntakeKit();
        var w = k.Services.GetRequiredService<LocalFileDropWatcher>();
        Directory.CreateDirectory(w.Folder);
        File.WriteAllBytes(Path.Combine(w.Folder, "pr7.sarif.json"), IntakeKit.Fixture("blackduck-sca.sarif.json"));
        File.WriteAllText(Path.Combine(w.Folder, "pr7.sarif.json.meta.json"), JsonSerializer.Serialize(new
        {
            repo = "synthetic-org/sample-orders", pr = "7", @ref = "feature/synthetic", head_sha = IntakeKit.Sha, scanner = "blackduck", run_id = "drop-1",
        }));
        File.WriteAllText(Path.Combine(w.Folder, "bad.json"), "{}");
        File.WriteAllText(Path.Combine(w.Folder, "bad.json.meta.json"), "{\"repo\":\"synthetic-org/sample-orders\"}");
        File.WriteAllText(Path.Combine(w.Folder, "waiting.sarif.json"), "{}");   // no sidecar yet: left alone
        var done = await w.ScanAsync(default);
        Assert.Equal(2, done.Count);
        Assert.Equal(400, done.Single(d => d.File.EndsWith("bad.json")).Result.StatusCode);
        Assert.Equal(202, done.Single(d => d.File.EndsWith("pr7.sarif.json")).Result.StatusCode);
        Assert.Single(k.Runs.Requests);
        Assert.True(File.Exists(Path.Combine(w.Folder, "waiting.sarif.json")));
        Assert.Single(Directory.GetFiles(Path.Combine(w.Folder, "processed"), "*-pr7.sarif.json"));
        Assert.Single(Directory.GetFiles(Path.Combine(w.Folder, "rejected"), "*-bad.json"));
    }

    [Fact]
    public async Task Blob_handler_infers_the_format_from_the_file_name_via_the_parser_registry()
    {
        using var k = new IntakeKit();
        Directory.CreateDirectory(k.Options.DropFolder);
        var file = Path.Combine(k.Options.DropFolder, "orders_1.0_BlackDuck_DeveloperMode_Result.json");
        File.WriteAllBytes(file, IntakeKit.Fixture("blackduck-rapid.json"));
        var md = new Dictionary<string, string> { ["repo"] = "synthetic-org/sample-orders", ["pr"] = "7", ["head_sha"] = IntakeKit.Sha, ["scanner"] = "blackduck", ["run_id"] = "blob-1" };
        var r = await k.Services.GetRequiredService<IBlobIntakeHandler>().HandleAsync(new BlobCreatedEvent(new Uri(file).AbsoluteUri, Path.GetFileName(file), new FileInfo(file).Length, md), default);
        Assert.Equal(202, r.StatusCode);
        Assert.Equal(IntakeFormats.BlackDuckRapid, k.Ledger.All().Single().Meta!.Format);
        // the local blob reader refuses files outside the drop folder
        var outside = Path.Combine(k.Root, "outside.json");
        File.WriteAllText(outside, "[]");
        await Assert.ThrowsAsync<IOException>(() => k.Services.GetRequiredService<IBlobReader>().ReadAsync(new BlobCreatedEvent(new Uri(outside).AbsoluteUri, "outside.json", 2, md), 100, default));
    }

    [Fact]
    public void Intake_assemblies_expose_no_merge_or_approve_method()
    {
        var methods = new[] { typeof(IntakePipeline).Assembly, typeof(IFindingParser).Assembly, typeof(SecAgent.Intake.Azure.AzureBlobRawFindingStore).Assembly }
            .SelectMany(a => a.GetTypes())
            .SelectMany(t => t.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.DeclaredOnly))
            .Where(m => m.Name.Contains("merge", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("approve", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.Empty(methods);
    }
}
