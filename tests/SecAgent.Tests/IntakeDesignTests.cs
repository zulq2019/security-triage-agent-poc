using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
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
using SecAgent.Intake.Azure;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;
using Xunit;

namespace SecAgent.Tests;

/// <summary>Design guarantees of the intake refactor: composition root, options validation, strategy registry, pipeline extension,
/// injected clock, adapter selection by configuration, dependency direction.</summary>
public class IntakeDesignTests
{
    // ---- Options pattern -----------------------------------------------------------------------------------------------

    [Fact]
    public void Options_bind_from_the_dashboard_appsettings_and_derive_folders_from_the_storage_root()
    {
        var root = Path.Combine(Path.GetTempPath(), "secagent-opt-" + Guid.NewGuid().ToString("N")[..6]);
        var config = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(TestEnv.RepoRoot, "src", "SecAgent.Dashboard", "appsettings.json"))
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Intake:StorageRoot"] = root }).Build();
        using var sp = new ServiceCollection().AddSecAgentIntake(config).BuildServiceProvider();
        sp.GetRequiredService<IStartupValidator>().Validate();
        var o = sp.GetRequiredService<IOptions<IntakeOptions>>().Value;
        Assert.True(o.Enabled);
        Assert.Equal("SECAGENT_INTAKE_HMAC_SECRET", o.HmacSecretEnv);
        Assert.Contains("blackduck", o.AllowedScanners);
        Assert.Equal(26214400, o.MaxBodyBytes);
        Assert.Equal(IntakeAdapterKeys.Local, o.Adapters.RawStore);
        Assert.Equal(Path.Combine(root, "blob"), o.RawStoreRoot);
        Assert.Equal(Path.Combine(root, "intake", "ledger"), o.LedgerFolder);
        Assert.Equal(Path.Combine(root, "intake", "drop"), o.DropFolder);
        Assert.True(o.RepoAllowed("anything/goes"));
        Assert.True(new IntakeOptions { AllowedRepos = ["synthetic-org/*"] }.RepoAllowed("Synthetic-Org/x"));
        Assert.False(new IntakeOptions { AllowedRepos = ["synthetic-org/*"] }.RepoAllowed("other/x"));
    }

    [Theory]
    [InlineData("Intake:MaxBodyBytes", "0", "MaxBodyBytes")]
    [InlineData("Intake:TimestampToleranceSeconds", "99999", "TimestampToleranceSeconds")]
    [InlineData("Intake:StorageRoot", "", "StorageRoot")]
    [InlineData("Intake:AllowedRepos:0", "no-slash", "AllowedRepos")]
    [InlineData("Intake:Adapters:RunQueue", "azure-servicebus", "AddSecAgentIntakeAzure")]
    [InlineData("Intake:Adapters:RawStore", "s3", "has no registered IRawFindingStore")]
    public void Invalid_configuration_fails_on_start(string key, string value, string expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Intake:StorageRoot"] = Path.Combine(Path.GetTempPath(), "secagent-opt"), [key] = value,
        }).Build();
        using var sp = new ServiceCollection().AddSecAgentIntake(config).BuildServiceProvider();
        var e = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IStartupValidator>().Validate());
        Assert.Contains(expected, e.Message);
    }

    // ---- Strategy: parser registry ----------------------------------------------------------------------------------------

    [Fact]
    public void Registry_resolves_parsers_by_format_infers_from_file_names_and_refuses_duplicates()
    {
        using var k = new IntakeKit();
        var reg = k.Services.GetRequiredService<IFindingParserRegistry>();
        Assert.Equal([IntakeFormats.BlackDuckRapid, IntakeFormats.Sarif], reg.Formats.Order());
        Assert.True(reg.TryGet("SARIF", out var p) && p is SarifParser);
        Assert.Equal(IntakeFormats.BlackDuckRapid, reg.InferFormat("svc_1.2_BlackDuck_DeveloperMode_Result.json"));
        Assert.Null(reg.InferFormat("report.sarif.json"));
        var masker = new SecretMasker();
        var e = Assert.Throws<InvalidOperationException>(() => new FindingParserRegistry([new SarifParser(IntakeKit.Defaults(), masker), new SarifParser(IntakeKit.Defaults(), masker)]));
        Assert.Contains("two intake parsers", e.Message);
    }

    /// <summary>A new format is one class + one registration: no change to the intake, the endpoint or the pipeline.</summary>
    sealed class SyntheticLinesParser : IFindingParser
    {
        public string Format => "synthetic-lines";
        public string RawFileExtension => "lines.txt";
        public ParseOutcome Parse(ReadOnlyMemory<byte> payload, IntakeMetadata meta)
        {
            var findings = Encoding.UTF8.GetString(payload.Span).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => new Finding
            {
                SourceScanner = meta.Scanner, ScannerVersion = "1", ScannerRuleId = "synthetic.rule", IssueType = IssueTypes.UnsafeCode,
                SeverityScanner = "low", Title = line.Trim(), Message = line.Trim(), Fingerprint = Hashing.Sha256(line), Repo = meta.Repo,
                Branch = meta.Branch, CommitSha = meta.HeadSha, PrNumber = meta.PrNumber,
            }).ToList();
            return new ParseOutcome(findings, "synthetic-lines", "1", []);
        }
        public byte[] Redact(ReadOnlyMemory<byte> payload, ParseOutcome parsed) => payload.ToArray();
    }

    [Fact]
    public async Task A_new_parser_registered_in_DI_is_routed_end_to_end()
    {
        using var k = new IntakeKit(services: sc => sc.AddIntakeParser<SyntheticLinesParser>());
        var meta = IntakeKit.Meta("synthetic-lines");
        var parsed = k.Metadata.Read("synthetic-lines", IntakeSignature.HeadersFor(meta));
        var r = await k.Acceptor.AcceptAsync(parsed, Encoding.UTF8.GetBytes("first synthetic issue\nsecond synthetic issue\n"), "test", default);
        Assert.Equal(202, r.StatusCode);
        Assert.Equal(2, Assert.Single(k.Runs.Requests).Findings);
        Assert.EndsWith(".lines.txt", k.Ledger.Get(parsed.IdempotencyKey)!.RawUri);
    }

    // ---- Chain of responsibility: pipeline steps ------------------------------------------------------------------------------

    sealed class RejectMarkedPayloadStep : IIntakeStep
    {
        public int Order => 250;   // after the duplicate fast path, before parsing / claiming
        public Task<IntakeResult?> ExecuteAsync(IntakeContext ctx, CancellationToken ct) =>
            Encoding.UTF8.GetString(ctx.Body.Span).Contains("SYNTHETIC-QUARANTINE") ? throw new IntakeRejectedException(422, "quarantined payload") : Task.FromResult<IntakeResult?>(null);
    }

    [Fact]
    public async Task Custom_steps_slot_into_the_pipeline_by_order()
    {
        using var k = new IntakeKit(services: sc => sc.AddIntakeStep<RejectMarkedPayloadStep>());
        var steps = k.Services.GetServices<IIntakeStep>().OrderBy(s => s.Order).Select(s => s.GetType().Name).ToList();
        Assert.Equal(["PayloadLimitsStep", "DuplicateFastPathStep", "RejectMarkedPayloadStep", "ParseStep", "ClaimStep", "StoreRawStep", "CanonicalFindingsStep", "EnqueueRunStep"], steps);
        var body = Encoding.UTF8.GetBytes("{\"version\":\"2.1.0\",\"runs\":[],\"note\":\"SYNTHETIC-QUARANTINE\"}");
        var r = await k.Acceptor.AcceptAsync(IntakeKit.Meta(), body, "test", default);
        Assert.Equal(422, r.StatusCode);
        Assert.Empty(k.Ledger.All());
        Assert.Empty(k.Runs.Requests);
    }

    // ---- Injected time / secret -------------------------------------------------------------------------------------------

    [Fact]
    public async Task Hmac_window_uses_the_injected_clock_and_missing_secret_is_503()
    {
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));
        using var k = new IntakeKit(services: sc => sc.Replace(ServiceDescriptor.Singleton<TimeProvider>(clock)));
        var handler = k.Services.GetRequiredService<IIntakeWebhookHandler>();
        var body = IntakeKit.Fixture("blackduck-rapid.json");
        var meta = IntakeKit.Meta(IntakeFormats.BlackDuckRapid);
        Dictionary<string, string> Signed()
        {
            var h = IntakeSignature.HeadersFor(meta);
            var ts = clock.Now.ToUnixTimeSeconds().ToString();
            h[IntakeHeaders.Timestamp] = ts;
            h[IntakeHeaders.Signature] = IntakeSignature.Sign(IntakeKit.Secret, meta.Format, h, ts, body);
            return h;
        }
        var signed = Signed();
        clock.Now = clock.Now.AddSeconds(301);                          // delivered 5 minutes later
        Assert.Equal(401, (await handler.HandleAsync(meta.Format, signed, body, default)).StatusCode);
        Assert.Equal(202, (await handler.HandleAsync(meta.Format, Signed(), body, default)).StatusCode);

        using var noSecret = new IntakeKit(services: sc => sc.Replace(ServiceDescriptor.Singleton<IIntakeSecretProvider>(new FixedSecret(null))));
        Assert.Equal(503, noSecret.Services.GetRequiredService<IIntakeWebhookHandler>().Precheck(10)!.StatusCode);
        using var disabled = new IntakeKit(o => o.Enabled = false);
        Assert.Equal(503, disabled.Services.GetRequiredService<IIntakeWebhookHandler>().Precheck(10)!.StatusCode);
        Assert.Equal(413, k.Services.GetRequiredService<IIntakeWebhookHandler>().Precheck(k.Options.MaxBodyBytes + 1)!.StatusCode);
    }

    // ---- Ports & adapters: selection by configuration -------------------------------------------------------------------------

    [Fact]
    public void Azure_adapters_are_selected_by_configuration_without_touching_the_intake()
    {
        var azure = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Intake:Azure:BlobServiceUri"] = "https://syntheticintake.blob.core.windows.net",
            ["Intake:Azure:ServiceBusNamespace"] = "synthetic-intake.servicebus.windows.net",
        }).Build();
        using var k = new IntakeKit(o => { o.Adapters.RawStore = IntakeAdapterKeys.AzureBlob; o.Adapters.BlobReader = IntakeAdapterKeys.AzureBlob; o.Adapters.RunQueue = IntakeAdapterKeys.AzureServiceBus; },
            fakeRunStarter: false, services: sc => sc.AddSecAgentIntakeAzure(azure));
        Assert.IsType<AzureBlobRawFindingStore>(k.Services.GetRequiredService<IRawFindingStore>());
        Assert.IsType<AzureBlobReader>(k.Services.GetRequiredService<IBlobReader>());
        Assert.IsType<ServiceBusIntakeRunQueue>(k.Services.GetRequiredService<IRunStarter>());
        Assert.Same(k.Services.GetRequiredService<IRunStarter>(), k.Services.GetRequiredService<IIntakeRunSource>());

        using var local = new IntakeKit(fakeRunStarter: false);
        Assert.IsType<SecAgent.Intake.Storage.LocalRawFindingStore>(local.Services.GetRequiredService<IRawFindingStore>());
        Assert.IsType<SecAgent.Intake.Runs.LocalIntakeRunQueue>(local.Services.GetRequiredService<IRunStarter>());
    }

    // ---- Injected schema cache (no process-wide static) ----------------------------------------------------------------------

    [Fact]
    public void Schema_cache_is_an_injected_instance_and_separate_instances_coexist()
    {
        var finding = new SarifParser(IntakeKit.Defaults(), new SecretMasker()).Parse(IntakeKit.Fixture("blackduck-sca.sarif.json"), IntakeKit.Meta()).Findings[0];
        finding.RawEvidenceRef = "blob://raw/test"; finding.CreatedByRun = Guid.NewGuid();
        var cacheA = new JsonSchemaCache();
        var a1 = new SchemaValidator(TestEnv.Cfg, cacheA);
        var a2 = new SchemaValidator(TestEnv.Cfg, cacheA);
        var b = new SchemaValidator(TestEnv.Cfg, new JsonSchemaCache());   // would throw "Overwriting registered schemas" with the global registry
        Assert.Null(a1.ValidateFinding(finding));
        Assert.Null(a2.ValidateFinding(finding));
        Assert.Null(b.ValidateFinding(finding));
        Assert.Equal(1, cacheA.Count);                                  // compiled once per cache
        Assert.Empty(typeof(SchemaValidator).GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public));
    }

    // ---- Dependency direction / no hidden singletons -----------------------------------------------------------------------

    static string[] SecAgentRefs(Assembly a) => a.GetReferencedAssemblies().Select(r => r.Name!).Where(n => n.StartsWith("SecAgent.")).Order().ToArray();

    [Fact]
    public void Dependencies_point_inwards_to_the_abstractions()
    {
        Assert.Equal(["SecAgent.Core"], SecAgentRefs(typeof(IFindingParser).Assembly));                         // Abstractions → domain only
        Assert.Equal(["SecAgent.Abstractions", "SecAgent.Core"], SecAgentRefs(typeof(IntakePipeline).Assembly));  // Intake: no pipeline, no host
        Assert.Equal(["SecAgent.Abstractions", "SecAgent.Core"], SecAgentRefs(typeof(AzureBlobRawFindingStore).Assembly));
        Assert.DoesNotContain("SecAgent.Intake", SecAgentRefs(typeof(AgentServices).Assembly));                   // pipeline knows only the port
    }

    [Fact]
    public void Intake_assemblies_have_no_mutable_static_state()
    {
        var offenders = new[] { typeof(IntakePipeline).Assembly, typeof(IFindingParser).Assembly, typeof(AzureBlobRawFindingStore).Assembly }
            .SelectMany(a => a.GetTypes())
            .Where(t => t.Namespace?.StartsWith("SecAgent.") == true && t.GetCustomAttribute<CompilerGeneratedAttribute>() == null)
            .SelectMany(t => t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
                .Where(f => !f.IsLiteral && !f.IsInitOnly && f.GetCustomAttribute<CompilerGeneratedAttribute>() == null)
                .Select(f => $"{t.FullName}.{f.Name}"))
            .ToList();
        Assert.Empty(offenders);
    }

    [Fact]
    public void Container_builds_with_validation_and_every_application_service_resolves()
    {
        using var k = new IntakeKit(fakeRunStarter: false);   // ValidateOnBuild already ran in the kit
        foreach (var t in new[] { typeof(IIntakeWebhookHandler), typeof(IIntakeAcceptor), typeof(IIntakeMetadataReader), typeof(SecAgent.Intake.Blob.IBlobIntakeHandler),
                     typeof(IExternalFindingSource), typeof(IIntakeAuthenticator), typeof(IRunStarter), typeof(IIntakeRunSource), typeof(IIntakeRecordQuery) })
            Assert.NotNull(k.Services.GetRequiredService(t));
        Assert.Same(k.Services.GetRequiredService<IIntakeLedger>(), k.Services.GetRequiredService<IIntakeRecordQuery>());
    }
}
