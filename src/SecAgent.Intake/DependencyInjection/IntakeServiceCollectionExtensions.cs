using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Application;
using SecAgent.Intake.Application.Steps;
using SecAgent.Intake.Blob;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;
using SecAgent.Intake.Pipeline;
using SecAgent.Intake.Runs;
using SecAgent.Intake.Security;
using SecAgent.Intake.Storage;

namespace SecAgent.Intake;

/// <summary>The intake's single composition root. Everything is constructor-injected; the host only adds the pipeline-side ports:
/// <list type="bullet">
/// <item><see cref="IFindingSchemaValidator"/> (required; the pipeline's SchemaValidator),</item>
/// <item><see cref="IPrRunLauncher"/> and <see cref="IRunAdmission"/> (required when Intake:DispatcherEnabled),</item>
/// <item>optionally its own <see cref="SecretMasker"/> and <see cref="IMessageQueue"/> instances (registered before this call to share them;
/// otherwise the intake gets its own), and a <see cref="TimeProvider"/> (default: system clock).</item>
/// </list>
/// Adapters are selected by Intake:Adapters:* among keyed registrations ("local" here, "azure-*" from SecAgent.Intake.Azure).</summary>
public static class IntakeServiceCollectionExtensions
{
    public static IServiceCollection AddSecAgentIntake(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddLogging();
        services.AddOptions<IntakeOptions>().Bind(configuration.GetSection(IntakeOptions.SectionName)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<IntakeOptions>, IntakeOptionsPostConfigure>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<IntakeOptions>, IntakeOptionsValidator>());

        // Shared infrastructure (TryAdd: the host may already provide the pipeline's instances).
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<SecretMasker>();
        services.TryAddSingleton<IMessageQueue, InProcessQueue>();

        // Parsers (Strategy) + registry. BlackDuckRapidFieldMap is the one place the rapid-scan field names live.
        services.TryAddSingleton<BlackDuckRapidFieldMap>();
        services.AddIntakeParser<SarifParser>();
        services.AddIntakeParser<BlackDuckRapidScanParser>();
        services.TryAddSingleton<IFindingParserRegistry, FindingParserRegistry>();

        // Security.
        services.TryAddSingleton<IIntakeSecretProvider, EnvironmentIntakeSecretProvider>();
        services.TryAddSingleton<IIntakeAuthenticator, HmacIntakeAuthenticator>();

        // Application: metadata → pipeline of steps (Chain of Responsibility) → webhook / blob entry points.
        services.TryAddSingleton<IIntakeMetadataReader, IntakeMetadataReader>();
        services.AddIntakeStep<PayloadLimitsStep>();
        services.AddIntakeStep<DuplicateFastPathStep>();
        services.AddIntakeStep<ParseStep>();
        services.AddIntakeStep<ClaimStep>();
        services.AddIntakeStep<StoreRawStep>();
        services.AddIntakeStep<CanonicalFindingsStep>();
        services.AddIntakeStep<EnqueueRunStep>();
        services.TryAddSingleton<IIntakeAcceptor, IntakePipeline>();
        services.TryAddSingleton<IIntakeWebhookHandler, IntakeWebhookHandler>();
        services.TryAddSingleton<IBlobIntakeHandler, IntakeFromBlobHandler>();

        // Local adapters (keyed), then the port → adapter selection by configuration (Abstract Factory over keyed services).
        services.AddKeyedSingleton(LocalRawFindingStore.BlobStoreKey, (sp, _) => new LocalBlobStore(Opts(sp).RawStoreRoot));
        services.AddKeyedSingleton<IRawFindingStore, LocalRawFindingStore>(IntakeAdapterKeys.Local);
        services.AddKeyedSingleton<FileIntakeLedger>(IntakeAdapterKeys.Local);
        services.AddKeyedSingleton<IIntakeLedger>(IntakeAdapterKeys.Local, (sp, k) => sp.GetRequiredKeyedService<FileIntakeLedger>(k));
        services.AddKeyedSingleton<IIntakeRecordQuery>(IntakeAdapterKeys.Local, (sp, k) => sp.GetRequiredKeyedService<FileIntakeLedger>(k));
        services.AddKeyedSingleton<LocalIntakeRunQueue>(IntakeAdapterKeys.Local);
        services.AddKeyedSingleton<IRunStarter>(IntakeAdapterKeys.Local, (sp, k) => sp.GetRequiredKeyedService<LocalIntakeRunQueue>(k));
        services.AddKeyedSingleton<IIntakeRunSource>(IntakeAdapterKeys.Local, (sp, k) => sp.GetRequiredKeyedService<LocalIntakeRunQueue>(k));
        services.AddKeyedSingleton<IBlobReader, LocalDropFolderBlobReader>(IntakeAdapterKeys.Local);

        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IRawFindingStore>(Opts(sp).Adapters.RawStore));
        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IIntakeLedger>(Opts(sp).Adapters.Ledger));
        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IIntakeRecordQuery>(Opts(sp).Adapters.Ledger));
        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IRunStarter>(Opts(sp).Adapters.RunQueue));
        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IIntakeRunSource>(Opts(sp).Adapters.RunQueue));
        services.TryAddSingleton(sp => sp.GetRequiredKeyedService<IBlobReader>(Opts(sp).Adapters.BlobReader));

        // Port the pipeline consumes.
        services.TryAddSingleton<IExternalFindingSource, IntakeExternalFindingSource>();

        // Background work (hosted services): queue → pipeline dispatcher, and the dev drop-folder watcher (both no-ops when disabled).
        services.TryAddSingleton<IntakeRunDispatcher>();
        services.AddHostedService(sp => sp.GetRequiredService<IntakeRunDispatcher>());
        services.TryAddSingleton<LocalFileDropWatcher>();
        services.AddHostedService(sp => sp.GetRequiredService<LocalFileDropWatcher>());
        return services;
    }

    /// <summary>Registers another payload format (Open/Closed: no existing code changes).</summary>
    public static IServiceCollection AddIntakeParser<TParser>(this IServiceCollection services) where TParser : class, IFindingParser
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IFindingParser, TParser>());
        return services;
    }

    /// <summary>Adds a step to the accept pipeline (ordered by <see cref="IIntakeStep.Order"/>).</summary>
    public static IServiceCollection AddIntakeStep<TStep>(this IServiceCollection services) where TStep : class, IIntakeStep
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IIntakeStep, TStep>());
        return services;
    }

    // Composition-root helper only (factories above); application classes receive IOptions<IntakeOptions> by constructor.
    static IntakeOptions Opts(IServiceProvider sp) => sp.GetRequiredService<IOptions<IntakeOptions>>().Value;
}
