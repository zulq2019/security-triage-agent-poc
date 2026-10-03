using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SecAgent.Agents;
using SecAgent.Agents.Llm;
using SecAgent.Core;
using SecAgent.Eval.Cases;
using SecAgent.Eval.Checks;
using SecAgent.Eval.Fixers;
using SecAgent.Eval.Models;
using SecAgent.Eval.Reporting;
using SecAgent.Eval.Scoring;
using SecAgent.Eval.Stages;
using SecAgent.Eval.Verification;
using SecAgent.Eval.Workspace;

namespace SecAgent.Eval.Composition;

/// <summary>Composition root of the evaluation harness. Every service is constructor-injected; strategies (model client per mode, fixer per
/// fixer id, checker per check type, gate rules, report writers) are added with the AddXxx extension methods below.</summary>
public static class EvalServiceCollectionExtensions
{
    public static IServiceCollection AddSecAgentEval(this IServiceCollection services, Action<EvalOptions> configure)
    {
        services.AddOptions<EvalOptions>().Configure(configure).PostConfigure(o => o.ApplyDefaults());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<EvalOptions>, EvalOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);

        // Pipeline building blocks reused as-is (same rules-as-code, schemas, masking, context assembly).
        services.AddSingleton(sp =>
        {
            var o = sp.GetRequiredService<IOptions<EvalOptions>>().Value;
            return o.Mode is EvalModes.Live or EvalModes.Record ? ConfigSnapshot.Load(o.RulesRoot, ModelProviderSettings.Load(o.RepoRoot)) : ConfigSnapshot.Load(o.RulesRoot);
        });
        services.AddSingleton<JsonSchemaCache>();
        services.AddSingleton<SchemaValidator>();
        services.AddSingleton<SecretMasker>();
        services.AddSingleton<ContextAssembler>();

        // Cases and workspaces
        services.AddSingleton<ICaseSource, FileSystemCaseSource>();
        services.AddSingleton<IProcessRunner, ProcessRunner>();
        services.AddSingleton<ISyntheticSecretGenerator, DeterministicSecretGenerator>();
        services.AddSingleton<ICaseWorkspaceFactory, GitCaseWorkspaceFactory>();
        services.AddSingleton<IGitDiff, GitDiff>();

        // Model port: one strategy per mode, chosen by EvalOptions.Mode
        services.AddSingleton<ICassetteStore, FileCassetteStore>();
        services.AddKeyedSingleton<IEvalModelClient, ReplayModelClient>(EvalModes.Replay);
        services.AddKeyedSingleton<IEvalModelClient, LiveModelClient>(EvalModes.Live);
        services.AddKeyedSingleton<IEvalModelClient, RecordingModelClient>(EvalModes.Record);
        services.AddKeyedSingleton<IEvalModelClient, StampingModelClient>(EvalModes.Stamp);
        services.AddSingleton(sp => sp.GetRequiredKeyedService<IEvalModelClient>(sp.GetRequiredService<IOptions<EvalOptions>>().Value.Mode));

        // Stages
        services.AddSingleton<IModelStep, ModelStep>();
        services.AddSingleton<ITriageStage, TriageStage>();
        services.AddSingleton<IFixRouter, RoutingTableFixRouter>();
        services.AddSingleton<IPackageVersionResolver, OfflinePackageVersionResolver>();
        services.AddEvalFixer<LibraryEvalFixer>().AddEvalFixer<SecretsEvalFixer>().AddEvalFixer<UnsafeCodeEvalFixer>().AddEvalFixer<BinaryLicenceEvalFixer>();
        services.AddSingleton<IBuildRunner, DotnetBuildRunner>();
        services.AddSingleton<IFindingScanner, RegexRuleScanner>();
        services.AddSingleton<ICaseEvidenceFactory, CaseEvidenceFactory>();
        services.AddSingleton<IVerifyStage, VerifyStage>();
        services.AddSingleton<ICaseRunner, CaseRunner>();

        // Scoring: one checker per check type
        services.AddOutcomeChecker<TriageDecisionChecker>().AddOutcomeChecker<FixerChecker>().AddOutcomeChecker<OutcomeChecker>()
            .AddOutcomeChecker<SeverityChecker>().AddOutcomeChecker<HumanTaskChecker>().AddOutcomeChecker<InjectionFlagChecker>()
            .AddOutcomeChecker<BuildsChecker>().AddOutcomeChecker<TestsPassChecker>().AddOutcomeChecker<PatternAbsentChecker>()
            .AddOutcomeChecker<PatternPresentChecker>().AddOutcomeChecker<PackageVersionChecker>().AddOutcomeChecker<NoNewFindingsChecker>()
            .AddOutcomeChecker<AllowedFilesChecker>().AddOutcomeChecker<NoChangesChecker>().AddOutcomeChecker<FileAbsentChecker>()
            .AddOutcomeChecker<SecretNotExposedChecker>();
        services.AddSingleton<ICheckerRegistry, CheckerRegistry>();

        // Baseline, gates, reports
        services.AddSingleton<IBaselineStore, FileBaselineStore>();
        services.AddGateRule<MinPassRateGate>().AddGateRule<NoRegressionGate>().AddGateRule<MaxUnsafeOutcomesGate>().AddGateRule<MaxErrorsGate>();
        services.AddSingleton<IGateEvaluator, GateEvaluator>();
        services.AddReportWriter<JsonReportWriter>().AddReportWriter<MarkdownReportWriter>();
        services.AddSingleton<IEvalRunner, EvalRunner>();
        return services;
    }

    public static IServiceCollection AddOutcomeChecker<T>(this IServiceCollection s) where T : class, IOutcomeChecker
    { s.TryAddEnumerable(ServiceDescriptor.Singleton<IOutcomeChecker, T>()); return s; }

    public static IServiceCollection AddEvalFixer<T>(this IServiceCollection s) where T : class, IEvalFixer
    { s.TryAddEnumerable(ServiceDescriptor.Singleton<IEvalFixer, T>()); return s; }

    public static IServiceCollection AddGateRule<T>(this IServiceCollection s) where T : class, IGateRule
    { s.TryAddEnumerable(ServiceDescriptor.Singleton<IGateRule, T>()); return s; }

    public static IServiceCollection AddReportWriter<T>(this IServiceCollection s) where T : class, IReportWriter
    { s.TryAddEnumerable(ServiceDescriptor.Singleton<IReportWriter, T>()); return s; }
}
