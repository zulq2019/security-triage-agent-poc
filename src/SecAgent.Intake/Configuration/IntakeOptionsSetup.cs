using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;

namespace SecAgent.Intake.Configuration;

/// <summary>Fills folder defaults from StorageRoot after binding.</summary>
internal sealed class IntakeOptionsPostConfigure : IPostConfigureOptions<IntakeOptions>
{
    public void PostConfigure(string? name, IntakeOptions o)
    {
        if (string.IsNullOrWhiteSpace(o.StorageRoot)) return;
        if (string.IsNullOrWhiteSpace(o.RawStoreRoot)) o.RawStoreRoot = Path.Combine(o.StorageRoot, "blob");
        if (string.IsNullOrWhiteSpace(o.LedgerFolder)) o.LedgerFolder = Path.Combine(o.StorageRoot, "intake", "ledger");
        if (string.IsNullOrWhiteSpace(o.DropFolder)) o.DropFolder = Path.Combine(o.StorageRoot, "intake", "drop");
    }
}

/// <summary>Start-up validation (ValidateOnStart): bad configuration stops the host instead of failing on the first request.
/// Also checks that every configured adapter key has a registered implementation.</summary>
internal sealed class IntakeOptionsValidator(IServiceProviderIsKeyedService keyed) : IValidateOptions<IntakeOptions>
{
    public ValidateOptionsResult Validate(string? name, IntakeOptions o)
    {
        var errors = new List<string>();
        void Check(bool ok, string message) { if (!ok) errors.Add(message); }

        Check(!string.IsNullOrWhiteSpace(o.HmacSecretEnv), "Intake:HmacSecretEnv is required (name of the env var holding the HMAC secret)");
        Check(o.TimestampToleranceSeconds is >= 30 and <= 3600, "Intake:TimestampToleranceSeconds must be 30..3600");
        Check(o.MaxBodyBytes is > 0 and <= 512L * 1024 * 1024, "Intake:MaxBodyBytes must be 1..536870912");
        Check(o.MaxResults is > 0 and <= 1_000_000, "Intake:MaxResults must be 1..1000000");
        Check(o.MaxJsonDepth is >= 8 and <= 256, "Intake:MaxJsonDepth must be 8..256");
        Check(o.ClaimLeaseSeconds is >= 5 and <= 3600, "Intake:ClaimLeaseSeconds must be 5..3600");
        Check(o.AllowedScanners.Count > 0, "Intake:AllowedScanners must not be empty");
        Check(o.AllowedScanners.All(s => s.Length is > 0 and <= 40 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')),
            "Intake:AllowedScanners entries must be scanner ids (letters, digits, - and _; max 40)");
        Check(o.AllowedRepos.All(p => p.Contains('/') && !p.TrimEnd('*').Contains('*')), "Intake:AllowedRepos entries must look like owner/name or owner/*");
        Check(!string.IsNullOrWhiteSpace(o.DefaultBlobFormat), "Intake:DefaultBlobFormat is required");

        bool Local(string key) => key == IntakeAdapterKeys.Local;
        if (Local(o.Adapters.RawStore)) Check(!string.IsNullOrWhiteSpace(o.RawStoreRoot), "Intake:StorageRoot (or Intake:RawStoreRoot) is required for the local raw store");
        if (Local(o.Adapters.Ledger)) Check(!string.IsNullOrWhiteSpace(o.LedgerFolder), "Intake:StorageRoot (or Intake:LedgerFolder) is required for the local ledger");
        if (o.DropWatcherEnabled) Check(!string.IsNullOrWhiteSpace(o.DropFolder), "Intake:DropFolder is required when the drop watcher is enabled");

        foreach (var (port, key, type) in new[]
        {
            ("RawStore", o.Adapters.RawStore, typeof(IRawFindingStore)), ("Ledger", o.Adapters.Ledger, typeof(IIntakeLedger)),
            ("RunQueue", o.Adapters.RunQueue, typeof(IRunStarter)), ("BlobReader", o.Adapters.BlobReader, typeof(IBlobReader)),
        })
            Check(keyed.IsKeyedService(type, key), $"Intake:Adapters:{port} = '{key}' has no registered {type.Name} (local adapters are built in; Azure ones need services.AddSecAgentIntakeAzure)");

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
