using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Storage;

/// <summary>Local adapter for the ledger ports: one JSON file per key ({LedgerFolder}/&lt;key&gt;.json). The claim uses FileMode.CreateNew,
/// which is atomic across threads and processes, so two identical concurrent POSTs cannot both be accepted.
/// Every later write is a compare-and-set on the claim token (<see cref="TryUpdate"/>). Claim creation and compare-and-set run under one
/// ledger lock, so they are atomic with respect to each other within one process (the dev / single-instance setup); a multi-instance
/// deployment uses a cloud ledger adapter: a SQL table with a UNIQUE key column and a rowversion check, or Azure Table Storage
/// (Add → 409 Conflict, Replace with If-Match ETag).</summary>
public sealed class FileIntakeLedger : IIntakeLedger, IIntakeRecordQuery
{
    readonly string _dir;
    readonly TimeProvider _clock;
    readonly Lock _lock = new();

    public FileIntakeLedger(IOptions<IntakeOptions> options, TimeProvider clock)
    {
        _dir = options.Value.LedgerFolder;
        _clock = clock;
        Directory.CreateDirectory(_dir);
    }

    string PathOf(string key) => Path.Combine(_dir, (key.All(Uri.IsHexDigit) ? key : Hashing.Sha256(key)) + ".json");

    public bool TryClaim(IntakeRecord record, out IntakeRecord existing)
    {
        var path = PathOf(record.Key);
        lock (_lock)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    JsonSerializer.Serialize(fs, record, Schema.JsonIndented);
                existing = record;
                return true;
            }
            catch (IOException) when (File.Exists(path))
            {
                existing = Read(path) ?? record;
                return false;
            }
        }
    }

    public LedgerWriteResult TryUpdate(IntakeRecord record, string expectedClaimToken)
    {
        var path = PathOf(record.Key);
        lock (_lock)
        {
            if (!File.Exists(path) || Read(path) is not { } current) return LedgerWriteResult.NotFound;
            if (current.ClaimToken != expectedClaimToken) return LedgerWriteResult.LostOwnership;
            record.UpdatedAt = _clock.GetUtcNow().UtcDateTime;
            var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(record, Schema.JsonIndented));
            File.Move(tmp, path, overwrite: true);
            return LedgerWriteResult.Updated;
        }
    }

    public IntakeRecord? Get(string key) => File.Exists(PathOf(key)) ? Read(PathOf(key)) : null;

    public IEnumerable<IntakeRecord> All() =>
        Directory.EnumerateFiles(_dir, "*.json").Select(Read).Where(r => r != null).Select(r => r!).OrderBy(r => r.ReceivedAt);

    static IntakeRecord? Read(string path)
    {
        for (int i = 0; i < 5; i++)
        {
            try { return JsonSerializer.Deserialize<IntakeRecord>(File.ReadAllText(path), Schema.Json); }
            catch (IOException) { Thread.Sleep(20); }      // concurrent writer holds the file
            catch (JsonException) { Thread.Sleep(20); }    // claim file being written
        }
        return null;
    }
}
