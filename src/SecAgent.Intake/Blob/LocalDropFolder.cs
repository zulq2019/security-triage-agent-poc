using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Application;
using SecAgent.Intake.Configuration;

namespace SecAgent.Intake.Blob;

/// <summary>Local adapter for <see cref="IBlobReader"/>: reads files from the drop folder only (path traversal outside it is refused).</summary>
public sealed class LocalDropFolderBlobReader(IOptions<IntakeOptions> options) : IBlobReader
{
    public async Task<byte[]> ReadAsync(BlobCreatedEvent evt, long maxBytes, CancellationToken ct)
    {
        var dir = Path.GetFullPath(options.Value.DropFolder);
        var path = Path.GetFullPath(new Uri(evt.Url).LocalPath);
        if (!path.StartsWith(dir, StringComparison.Ordinal)) throw new IOException("blob outside the drop folder");
        return await File.ReadAllBytesAsync(path, ct);
    }
}

/// <summary>Dev stand-in for Blob + Event Grid: drop "&lt;name&gt;.sarif.json" (or any .json) plus "&lt;name&gt;.sarif.json.meta.json" into the drop folder.
/// The payload is picked up once its sidecar exists; afterwards both files move to processed/ (or rejected/ with a .result.json).
/// Turns files into <see cref="BlobCreatedEvent"/>s for <see cref="IBlobIntakeHandler"/>; reading is the <see cref="IBlobReader"/>'s job.
/// Hosted service: watches only when Intake:DropWatcherEnabled is true; the constructor has no side effects.</summary>
public sealed class LocalFileDropWatcher : IHostedService, IDisposable
{
    readonly bool _enabled;
    readonly string _dir;
    readonly IBlobIntakeHandler _handler;
    readonly TimeProvider _clock;
    readonly SecretMasker _masker;
    readonly ILogger<LocalFileDropWatcher> _log;
    readonly SemaphoreSlim _gate = new(1, 1);
    FileSystemWatcher? _fsw;

    public LocalFileDropWatcher(IOptions<IntakeOptions> options, IBlobIntakeHandler handler, TimeProvider clock, SecretMasker masker, ILogger<LocalFileDropWatcher> log)
    {
        _dir = options.Value.DropFolder; _enabled = options.Value.DropWatcherEnabled; _handler = handler; _clock = clock; _masker = masker; _log = log;
    }

    public Task StartAsync(CancellationToken ct) { if (_enabled) Start(); return Task.CompletedTask; }
    public Task StopAsync(CancellationToken ct) { if (_fsw != null) _fsw.EnableRaisingEvents = false; return Task.CompletedTask; }

    public string Folder => _dir;

    public void Start()
    {
        Directory.CreateDirectory(_dir);
        _fsw ??= new FileSystemWatcher(_dir) { IncludeSubdirectories = false };
        _fsw.Created += (_, _) => _ = ScanAsync(CancellationToken.None);
        _fsw.Renamed += (_, _) => _ = ScanAsync(CancellationToken.None);
        _fsw.EnableRaisingEvents = true;
        _ = ScanAsync(CancellationToken.None);
    }

    /// <summary>Processes every complete pair in the folder (also callable directly, e.g. from tests).</summary>
    public async Task<List<(string File, IntakeResult Result)>> ScanAsync(CancellationToken ct)
    {
        var done = new List<(string, IntakeResult)>();
        await _gate.WaitAsync(ct);
        try
        {
            Directory.CreateDirectory(_dir);
            foreach (var meta in Directory.GetFiles(_dir, "*.meta.json").Order())
            {
                var payload = meta[..^".meta.json".Length];
                if (!File.Exists(payload)) continue;
                IntakeResult r;
                try
                {
                    var md = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(await File.ReadAllTextAsync(meta, ct))!
                        .ToDictionary(kv => kv.Key.ToLowerInvariant(), kv => kv.Value.ValueKind == JsonValueKind.String ? kv.Value.GetString()! : kv.Value.ToString());
                    var evt = new BlobCreatedEvent(new Uri(payload).AbsoluteUri, Path.GetFileName(payload), new FileInfo(payload).Length, md);
                    r = await _handler.HandleAsync(evt, ct);
                }
                catch (Exception e) when (e is JsonException or IOException) { r = IntakeResult.Rejected(400, "bad sidecar: " + e.Message); }
                var target = Path.Combine(_dir, r.IsSuccess ? "processed" : "rejected");
                Directory.CreateDirectory(target);
                var stamp = _clock.GetUtcNow().ToString("yyyyMMddHHmmssfff");
                File.Move(payload, Path.Combine(target, stamp + "-" + Path.GetFileName(payload)), true);
                File.Move(meta, Path.Combine(target, stamp + "-" + Path.GetFileName(meta)), true);
                await File.WriteAllTextAsync(Path.Combine(target, stamp + "-" + Path.GetFileName(payload) + ".result.json"), JsonSerializer.Serialize(new { r.StatusCode, r.Body }), ct);
                _log.LogInformation("intake drop {File} → {Status}", _masker.Mask(Path.GetFileName(payload), false), r.StatusCode);
                done.Add((payload, r));
            }
        }
        finally { _gate.Release(); }
        return done;
    }

    public void Dispose() { _fsw?.Dispose(); _gate.Dispose(); }
}
