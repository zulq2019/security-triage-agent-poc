using System.Text.Json;

namespace SecAgent.Intake.Blob;

/// <summary>A "blob created" notification, shaped like the Event Grid Microsoft.Storage.BlobCreated event data we need:
/// subject "/blobServices/default/containers/{container}/blobs/{name}", url, contentLength. Metadata comes from the blob's own metadata
/// (x-ms-meta-repo, -pr, -ref, -head_sha, -scanner, -run_id, -format) or, for the local drop folder, a sidecar "&lt;file&gt;.meta.json".</summary>
public sealed record BlobCreatedEvent(string Url, string Name, long ContentLength, IReadOnlyDictionary<string, string> Metadata);

/// <summary>Reads blob content. Azure: BlobClient.DownloadContentAsync with the app's managed identity (Storage Blob Data Reader on the intake container).</summary>
public interface IBlobReader
{
    Task<byte[]> ReadAsync(BlobCreatedEvent evt, long maxBytes, CancellationToken ct);
}

/// <summary>Blob path: GitHub Action uploads the SARIF to a private intake container (OIDC → Azure, no shared secret) → Event Grid
/// BlobCreated → this handler → the same <see cref="IntakeService"/> as the webhook. Trust comes from who can write to the container
/// (RBAC) and from Event Grid delivery auth (Entra ID-protected webhook or an Azure Function trigger), so no HMAC check here.
/// The Event Grid webhook endpoint itself (subscription validation handshake + Entra token check) is a TODO: see docs/intake.md.</summary>
public sealed class IntakeFromBlobHandler(IntakeService intake, IBlobReader reader)
{
    public async Task<IntakeResult> HandleAsync(BlobCreatedEvent evt, CancellationToken ct)
    {
        var o = intake.Options;
        if (evt.ContentLength > o.MaxBodyBytes) return new IntakeResult(413, new { status = "rejected", error = $"blob is {evt.ContentLength} bytes; the limit is {o.MaxBodyBytes}" });
        var format = evt.Metadata.TryGetValue("format", out var fm) && fm.Length > 0 ? fm.ToLowerInvariant()
            : evt.Name.Contains("rapid", StringComparison.OrdinalIgnoreCase) || evt.Name.Contains("DeveloperMode", StringComparison.OrdinalIgnoreCase) ? IntakeFormats.BlackDuckRapid : IntakeFormats.Sarif;
        IntakeMetadata meta;
        try { meta = intake.ReadMetadata(format, evt.Metadata); }
        catch (IntakeRejectedException e) { return new IntakeResult(e.StatusCode, new { status = "rejected", error = e.Message }); }
        var body = await reader.ReadAsync(evt, o.MaxBodyBytes, ct);
        return await intake.AcceptAsync(meta, body, "blob", ct);
    }
}

/// <summary>Dev stand-in for Blob + Event Grid: drop "&lt;name&gt;.sarif.json" (or any .json) plus "&lt;name&gt;.sarif.json.meta.json" into the drop folder.
/// The payload is picked up once its sidecar exists; afterwards both files move to processed/ (or rejected/ with a .result.json).</summary>
public sealed class LocalFileDropWatcher : IDisposable, IBlobReader
{
    readonly string _dir;
    readonly IntakeFromBlobHandler _handler;
    readonly Action<string>? _log;
    readonly FileSystemWatcher _fsw;
    readonly SemaphoreSlim _gate = new(1, 1);

    public LocalFileDropWatcher(string dir, Func<IBlobReader, IntakeFromBlobHandler> handlerFactory, Action<string>? log = null)
    {
        _dir = dir; _log = log;
        Directory.CreateDirectory(dir);
        _handler = handlerFactory(this);
        _fsw = new FileSystemWatcher(dir) { IncludeSubdirectories = false, EnableRaisingEvents = false };
        _fsw.Created += (_, _) => _ = ScanAsync(CancellationToken.None);
        _fsw.Renamed += (_, _) => _ = ScanAsync(CancellationToken.None);
    }

    public string Folder => _dir;
    public void Start() { _fsw.EnableRaisingEvents = true; _ = ScanAsync(CancellationToken.None); }

    /// <summary>Processes every complete pair in the folder (also callable directly, e.g. from tests).</summary>
    public async Task<List<(string File, IntakeResult Result)>> ScanAsync(CancellationToken ct)
    {
        var done = new List<(string, IntakeResult)>();
        await _gate.WaitAsync(ct);
        try
        {
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
                catch (Exception e) when (e is JsonException or IOException) { r = new IntakeResult(400, new { status = "rejected", error = "bad sidecar: " + e.Message }); }
                var target = Path.Combine(_dir, r.StatusCode is 200 or 202 ? "processed" : "rejected");
                Directory.CreateDirectory(target);
                var stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
                File.Move(payload, Path.Combine(target, stamp + "-" + Path.GetFileName(payload)), true);
                File.Move(meta, Path.Combine(target, stamp + "-" + Path.GetFileName(meta)), true);
                await File.WriteAllTextAsync(Path.Combine(target, stamp + "-" + Path.GetFileName(payload) + ".result.json"), JsonSerializer.Serialize(new { r.StatusCode, r.Body }), ct);
                _log?.Invoke($"intake drop {Path.GetFileName(payload)} → {r.StatusCode}");
                done.Add((payload, r));
            }
        }
        finally { _gate.Release(); }
        return done;
    }

    public async Task<byte[]> ReadAsync(BlobCreatedEvent evt, long maxBytes, CancellationToken ct)
    {
        var path = new Uri(evt.Url).LocalPath;
        if (!Path.GetFullPath(path).StartsWith(Path.GetFullPath(_dir), StringComparison.Ordinal)) throw new IOException("blob outside the drop folder");
        return await File.ReadAllBytesAsync(path, ct);
    }

    public void Dispose() { _fsw.Dispose(); _gate.Dispose(); }
}
