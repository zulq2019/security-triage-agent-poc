using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using SecAgent.Core;

namespace SecAgent.Hosting;

/// <summary>Optional capability of an <see cref="IMessageQueue"/> whose receives are leased claims (like a Service Bus lock): the consumer
/// renews the lease while its handler runs. Separate from IMessageQueue (Core), which the in-process queue implements without leases.</summary>
public interface IMessageLeaseRenewal
{
    /// <summary>Restarts the lease of a received, unsettled message. False when the claim is gone (expired and taken by another consumer).</summary>
    bool RenewLease(QueueMessage message);
}

/// <summary><see cref="IMessageQueue"/> over a shared folder, so several containers on one machine (docker compose) can pass messages
/// without a broker. Stands in for Service Bus locally; not for production.
/// <para>Layout per queue: <c>ready/</c> (FIFO by file name), <c>inflight/</c> (claimed: an atomic rename to a name unique to this claim,
/// so only one consumer gets a message), <c>dlq/</c>, <c>seen/</c> (duplicate detection by MessageId within a window). A claim older than the
/// lease is put back (crash recovery, like a Service Bus lock expiring); a running handler keeps its claim alive with
/// <see cref="RenewLease"/>. Settling a claim that was already recovered and re-claimed touches nothing (each claim has its own file name).
/// Delivery counts are kept in the file, so they survive restarts.</para></summary>
public sealed class FileSystemMessageQueue : IMessageQueue, IAgentTransportHealth, IMessageLeaseRenewal
{
    readonly string _root;
    readonly int _maxDeliveries;
    readonly TimeSpan _dedupeWindow, _lease;
    readonly TimeProvider _clock;
    readonly ConditionalWeakTable<QueueMessage, string> _claims = new();
    readonly ConcurrentDictionary<string, DateTimeOffset> _lastRecovery = new();
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public FileSystemMessageQueue(string root, int maxDeliveries = 3, TimeSpan? dedupeWindow = null, TimeSpan? lease = null, TimeProvider? clock = null)
    {
        _root = Path.GetFullPath(root);
        _maxDeliveries = maxDeliveries;
        _dedupeWindow = dedupeWindow ?? TimeSpan.FromMinutes(10);
        _lease = lease ?? TimeSpan.FromMinutes(5);
        _clock = clock ?? TimeProvider.System;
        Directory.CreateDirectory(_root);
    }

    public string Root => _root;

    sealed record Stored(string MessageId, string Body, int DeliveryCount, DateTime EnqueuedAt, string? Error);

    /// <summary>Folder name for a queue or subscription entity ("run-events/subscriptions/audit" → "run-events_subscriptions_audit").
    /// Only letters, digits and '-' survive, so an entity name can never climb out of the root.</summary>
    public static string SafeName(string entity) => string.Concat(entity.Select(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-' ? ch : '_'));

    string Dir(string queue, string sub)
    {
        var d = Path.Combine(_root, SafeName(queue), sub);
        Directory.CreateDirectory(d);
        return d;
    }

    string NewName(string messageId) => $"{_clock.GetUtcNow().UtcTicks:D20}-{Hashing.Sha256(messageId + Guid.NewGuid())[..12]}.json";

    public bool Publish(string queue, string messageId, object body)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var seen = Path.Combine(Dir(queue, "seen"), Hashing.Sha256(messageId)[..32]);
        try { using (new FileStream(seen, FileMode.CreateNew, FileAccess.Write)) { } }
        catch (IOException) when (File.Exists(seen))
        {
            if (now - File.GetLastWriteTimeUtc(seen) < _dedupeWindow) return false;   // duplicate detection
            File.SetLastWriteTimeUtc(seen, now);
        }
        var text = body as string ?? JsonSerializer.Serialize(body, Schema.Json);
        Write(Path.Combine(Dir(queue, "ready"), NewName(messageId)), new Stored(messageId, text, 0, now, null), queue);
        return true;
    }

    void Write(string path, Stored s, string queue)
    {
        var tmp = Path.Combine(Dir(queue, "tmp"), Guid.NewGuid().ToString("N"));
        File.WriteAllText(tmp, JsonSerializer.Serialize(s, Json));
        File.Move(tmp, path, overwrite: true);   // atomic on one file system: readers never see half a message
    }

    public bool TryReceive(string queue, out QueueMessage? message)
    {
        RecoverExpired(queue);
        var ready = Dir(queue, "ready");
        var inflight = Dir(queue, "inflight");
        foreach (var file in Directory.EnumerateFiles(ready, "*.json").Order(StringComparer.Ordinal))
        {
            var claimed = Path.Combine(inflight, ClaimName(file));
            try { File.Move(file, claimed); }
            catch (IOException) { continue; }          // another consumer claimed it first
            catch (UnauthorizedAccessException) { continue; }
            Stored s;
            try { s = JsonSerializer.Deserialize<Stored>(File.ReadAllText(claimed), Json)!; }
            catch (JsonException) { File.Move(claimed, Path.Combine(Dir(queue, "dlq"), Path.GetFileName(file)), overwrite: true); continue; }
            s = s with { DeliveryCount = s.DeliveryCount + 1 };
            Write(claimed, s, queue);                  // persists the count
            File.SetLastWriteTimeUtc(claimed, _clock.GetUtcNow().UtcDateTime);   // starts the lease (mtime, on the queue's clock)
            var m = new QueueMessage { Queue = queue, MessageId = s.MessageId, Body = s.Body, DeliveryCount = s.DeliveryCount, Error = s.Error, EnqueuedAt = s.EnqueuedAt };
            _claims.AddOrUpdate(m, claimed);
            message = m;
            return true;
        }
        message = null;
        return false;
    }

    public async IAsyncEnumerable<QueueMessage> ReceiveAsync(string queue, [EnumeratorCancellation] CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            if (TryReceive(queue, out var m) && m != null) yield return m;
            else await Task.Delay(TimeSpan.FromMilliseconds(250), _clock, ct);
        }
    }

    /// <summary>"…/ready/0001-abc.json" → "0001-abc~&lt;claim id&gt;.json". The claim id makes a re-claim after lease expiry a different file.</summary>
    static string ClaimName(string readyFile) => $"{Path.GetFileNameWithoutExtension(readyFile)}~{Guid.NewGuid():N}.json";

    /// <summary>Inverse of <see cref="ClaimName"/>: the ready/ name a recovered claim goes back under (same FIFO position).</summary>
    static string ReadyName(string claimFile)
    {
        var name = Path.GetFileNameWithoutExtension(claimFile);
        var i = name.IndexOf('~');
        return (i > 0 ? name[..i] : name) + ".json";
    }

    public bool RenewLease(QueueMessage m)
    {
        if (!_claims.TryGetValue(m, out var path)) return false;
        try { File.SetLastWriteTimeUtc(path, _clock.GetUtcNow().UtcDateTime); return true; }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException) { return false; }   // recovered by a peer
    }

    public void Complete(QueueMessage m)
    {
        // A claim recovered after its lease (and possibly re-claimed under a new name) is simply gone: nothing to delete.
        if (_claims.TryGetValue(m, out var path)) { _claims.Remove(m); File.Delete(path); }
    }

    public void Abandon(QueueMessage m, string error)
    {
        if (!_claims.TryGetValue(m, out var path)) return;
        _claims.Remove(m);
        if (!File.Exists(path)) return;   // claim lost to lease recovery: the message is already back in circulation, do not duplicate it
        m.Error = error;
        var s = new Stored(m.MessageId, m.Body, m.DeliveryCount, m.EnqueuedAt, error);
        var target = m.DeliveryCount >= _maxDeliveries ? Path.Combine(Dir(m.Queue, "dlq"), ReadyName(path)) : Path.Combine(Dir(m.Queue, "ready"), NewName(m.MessageId));
        Write(target, s, m.Queue);
        File.Delete(path);
    }

    public IReadOnlyList<QueueMessage> DeadLetters(string queue) =>
        Directory.EnumerateFiles(Dir(queue, "dlq"), "*.json").Order(StringComparer.Ordinal)
            .Select(f => JsonSerializer.Deserialize<Stored>(File.ReadAllText(f), Json)!)
            .Select(s => new QueueMessage { Queue = queue, MessageId = s.MessageId, Body = s.Body, DeliveryCount = s.DeliveryCount, Error = s.Error, EnqueuedAt = s.EnqueuedAt })
            .ToList();

    /// <summary>Messages in ready/ (for tests and diagnostics).</summary>
    public int ReadyCount(string queue) => Directory.EnumerateFiles(Dir(queue, "ready"), "*.json").Count();

    /// <summary>Claims older than the lease go back to ready/ (their consumer crashed or was killed before settling).</summary>
    void RecoverExpired(string queue)
    {
        var now = _clock.GetUtcNow();
        if (_lastRecovery.TryGetValue(queue, out var last) && now - last < TimeSpan.FromSeconds(5)) return;
        _lastRecovery[queue] = now;
        foreach (var f in Directory.EnumerateFiles(Dir(queue, "inflight"), "*.json"))
            if (now.UtcDateTime - File.GetLastWriteTimeUtc(f) > _lease)
                try { File.Move(f, Path.Combine(Dir(queue, "ready"), ReadyName(f))); } catch (IOException) { }
    }

    public Task<(bool Ok, string Detail)> CheckAsync(CancellationToken ct)
    {
        try
        {
            var probe = Path.Combine(_root, $".probe-{Environment.ProcessId}");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return Task.FromResult((true, $"file queue at {_root}"));
        }
        catch (Exception e) { return Task.FromResult((false, $"file queue at {_root} not writable: {e.Message}")); }
    }
}
