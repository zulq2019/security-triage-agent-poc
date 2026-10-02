using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace SecAgent.Core;

public static class Telemetry
{
    public const string SourceName = "SecAgent";
    public static readonly ActivitySource Source = new(SourceName, "0.1.0");
    public static string TraceId => Activity.Current?.TraceId.ToString() ?? "";
    public static string SpanId => Activity.Current?.SpanId.ToString() ?? "";
}

/// <summary>Local folder standing in for Azure Blob (raw + evidence containers). Write-once: existing blobs are never overwritten.</summary>
public sealed class LocalBlobStore(string root)
{
    public string Root { get; } = root;

    public (string Uri, string Hash) Put(string container, string path, string content) => Put(container, path, Encoding.UTF8.GetBytes(content));

    public (string Uri, string Hash) Put(string container, string path, byte[] content)
    {
        var full = Path.Combine(Root, container, path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var hash = "sha256:" + Hashing.Sha256(content);
        if (File.Exists(full))
        {
            var existing = "sha256:" + Hashing.Sha256(File.ReadAllBytes(full));
            if (existing != hash) { full += "." + DateTime.UtcNow.Ticks; path += "." + DateTime.UtcNow.Ticks; }
            else return ($"blob://{container}/{path}", hash);
        }
        File.WriteAllBytes(full, content);
        try { File.SetAttributes(full, FileAttributes.ReadOnly); } catch { }
        return ($"blob://{container}/{path}", hash);
    }

    public string ResolvePath(string uri) => Path.Combine(Root, uri.Replace("blob://", ""));
    public string Read(string uri) => File.ReadAllText(ResolvePath(uri));
    public bool Verify(string uri, string hash) => File.Exists(ResolvePath(uri)) && "sha256:" + Hashing.Sha256(File.ReadAllBytes(ResolvePath(uri))) == hash;
}

/// <summary>Queue abstraction standing in for Azure Service Bus (duplicate detection by MessageId, dead-letter after max deliveries).</summary>
public interface IMessageQueue
{
    bool Publish(string queue, string messageId, object body);
    IAsyncEnumerable<QueueMessage> ReceiveAsync(string queue, CancellationToken ct);
    bool TryReceive(string queue, out QueueMessage? message);
    void Complete(QueueMessage m);
    void Abandon(QueueMessage m, string error);
    IReadOnlyList<QueueMessage> DeadLetters(string queue);
}
public sealed class QueueMessage
{
    public string Queue { get; init; } = ""; public string MessageId { get; init; } = ""; public string Body { get; init; } = "";
    public int DeliveryCount { get; set; } public string? Error { get; set; } public DateTime EnqueuedAt { get; init; } = DateTime.UtcNow;
    public T As<T>() => JsonSerializer.Deserialize<T>(Body, Schema.Json)!;
}

public sealed class InProcessQueue(int maxDeliveries = 3, TimeSpan? dedupeWindow = null) : IMessageQueue
{
    readonly ConcurrentDictionary<string, Channel<QueueMessage>> _queues = new();
    readonly ConcurrentDictionary<string, DateTime> _seen = new();
    readonly ConcurrentDictionary<string, ConcurrentBag<QueueMessage>> _dlq = new();
    readonly TimeSpan _window = dedupeWindow ?? TimeSpan.FromMinutes(10);

    Channel<QueueMessage> Q(string name) => _queues.GetOrAdd(name, _ => Channel.CreateUnbounded<QueueMessage>());

    public bool Publish(string queue, string messageId, object body)
    {
        var key = queue + "/" + messageId;
        if (_seen.TryGetValue(key, out var at) && DateTime.UtcNow - at < _window) return false; // duplicate detection
        _seen[key] = DateTime.UtcNow;
        Q(queue).Writer.TryWrite(new QueueMessage { Queue = queue, MessageId = messageId, Body = body as string ?? JsonSerializer.Serialize(body, Schema.Json) });
        return true;
    }

    public async IAsyncEnumerable<QueueMessage> ReceiveAsync(string queue, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var m in Q(queue).Reader.ReadAllAsync(ct)) { m.DeliveryCount++; yield return m; }
    }

    public bool TryReceive(string queue, out QueueMessage? message)
    {
        if (Q(queue).Reader.TryRead(out var m)) { m.DeliveryCount++; message = m; return true; }
        message = null; return false;
    }

    public void Complete(QueueMessage m) { }
    public void Abandon(QueueMessage m, string error)
    {
        m.Error = error;
        if (m.DeliveryCount >= maxDeliveries) _dlq.GetOrAdd(m.Queue, _ => []).Add(m);
        else Q(m.Queue).Writer.TryWrite(m);
    }
    public IReadOnlyList<QueueMessage> DeadLetters(string queue) => _dlq.TryGetValue(queue, out var b) ? b.ToList() : [];
}

/// <summary>Kill switch (feature flag). Persisted to a control file standing in for an App Configuration feature flag; every change is audited.</summary>
public sealed class KillSwitch
{
    readonly string _file;
    readonly object _lock = new();
    CancellationTokenSource _cts = new();
    public event Action<bool, string>? Changed;

    public KillSwitch(string controlDir, bool configDefault)
    {
        Directory.CreateDirectory(controlDir);
        _file = Path.Combine(controlDir, "killswitch.json");
        IsOn = File.Exists(_file) ? JsonDocument.Parse(File.ReadAllText(_file)).RootElement.GetProperty("on").GetBoolean() : configDefault;
        if (IsOn) _cts.Cancel();
    }

    public bool IsOn { get; private set; }
    /// <summary>Cancelled the moment the switch is turned on: in-flight model calls and tool processes observe it.</summary>
    public CancellationToken Token { get { lock (_lock) return _cts.Token; } }

    public void Set(bool on, string who)
    {
        lock (_lock)
        {
            IsOn = on;
            File.WriteAllText(_file, JsonSerializer.Serialize(new { on, by = who, at = DateTime.UtcNow }));
            File.AppendAllText(_file + ".audit.log", $"{DateTime.UtcNow:O} kill_switch={(on ? "on" : "off")} by={who}\n");
            if (on) _cts.Cancel(); else if (_cts.IsCancellationRequested) _cts = new CancellationTokenSource();
        }
        Changed?.Invoke(on, who);
    }

    public void ThrowIfOn(string action)
    {
        if (IsOn) throw new KillSwitchEngagedException(action);
    }
}
public sealed class KillSwitchEngagedException(string action) : Exception($"Kill switch is on: refused '{action}'");
public sealed class BudgetExceededException(string message) : Exception(message);

/// <summary>Runs external CLIs (scanners, git, gh, dotnet). Output is returned raw; callers mask before logging.</summary>
public static class Proc
{
    public sealed record Result(int ExitCode, string StdOut, string StdErr, long ElapsedMs);

    public static async Task<Result> RunAsync(string file, IEnumerable<string> args, string? cwd = null, CancellationToken ct = default,
        IDictionary<string, string>? env = null, int timeoutSeconds = 900)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = cwd ?? Environment.CurrentDirectory };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (env != null) foreach (var (k, v) in env) psi.Environment[k] = v;
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        psi.Environment["NO_COLOR"] = "1";
        var sw = Stopwatch.StartNew();
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Cannot start {file}");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        var so = p.StandardOutput.ReadToEndAsync(linked.Token);
        var se = p.StandardError.ReadToEndAsync(linked.Token);
        try { await p.WaitForExitAsync(linked.Token); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch { } throw; }
        return new Result(p.ExitCode, await so, await se, sw.ElapsedMilliseconds);
    }

    public static string Which(string name)
    {
        var home = Environment.GetEnvironmentVariable("HOME") ?? "";
        foreach (var dir in new[] { Path.Combine(home, ".local/bin"), Path.Combine(home, ".dotnet"), "/usr/local/bin", "/usr/bin" }
                     .Concat((Environment.GetEnvironmentVariable("PATH") ?? "").Split(':')))
        {
            var p = Path.Combine(dir, name);
            if (File.Exists(p)) return p;
        }
        return name;
    }
}
