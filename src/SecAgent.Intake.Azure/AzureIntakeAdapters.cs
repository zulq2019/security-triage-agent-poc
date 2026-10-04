using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Azure;

/// <summary>Configuration section "Intake:Azure". Authentication is always Entra ID (managed identity in Azure, developer login locally):
/// no connection strings or keys.</summary>
public sealed class AzureIntakeOptions
{
    public const string SectionName = "Intake:Azure";
    /// <summary>e.g. https://secagentintake.blob.core.windows.net</summary>
    public string BlobServiceUri { get; set; } = "";
    /// <summary>Container for raw payloads + canonical findings (write-once; enable an immutability policy).</summary>
    public string RawContainer { get; set; } = "raw";
    /// <summary>Fully qualified Service Bus namespace, e.g. secagent.servicebus.windows.net (queue with duplicate detection on).</summary>
    public string ServiceBusNamespace { get; set; } = "";
    /// <summary>Run queue (<see cref="RunQueueConvention.QueueName"/>, created by infra/agents.bicep).</summary>
    public string RunQueueName { get; set; } = RunQueueConvention.QueueName;
    /// <summary>True (default) when the queue is session-enabled, as the Bicep creates it. Set false only if the queue is listed in the
    /// Bicep parameter sessionlessQueues. Sends always carry the session key; this switch only selects the receiver type.</summary>
    public bool RunQueueRequiresSession { get; set; } = true;
    public int ReceiveWaitSeconds { get; set; } = 5;
}

/// <summary>Azure Blob adapter for <see cref="IRawFindingStore"/>. Write-once semantics match the local store: create-only upload
/// (If-None-Match: *); an existing blob with the same bytes is reused; different bytes go to a suffixed name. URIs stay blob://raw/….</summary>
public sealed class AzureBlobRawFindingStore(BlobServiceClient service, IOptions<AzureIntakeOptions> options, TimeProvider clock) : IRawFindingStore
{
    BlobContainerClient Container => service.GetBlobContainerClient(options.Value.RawContainer);

    public RawRef Put(string path, byte[] content)
    {
        var hash = "sha256:" + Hashing.Sha256(content);
        var blob = Container.GetBlobClient(path);
        try
        {
            blob.Upload(BinaryData.FromBytes(content), new BlobUploadOptions { Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All } });
        }
        catch (RequestFailedException e) when (e.Status is 409 or 412)
        {
            var existing = blob.DownloadContent().Value.Content.ToArray();
            if ("sha256:" + Hashing.Sha256(existing) != hash)
            {
                path += "." + clock.GetUtcNow().UtcTicks;
                Container.GetBlobClient(path).Upload(BinaryData.FromBytes(content), new BlobUploadOptions { Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All } });
            }
        }
        return new RawRef($"blob://{options.Value.RawContainer}/{path}", hash);
    }

    public byte[] Get(string uri)
    {
        var prefix = $"blob://{options.Value.RawContainer}/";
        if (!uri.StartsWith(prefix, StringComparison.Ordinal)) throw new ArgumentException($"not a {prefix} uri", nameof(uri));
        return Container.GetBlobClient(uri[prefix.Length..]).DownloadContent().Value.Content.ToArray();
    }
}

/// <summary>Azure Blob adapter for <see cref="IBlobReader"/> (Event Grid BlobCreated → read the uploaded file with the app's identity).</summary>
public sealed class AzureBlobReader(BlobServiceClient service) : IBlobReader
{
    public async Task<byte[]> ReadAsync(BlobCreatedEvent evt, long maxBytes, CancellationToken ct)
    {
        var parts = new BlobUriBuilder(new Uri(evt.Url));
        if (!string.Equals(parts.Host, service.Uri.Host, StringComparison.OrdinalIgnoreCase)) throw new IOException("blob is not in the configured storage account");
        var blob = service.GetBlobContainerClient(parts.BlobContainerName).GetBlobClient(parts.BlobName);
        var props = await blob.GetPropertiesAsync(cancellationToken: ct);
        if (props.Value.ContentLength > maxBytes) throw new IOException($"blob is {props.Value.ContentLength} bytes; the limit is {maxBytes}");
        return (await blob.DownloadContentAsync(ct)).Value.Content.ToArray();
    }
}

/// <summary>Service Bus adapter for both sides of the run queue. MessageId = idempotency key: with duplicate detection enabled on the
/// queue, a second copy is dropped by the broker. SessionId = <see cref="RunQueueConvention.SessionId"/> (the run target), so it works
/// with the session-enabled <c>runs</c> queue from the Bicep. Abandoned messages are redelivered and dead-lettered after MaxDeliveryCount.</summary>
public sealed class ServiceBusIntakeRunQueue : IRunStarter, IIntakeRunSource, IAsyncDisposable
{
    readonly ServiceBusClient _client;
    readonly ServiceBusSender _sender;
    readonly ServiceBusReceiver? _receiver;   // sessionless queues only; session-enabled queues accept a session per delivery
    readonly TimeSpan _wait;
    readonly string _queue;

    public ServiceBusIntakeRunQueue(ServiceBusClient client, IOptions<AzureIntakeOptions> options)
    {
        _client = client;
        _queue = options.Value.RunQueueName;
        _sender = client.CreateSender(_queue);
        _receiver = options.Value.RunQueueRequiresSession ? null : client.CreateReceiver(_queue);
        _wait = TimeSpan.FromSeconds(options.Value.ReceiveWaitSeconds);
    }

    /// <summary>The message sent for a run request (exposed for tests).</summary>
    public static ServiceBusMessage ToMessage(IntakeRunRequest request) => new(BinaryData.FromObjectAsJson(request, Schema.Json))
    {
        MessageId = request.IdempotencyKey, SessionId = RunQueueConvention.SessionId(request), ContentType = "application/json", Subject = "intake-run",
    };

    public async Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct)
    {
        await _sender.SendMessageAsync(ToMessage(request), ct);
        return new RunTicket($"{_queue}/{request.IdempotencyKey[..16]}", true);   // the broker, not us, knows whether it was a duplicate
    }

    public async Task<IntakeRunDelivery?> ReceiveAsync(CancellationToken ct)
    {
        if (_receiver != null)
        {
            var m = await _receiver.ReceiveMessageAsync(_wait, ct);
            return m == null ? null : new IntakeRunDelivery(m.Body.ToObjectFromJson<IntakeRunRequest>(Schema.Json)!, new Handle(_receiver, m, OwnsReceiver: false));
        }
        ServiceBusSessionReceiver session;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(_wait);
            try { session = await _client.AcceptNextSessionAsync(_queue, cancellationToken: timeout.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            catch (ServiceBusException e) when (e.Reason == ServiceBusFailureReason.ServiceTimeout) { return null; }
        }
        var msg = await session.ReceiveMessageAsync(_wait, ct);
        if (msg == null) { await session.DisposeAsync(); return null; }
        return new IntakeRunDelivery(msg.Body.ToObjectFromJson<IntakeRunRequest>(Schema.Json)!, new Handle(session, msg, OwnsReceiver: true));
    }

    public async Task CompleteAsync(IntakeRunDelivery delivery, CancellationToken ct)
    {
        var h = (Handle)delivery.Handle;
        try { await h.Receiver.CompleteMessageAsync(h.Message, ct); } finally { await h.ReleaseAsync(); }
    }

    public async Task AbandonAsync(IntakeRunDelivery delivery, string error, CancellationToken ct)
    {
        var h = (Handle)delivery.Handle;
        try { await h.Receiver.AbandonMessageAsync(h.Message, new Dictionary<string, object> { ["secagent_error"] = error }, ct); }
        finally { await h.ReleaseAsync(); }
    }

    public async ValueTask DisposeAsync()
    {
        await _sender.DisposeAsync();
        if (_receiver != null) await _receiver.DisposeAsync();
    }

    sealed record Handle(ServiceBusReceiver Receiver, ServiceBusReceivedMessage Message, bool OwnsReceiver)
    {
        public async Task ReleaseAsync() { if (OwnsReceiver) await Receiver.DisposeAsync(); }
    }
}

public static class AzureIntakeServiceCollectionExtensions
{
    /// <summary>Registers the Azure adapters under the keys <see cref="IntakeAdapterKeys.AzureBlob"/> (IRawFindingStore, IBlobReader) and
    /// <see cref="IntakeAdapterKeys.AzureServiceBus"/> (IRunStarter, IIntakeRunSource). Select them with Intake:Adapters:*.
    /// Clients are created lazily, so registering without using them costs nothing.</summary>
    public static IServiceCollection AddSecAgentIntakeAzure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AzureIntakeOptions>().Bind(configuration.GetSection(AzureIntakeOptions.SectionName));
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<TokenCredential>(_ => new DefaultAzureCredential());
        services.TryAddSingleton(sp => new BlobServiceClient(new Uri(Required(sp.GetRequiredService<IOptions<AzureIntakeOptions>>().Value.BlobServiceUri, "BlobServiceUri")),
            sp.GetRequiredService<TokenCredential>()));
        services.TryAddSingleton(sp => new ServiceBusClient(Required(sp.GetRequiredService<IOptions<AzureIntakeOptions>>().Value.ServiceBusNamespace, "ServiceBusNamespace"),
            sp.GetRequiredService<TokenCredential>()));

        services.AddKeyedSingleton<IRawFindingStore, AzureBlobRawFindingStore>(IntakeAdapterKeys.AzureBlob);
        services.AddKeyedSingleton<IBlobReader, AzureBlobReader>(IntakeAdapterKeys.AzureBlob);
        services.AddKeyedSingleton<ServiceBusIntakeRunQueue>(IntakeAdapterKeys.AzureServiceBus);
        services.AddKeyedSingleton<IRunStarter>(IntakeAdapterKeys.AzureServiceBus, (sp, k) => sp.GetRequiredKeyedService<ServiceBusIntakeRunQueue>(k));
        services.AddKeyedSingleton<IIntakeRunSource>(IntakeAdapterKeys.AzureServiceBus, (sp, k) => sp.GetRequiredKeyedService<ServiceBusIntakeRunQueue>(k));
        return services;
    }

    static string Required(string value, string name) =>
        string.IsNullOrWhiteSpace(value) ? throw new InvalidOperationException($"Intake:Azure:{name} is required for the Azure intake adapters") : value;
}
