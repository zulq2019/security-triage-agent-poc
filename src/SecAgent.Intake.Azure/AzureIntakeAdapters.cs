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
    public string RunQueueName { get; set; } = "intake-runs";
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
/// queue, a second copy is dropped by the broker. Abandoned messages are redelivered and dead-lettered after MaxDeliveryCount.</summary>
public sealed class ServiceBusIntakeRunQueue : IRunStarter, IIntakeRunSource, IAsyncDisposable
{
    readonly ServiceBusSender _sender;
    readonly ServiceBusReceiver _receiver;
    readonly TimeSpan _wait;
    readonly string _queue;

    public ServiceBusIntakeRunQueue(ServiceBusClient client, IOptions<AzureIntakeOptions> options)
    {
        _queue = options.Value.RunQueueName;
        _sender = client.CreateSender(_queue);
        _receiver = client.CreateReceiver(_queue);
        _wait = TimeSpan.FromSeconds(options.Value.ReceiveWaitSeconds);
    }

    public async Task<RunTicket> EnqueueAsync(IntakeRunRequest request, CancellationToken ct)
    {
        await _sender.SendMessageAsync(new ServiceBusMessage(BinaryData.FromObjectAsJson(request, Schema.Json))
        {
            MessageId = request.IdempotencyKey, ContentType = "application/json", Subject = "intake-run",
        }, ct);
        return new RunTicket($"{_queue}/{request.IdempotencyKey[..16]}", true);   // the broker, not us, knows whether it was a duplicate
    }

    public async Task<IntakeRunDelivery?> ReceiveAsync(CancellationToken ct)
    {
        var m = await _receiver.ReceiveMessageAsync(_wait, ct);
        return m == null ? null : new IntakeRunDelivery(m.Body.ToObjectFromJson<IntakeRunRequest>(Schema.Json)!, m);
    }

    public Task CompleteAsync(IntakeRunDelivery delivery, CancellationToken ct) => _receiver.CompleteMessageAsync((ServiceBusReceivedMessage)delivery.Handle, ct);

    public Task AbandonAsync(IntakeRunDelivery delivery, string error, CancellationToken ct) =>
        _receiver.AbandonMessageAsync((ServiceBusReceivedMessage)delivery.Handle, new Dictionary<string, object> { ["secagent_error"] = error }, ct);

    public async ValueTask DisposeAsync() { await _sender.DisposeAsync(); await _receiver.DisposeAsync(); }
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
