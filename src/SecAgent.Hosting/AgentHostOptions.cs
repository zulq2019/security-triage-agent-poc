using Microsoft.Extensions.Configuration;

namespace SecAgent.Hosting;

/// <summary>Keys of the queue transports (adapters for the worker's queue ports). Selected with Agent:Transport / SECAGENT_QUEUE.</summary>
public static class AgentTransportKeys
{
    /// <summary>In-memory queue: everything in one process (tests, all-in-one dev).</summary>
    public const string InProcess = "in-process";
    /// <summary>Folder-per-queue on a shared volume: several containers on one machine (docker compose).</summary>
    public const string File = "file";
    /// <summary>Azure Service Bus with the app's managed identity (Container Apps; Bicep sets SECAGENT_QUEUE=servicebus).</summary>
    public const string ServiceBus = "servicebus";
}

/// <summary>Worker host configuration, section "Agent" (Options pattern). Environment aliases used by the Bicep in PR #3
/// (SECAGENT_AGENT, SECAGENT_QUEUE, ...) map onto it, see <see cref="AgentConfigurationExtensions.AddSecAgentEnvironmentAliases"/>.</summary>
public sealed class AgentHostOptions
{
    public const string SectionName = "Agent";

    /// <summary>Agent name from deploy/agents.json, e.g. scanner, fixer-library. Required.</summary>
    public string Role { get; set; } = "";
    public string Transport { get; set; } = AgentTransportKeys.InProcess;
    /// <summary>Folder with rules/, db/ and deploy/agents.json. Default: found by walking up from the working directory (repo checkout) or /app (image).</summary>
    public string ContentRoot { get; set; } = "";
    /// <summary>Writable state (checkpoints, work trees, local blobs, file queues). Default {ContentRoot}/.data; /data in the images.</summary>
    public string DataRoot { get; set; } = "";
    /// <summary>Default {ContentRoot}/deploy/agents.json.</summary>
    public string CatalogPath { get; set; } = "";
    /// <summary>File transport root (default {DataRoot}/queues). Every container that shares queues mounts the same folder.</summary>
    public string QueueRoot { get; set; } = "";
    /// <summary>On shutdown: stop receiving, then give in-flight messages this long before cancelling them (they are abandoned and redelivered).</summary>
    public int DrainTimeoutSeconds { get; set; } = 30;
    /// <summary>Parallel messages per consumed queue.</summary>
    public int MaxConcurrentMessages { get; set; } = 1;
    /// <summary>Long-poll wait per receive call.</summary>
    public int ReceiveWaitSeconds { get; set; } = 5;
    /// <summary>Deliveries before a message is dead-lettered (local transports; Service Bus uses the queue's MaxDeliveryCount).</summary>
    public int MaxDeliveries { get; set; } = 3;
    /// <summary>While a handler runs, renew its message lock / lease this often (0 = never). Keep it well below the Service Bus
    /// lockDuration (Bicep default PT5M) and the file-queue lease (5 minutes).</summary>
    public int LockRenewalSeconds { get; set; } = 30;

    /// <summary>Fills derived defaults and checks what can be checked without the catalogue.</summary>
    public AgentHostOptions Resolve()
    {
        if (string.IsNullOrWhiteSpace(Role))
            throw new AgentHostConfigurationException("no agent role: set SECAGENT_AGENT (or Agent__Role) to a name from deploy/agents.json");
        Role = Role.Trim().ToLowerInvariant();
        Transport = string.IsNullOrWhiteSpace(Transport) ? AgentTransportKeys.InProcess : Transport.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(ContentRoot)) ContentRoot = FindContentRoot();
        if (string.IsNullOrWhiteSpace(DataRoot)) DataRoot = Path.Combine(ContentRoot, ".data");
        if (string.IsNullOrWhiteSpace(CatalogPath)) CatalogPath = Path.Combine(ContentRoot, "deploy", "agents.json");
        if (string.IsNullOrWhiteSpace(QueueRoot)) QueueRoot = Path.Combine(DataRoot, "queues");
        if (DrainTimeoutSeconds < 0 || LockRenewalSeconds < 0 || MaxConcurrentMessages < 1 || ReceiveWaitSeconds < 1 || MaxDeliveries < 1)
            throw new AgentHostConfigurationException("Agent: DrainTimeoutSeconds/LockRenewalSeconds >= 0, MaxConcurrentMessages/ReceiveWaitSeconds/MaxDeliveries >= 1");
        return this;
    }

    static string FindContentRoot()
    {
        foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
            for (var d = new DirectoryInfo(start); d != null; d = d.Parent)
                if (Directory.Exists(Path.Combine(d.FullName, "rules")) && File.Exists(Path.Combine(d.FullName, "deploy", "agents.json"))) return d.FullName;
        throw new AgentHostConfigurationException("cannot find the content root (folder with rules/ and deploy/agents.json); set SECAGENT_CONTENT_ROOT");
    }
}

public static class AgentConfigurationExtensions
{
    /// <summary>Environment names set by the Container Apps template (infra/main.bicep, PR #3) mapped onto the "Agent" section.</summary>
    public static readonly IReadOnlyDictionary<string, string> EnvironmentAliases = new Dictionary<string, string>
    {
        ["SECAGENT_AGENT"] = "Agent:Role",
        ["SECAGENT_QUEUE"] = "Agent:Transport",
        ["SECAGENT_SERVICEBUS_NAMESPACE"] = "Agent:ServiceBus:Namespace",
        ["SECAGENT_CONTENT_ROOT"] = "Agent:ContentRoot",
        ["SECAGENT_DATA_ROOT"] = "Agent:DataRoot",
    };

    /// <summary>Adds the aliases, then the environment again so explicit Agent__X variables win over an alias.</summary>
    public static IConfigurationBuilder AddSecAgentEnvironmentAliases(this IConfigurationBuilder builder, Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var values = new Dictionary<string, string?>();
        foreach (var (env, key) in EnvironmentAliases)
            if (environment(env) is { Length: > 0 } v) values[key] = v;
        builder.AddInMemoryCollection(values);
        if (environment == Environment.GetEnvironmentVariable) builder.AddEnvironmentVariables();
        return builder;
    }
}
