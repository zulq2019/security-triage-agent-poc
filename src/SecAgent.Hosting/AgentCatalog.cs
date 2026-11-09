using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SecAgent.Hosting;

/// <summary>Which host project runs an agent. <c>worker</c> = src/SecAgent.Worker (role selected by SECAGENT_AGENT);
/// <c>dashboard</c> = src/SecAgent.Dashboard (<c>secagent serve</c>, the agent-api).</summary>
public static class AgentHosts
{
    public const string Worker = "worker";
    public const string Dashboard = "dashboard";
}

/// <summary>One agent in deploy/agents.json. Field names and meanings mirror the agentSpec type in infra/types.bicep (PR #3), so the
/// same list drives the CI image matrix, the worker's role/queue wiring and (by alignment test) the Bicep scale rules.</summary>
public sealed record AgentSpec
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary><see cref="AgentHosts"/>.</summary>
    public string Host { get; init; } = AgentHosts.Worker;
    /// <summary>Dockerfile target (deploy/Dockerfile): runtime | scanner | toolchain | dashboard.</summary>
    public string ImageTarget { get; init; } = "runtime";
    /// <summary>HTTP port (ingress for intake / agent-api; health probes for every agent).</summary>
    public int Port { get; init; } = 8080;
    public string Ingress { get; init; } = "none";
    /// <summary>Queues consumed (one KEDA azure-servicebus rule each in Bicep).</summary>
    public List<string> Consumes { get; init; } = [];
    /// <summary>Subscriptions on the run-events topic consumed.</summary>
    public List<string> Subscribes { get; init; } = [];
    /// <summary>Queues the agent may send to (Service Bus Data Sender in Bicep).</summary>
    public List<string> Sends { get; init; } = [];
    /// <summary>Publishes to the run-events topic.</summary>
    public bool PublishesEvents { get; init; }
    /// <summary>Dispatcher (orchestrator): may send to every queue consumed by a non-dispatcher agent (same rule as main.bicep).</summary>
    public bool DispatchesWork { get; init; }
}

/// <summary>The agent catalogue: deploy/agents.json. Pure data; one entry per agent / container image.</summary>
public sealed partial class AgentCatalog
{
    public static readonly string[] ImageTargets = ["runtime", "scanner", "toolchain", "dashboard"];

    public int Version { get; init; } = 1;
    /// <summary>Image name = {ImageRepositoryPrefix}-{agent} (matches main.bicep: {registry}/{workload}-{agent}:{tag}).</summary>
    public string ImageRepositoryPrefix { get; init; } = "secagent";
    public string RunEventsTopic { get; init; } = "run-events";
    public List<AgentSpec> Agents { get; init; } = [];

    public AgentSpec? Find(string name) => Agents.FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Entity path of a topic subscription, as Service Bus names it: run-events/subscriptions/audit.</summary>
    public string SubscriptionEntity(string subscription) => $"{RunEventsTopic}/subscriptions/{subscription}";

    /// <summary>Everything the agent receives from: its queues, then its topic subscriptions.</summary>
    public IReadOnlyList<string> ConsumedEntities(AgentSpec agent) => [.. agent.Consumes, .. agent.Subscribes.Select(SubscriptionEntity)];

    /// <summary>Queues the agent may send to: its own <c>sends</c>, plus every worker queue for a dispatcher (main.bicep's dispatchQueues rule).</summary>
    public IReadOnlySet<string> AllowedSends(AgentSpec agent)
    {
        var set = new HashSet<string>(agent.Sends, StringComparer.Ordinal);
        if (agent.DispatchesWork) foreach (var other in Agents.Where(a => !a.DispatchesWork)) set.UnionWith(other.Consumes);
        return set;
    }

    /// <summary>Subscriptions that receive a run event. Locally a topic is emulated by copying the event to each of these;
    /// on Service Bus the broker fans out.</summary>
    public IReadOnlyList<string> TopicSubscriptions(Func<AgentSpec, bool>? filter = null) =>
        Agents.Where(filter ?? (_ => true)).SelectMany(a => a.Subscribes).Distinct().ToList();

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };

    public static AgentCatalog Load(string path)
    {
        if (!File.Exists(path)) throw new AgentHostConfigurationException($"agent catalogue not found: {path} (Agent:CatalogPath)");
        return Parse(File.ReadAllText(path));
    }

    public static AgentCatalog Parse(string json)
    {
        var c = JsonSerializer.Deserialize<AgentCatalog>(json, Json) ?? throw new AgentHostConfigurationException("agent catalogue is empty");
        c.Validate();
        return c;
    }

    [GeneratedRegex("^[a-z][a-z0-9-]{1,19}$")] private static partial Regex NameRule();

    void Validate()
    {
        var errors = new List<string>();
        foreach (var dup in Agents.GroupBy(a => a.Name).Where(g => g.Count() > 1)) errors.Add($"duplicate agent '{dup.Key}'");
        foreach (var a in Agents)
        {
            if (!NameRule().IsMatch(a.Name)) errors.Add($"agent name '{a.Name}' must be 2-20 lowercase letters, digits or hyphens (Bicep agentSpec)");
            if (a.Host is not (AgentHosts.Worker or AgentHosts.Dashboard)) errors.Add($"{a.Name}: host must be worker or dashboard");
            if (!ImageTargets.Contains(a.ImageTarget)) errors.Add($"{a.Name}: imageTarget must be one of {string.Join(", ", ImageTargets)}");
            if (a.Ingress is not ("none" or "internal" or "external")) errors.Add($"{a.Name}: ingress must be none, internal or external");
        }
        if (errors.Count > 0) throw new AgentHostConfigurationException("deploy/agents.json: " + string.Join("; ", errors));
    }
}

/// <summary>Invalid host configuration (unknown role, missing catalogue, unregistered transport). Thrown while the host is composed,
/// so a misconfigured container fails at start instead of idling.</summary>
public sealed class AgentHostConfigurationException(string message) : Exception(message);
