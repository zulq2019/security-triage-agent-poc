using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SecAgent.Hosting;

/// <summary>Everything a role or transport module needs to register itself: its catalogue entry, the whole catalogue, resolved options
/// and configuration. Also registered as a singleton.</summary>
public sealed class AgentRoleContext(AgentSpec spec, AgentCatalog catalog, AgentHostOptions options, IConfiguration configuration)
{
    public AgentSpec Spec { get; } = spec;
    public AgentCatalog Catalog { get; } = catalog;
    public AgentHostOptions Options { get; } = options;
    public IConfiguration Configuration { get; } = configuration;
    public string ContentRoot => Options.ContentRoot;
    public string DataRoot => Options.DataRoot;
    public IReadOnlyList<string> ConsumedEntities { get; } = catalog.ConsumedEntities(spec);
    public IReadOnlySet<string> AllowedSends { get; } = catalog.AllowedSends(spec);
}

/// <summary>Plug-in module for one agent role (Strategy, selected by name). Registers only that role's services and message handlers;
/// the host adds the shared parts (transport, consumer, health, telemetry). Adding a role = one class + one line in the host's registry.</summary>
public interface IAgentRoleModule
{
    /// <summary>Agent name in deploy/agents.json.</summary>
    string Role { get; }
    void ConfigureServices(IServiceCollection services, AgentRoleContext context);
}

/// <summary>Optional: a role that serves HTTP endpoints besides health (the intake). Separate from <see cref="IAgentRoleModule"/> so
/// queue-only roles do not implement an empty method.</summary>
public interface IAgentRoleEndpoints
{
    void MapEndpoints(IEndpointRouteBuilder endpoints);
}

/// <summary>Plug-in module for one queue transport (selected by Agent:Transport). Must register <see cref="IAgentQueueTransport"/> and,
/// for local transports, the <see cref="SecAgent.Core.IMessageQueue"/> the intake shares.</summary>
public interface IQueueTransportModule
{
    string Key { get; }
    void ConfigureServices(IServiceCollection services, AgentRoleContext context);
}

/// <summary>The modules this host knows. Built explicitly in the host's Program.cs (no assembly scanning), then one role and one transport
/// are picked by configuration.</summary>
public sealed class AgentHostRegistry
{
    readonly Dictionary<string, IAgentRoleModule> _roles = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, IQueueTransportModule> _transports = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, IAgentRoleModule> Roles => _roles;
    public IReadOnlyDictionary<string, IQueueTransportModule> Transports => _transports;

    public AgentHostRegistry AddRole(IAgentRoleModule module)
    {
        if (!_roles.TryAdd(module.Role, module)) throw new AgentHostConfigurationException($"role '{module.Role}' registered twice");
        return this;
    }

    public AgentHostRegistry AddTransport(IQueueTransportModule module)
    {
        if (!_transports.TryAdd(module.Key, module)) throw new AgentHostConfigurationException($"transport '{module.Key}' registered twice");
        return this;
    }

    public IAgentRoleModule Role(string name) => _roles.TryGetValue(name, out var m) ? m
        : throw new AgentHostConfigurationException($"unknown agent role '{name}'. This host runs: {string.Join(", ", _roles.Keys.Order())}");

    public IQueueTransportModule Transport(string key) => _transports.TryGetValue(key, out var m) ? m
        : throw new AgentHostConfigurationException($"unknown queue transport '{key}'. Registered: {string.Join(", ", _transports.Keys.Order())}");
}

/// <summary>The role this process runs (singleton), for endpoints and health.</summary>
public sealed record SelectedAgentRole(IAgentRoleModule Module, AgentRoleContext Context, string Transport);

/// <summary>Built-in local transports.</summary>
public sealed class InProcessTransportModule : IQueueTransportModule
{
    public string Key => AgentTransportKeys.InProcess;
    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        services.AddSingleton<SecAgent.Core.IMessageQueue>(_ => new SecAgent.Core.InProcessQueue(context.Options.MaxDeliveries));
        services.AddSingleton<IAgentTransportHealth, InProcessTransportHealth>();
        services.AddSingleton<IAgentQueueTransport, MessageQueueAgentTransport>();
    }
}

public sealed class FileSystemTransportModule : IQueueTransportModule
{
    public string Key => AgentTransportKeys.File;
    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        services.AddSingleton(_ => new FileSystemMessageQueue(context.Options.QueueRoot, context.Options.MaxDeliveries));
        services.AddSingleton<SecAgent.Core.IMessageQueue>(sp => sp.GetRequiredService<FileSystemMessageQueue>());
        services.AddSingleton<IAgentTransportHealth>(sp => sp.GetRequiredService<FileSystemMessageQueue>());
        services.AddSingleton<IAgentQueueTransport, MessageQueueAgentTransport>();
    }
}
