using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SecAgent.Core;

namespace SecAgent.Hosting;

/// <summary>The worker host's composition root. Order: options → catalogue → role context → transport module → role module → shared parts
/// (publisher decorator, consumer, health, telemetry, shutdown timeout). Role and transport are chosen by configuration through dictionary
/// lookups in <see cref="AgentHostRegistry"/>: no if/else per role.</summary>
public static class AgentHostServiceCollectionExtensions
{
    public static SelectedAgentRole AddSecAgentAgentHost(this IServiceCollection services, IConfiguration configuration, AgentHostRegistry registry)
    {
        var options = (configuration.GetSection(AgentHostOptions.SectionName).Get<AgentHostOptions>() ?? new()).Resolve();
        var catalog = AgentCatalog.Load(options.CatalogPath);
        var spec = catalog.Find(options.Role)
            ?? throw new AgentHostConfigurationException($"role '{options.Role}' is not in {options.CatalogPath}. Agents: {string.Join(", ", catalog.Agents.Select(a => a.Name))}");
        if (spec.Host != AgentHosts.Worker)
            throw new AgentHostConfigurationException($"'{spec.Name}' runs in the {spec.Host} host, not the worker (deploy/agents.json host)");
        var module = registry.Role(spec.Name);
        var transport = registry.Transport(options.Transport);
        Directory.CreateDirectory(options.DataRoot);

        var context = new AgentRoleContext(spec, catalog, options, configuration);
        var selected = new SelectedAgentRole(module, context, transport.Key);
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(options));
        services.AddSingleton(catalog);
        services.AddSingleton(context);
        services.AddSingleton(selected);

        transport.ConfigureServices(services, context);
        module.ConfigureServices(services, context);

        // Shared parts. TryAdd: a role module may already have provided the pipeline's instance (e.g. its SecretMasker).
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<SecretMasker>();
        services.AddSingleton<IAgentQueueReceiver>(sp => sp.GetRequiredService<IAgentQueueTransport>());
        services.AddSingleton<IAgentQueuePublisher>(sp => new CatalogScopedPublisher(sp.GetRequiredService<IAgentQueueTransport>(), context));
        services.AddMetrics();
        services.AddSingleton<AgentMetrics>();
        services.AddSingleton<AgentReadiness>();
        services.AddSingleton<AgentQueueConsumer>();
        services.AddHostedService(sp => sp.GetRequiredService<AgentQueueConsumer>());
        services.AddHealthChecks()
            .AddCheck<AgentRoleHealthCheck>("role", tags: [AgentHealthTags.Ready])
            .AddCheck<AgentTransportHealthCheck>("transport", tags: [AgentHealthTags.Ready])
            .AddCheck<AgentConsumerHealthCheck>("consumer", tags: [AgentHealthTags.Ready]);
        services.Configure<HostOptions>(h => h.ShutdownTimeout = TimeSpan.FromSeconds(options.DrainTimeoutSeconds + 10));
        services.AddSecAgentAgentTelemetry(context);
        return selected;
    }

    /// <summary>Registers a handler for one consumed entity (queue name, or run-events/subscriptions/&lt;sub&gt;). The entity must be one
    /// the role consumes in deploy/agents.json, so KEDA scales on exactly what the code reads.</summary>
    public static IServiceCollection AddAgentMessageHandler<THandler>(this IServiceCollection services, AgentRoleContext context, string entity)
        where THandler : class, IAgentMessageHandler
    {
        if (!context.ConsumedEntities.Contains(entity))
            throw new AgentHostConfigurationException($"agent '{context.Spec.Name}' does not consume '{entity}' in deploy/agents.json (consumes: {string.Join(", ", context.ConsumedEntities)})");
        services.TryAddScoped<THandler>();
        services.AddSingleton(new AgentHandlerRegistration(entity, typeof(THandler)));
        return services;
    }

    /// <summary>Health endpoints + the role's own endpoints (if it has any).</summary>
    public static IEndpointRouteBuilder MapSecAgentAgentHost(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSecAgentHealth();
        var selected = endpoints.ServiceProvider.GetRequiredService<SelectedAgentRole>();
        if (selected.Module is IAgentRoleEndpoints withEndpoints) withEndpoints.MapEndpoints(endpoints);
        return endpoints;
    }
}
