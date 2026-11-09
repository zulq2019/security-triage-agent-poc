using SecAgent.Hosting;
using SecAgent.Worker;

// ---------------------------------------------------------------------------------------------------------------------------------------
// secagent-worker                  run the agent named by SECAGENT_AGENT (or Agent__Role) from deploy/agents.json
// secagent-worker probe [url]      HTTP health probe for container HEALTHCHECKs (chiselled images have no shell/curl)
// ---------------------------------------------------------------------------------------------------------------------------------------
if (args is ["probe", ..]) return await HealthProbe.RunAsync(args.Length > 1 ? args[1] : null);

// Content root = the binary folder, so appsettings.json is found wherever the process starts (repo checkout or /app/bin in the image).
var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Configuration.AddSecAgentEnvironmentAliases();
SelectedAgentRole selected;
try { selected = builder.Services.AddSecAgentAgentHost(builder.Configuration, WorkerRegistry.Create()); }
catch (AgentHostConfigurationException e)
{
    // Misconfiguration (unknown role/transport, missing SQL, ...) is not a crash: one clear line, exit 2, no stack trace.
    await Console.Error.WriteLineAsync($"secagent-worker: configuration error: {e.Message}");
    return 2;
}
var app = builder.Build();
app.MapSecAgentAgentHost();
app.Logger.LogInformation("secagent-worker: agent {Role} on transport {Transport}", selected.Context.Spec.Name, selected.Transport);
await app.RunAsync();
return 0;
