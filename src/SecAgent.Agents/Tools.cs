using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.AI;
using SecAgent.Core;

namespace SecAgent.Agents;

public sealed class ToolNotAllowedException(string agent, string tool) : Exception($"Tool '{tool}' is not on the allow-list for agent '{agent}'");

/// <summary>Tool layer. Tools are Microsoft.Extensions.AI function tools (AIFunction) or wrapped CLI operations.
/// Every invocation is checked against the per-agent allow-list (routing.yaml), traced, and shown in the activity feed.
/// There is deliberately no merge / approve / branch-protection tool (FR-17).</summary>
public sealed class ToolInvoker(ConfigSnapshot cfg, SqlStore store, KillSwitch kill)
{
    readonly Dictionary<string, AIFunction> _functions = new();
    public IReadOnlyDictionary<string, AIFunction> Functions => _functions;

    public void Register(string name, Delegate impl, string description) =>
        _functions[name] = AIFunctionFactory.Create(impl, name.Replace('.', '_'), description);

    void Check(string agent, string tool, Guid runId)
    {
        if (cfg.Routing.Agents.TryGetValue(agent, out var allowed) && allowed.Contains(tool)) return;
        store.PolicyViolation(runId, null, "tool_not_allowed", $"agent={agent} tool={tool}");
        throw new ToolNotAllowedException(agent, tool);
    }

    /// <summary>Invoke a registered AIFunction tool with JSON-able arguments.</summary>
    public async Task<JsonElement> CallAsync(string agent, string tool, Dictionary<string, object?> args, Feed? feed, string? entryId, string display, CancellationToken ct)
    {
        return await RunAsync(agent, tool, display, feed, entryId, async () =>
        {
            var fn = _functions[tool];
            var result = await fn.InvokeAsync(new AIFunctionArguments(args), ct);
            return result is JsonElement je ? je : JsonSerializer.SerializeToElement(result, Schema.Json);
        }, ct);
    }

    /// <summary>Run a (CLI-backed) tool operation under the same allow-list, tracing and feed rules.</summary>
    public async Task<T> RunAsync<T>(string agent, string tool, string display, Feed? feed, string? entryId, Func<Task<T>> op, CancellationToken ct, Func<T, bool>? ok = null)
    {
        Check(agent, tool, feed?.RunId ?? Guid.Empty);
        if (tool is not ("scan.gitleaks" or "scan.trivy" or "scan.semgrep" or "scan.binary_check" or "dotnet.test" or "evidence.write")) kill.ThrowIfOn(tool);
        using var span = Telemetry.Source.StartActivity("tool " + tool);
        span?.SetTag("secagent.agent", agent); span?.SetTag("secagent.tool", tool);
        var toolId = entryId != null ? feed?.ToolStart(entryId, tool, display) : null;
        var sw = Stopwatch.StartNew();
        try
        {
            var r = await op();
            var good = ok?.Invoke(r) ?? true;
            if (toolId != null) feed!.ToolEnd(entryId!, toolId, tool, display, good, sw.ElapsedMilliseconds);
            span?.SetTag("secagent.ok", good);
            return r;
        }
        catch (Exception e)
        {
            if (toolId != null) feed!.ToolEnd(entryId!, toolId, tool, display, false, sw.ElapsedMilliseconds);
            span?.SetStatus(ActivityStatusCode.Error, e.Message);
            throw;
        }
    }
}
