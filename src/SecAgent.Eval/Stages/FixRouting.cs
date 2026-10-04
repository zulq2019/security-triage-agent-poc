using SecAgent.Core;

namespace SecAgent.Eval.Stages;

/// <summary>A fixer the harness can drive. One implementation per pipeline fixer id (Strategy); registered with services.AddEvalFixer&lt;T&gt;().</summary>
public interface IEvalFixer
{
    string Id { get; }
    Task<FixResult> ApplyAsync(CaseContext ctx, CancellationToken ct);
}

/// <summary>Issue type → fixer, from the pipeline's routing table (rules/routing/routing.yaml).</summary>
public interface IFixRouter
{
    IEvalFixer Route(Finding f, out string fixerId);
}

public sealed class RoutingTableFixRouter : IFixRouter
{
    readonly ConfigSnapshot _cfg;
    readonly Dictionary<string, IEvalFixer> _fixers;

    public RoutingTableFixRouter(ConfigSnapshot cfg, IEnumerable<IEvalFixer> fixers)
    {
        _cfg = cfg;
        _fixers = new();
        foreach (var f in fixers)
            if (!_fixers.TryAdd(f.Id, f)) throw new InvalidOperationException($"two eval fixers registered for '{f.Id}'");
        // Same start-up rule as the pipeline's AgentServices: every routed fixer must exist.
        foreach (var (type, route) in cfg.Routing.Routes)
            if (!_fixers.ContainsKey(route.Fixer)) throw new InvalidOperationException($"routing.yaml: issue type '{type}' routes to fixer '{route.Fixer}', which has no eval fixer");
    }

    public IEvalFixer Route(Finding f, out string fixerId)
    {
        if (!_cfg.Routing.Routes.TryGetValue(f.IssueType, out var route)) throw new InvalidOperationException($"no route for issue type '{f.IssueType}'");
        fixerId = route.Fixer;
        return _fixers[route.Fixer];
    }
}
