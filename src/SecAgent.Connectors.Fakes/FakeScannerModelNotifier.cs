namespace SecAgent.Connectors.Fakes;

/// <summary>Per-tenant in-memory Black Duck: project versions, their vulnerabilities and upgrade guidance (synthetic data only).</summary>
public sealed class FakeScannerSourceState
{
    internal readonly object Lock = new();
    internal readonly Dictionary<string, List<(ScannerProjectVersion Version, List<ScannerVulnerability> Vulns)>> Projects = new(StringComparer.OrdinalIgnoreCase);
    internal readonly Dictionary<string, Dictionary<string, RemediationGuidance>> Guidance = new(StringComparer.OrdinalIgnoreCase);

    public ScannerProjectVersion AddProjectVersion(string tenantId, string project, string version, params ScannerVulnerability[] vulns)
    {
        lock (Lock)
        {
            if (!Projects.TryGetValue(tenantId, out var list)) Projects[tenantId] = list = [];
            var pv = new ScannerProjectVersion(FakeConnectorWorld.Sha("project", project)[..8], project, FakeConnectorWorld.Sha("version", project, version)[..8], version);
            list.Add((pv, vulns.ToList()));
            return pv;
        }
    }

    public void AddGuidance(string tenantId, ComponentVersionRef component, RemediationGuidance guidance)
    {
        lock (Lock)
        {
            if (!Guidance.TryGetValue(tenantId, out var g)) Guidance[tenantId] = g = new();
            g[component.ComponentId + "/" + component.ComponentVersionId] = guidance;
        }
    }
}

public sealed class FakeScannerSourceClient(FakeConnectorWorld world, string tenant) : IScannerSourceClient
{
    FakeScannerSourceState S => world.ScannerSource;

    public Task<ScannerProjectVersion?> FindProjectVersionAsync(string projectName, string versionName, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.ScannerSource, "project_version.find", ("project", projectName), ("version", versionName));
        lock (S.Lock)
            return Task.FromResult(S.Projects.GetValueOrDefault(tenant)?.Select(p => p.Version)
                .FirstOrDefault(v => v.ProjectName.Equals(projectName, StringComparison.OrdinalIgnoreCase) && v.VersionName.Equals(versionName, StringComparison.OrdinalIgnoreCase)));
    }

    public Task<IReadOnlyList<ScannerVulnerability>> ListVulnerabilitiesAsync(ScannerProjectVersion version, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.ScannerSource, "vulnerability.list", ("project", version.ProjectName), ("version", version.VersionName));
        lock (S.Lock)
            return Task.FromResult<IReadOnlyList<ScannerVulnerability>>(S.Projects.GetValueOrDefault(tenant)?.FirstOrDefault(p => p.Version == version).Vulns?.ToList() ?? []);
    }

    public Task<RemediationGuidance?> GetRemediationGuidanceAsync(ComponentVersionRef component, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.ScannerSource, "remediation.get", ("component", component.ComponentId), ("version", component.ComponentVersionId));
        lock (S.Lock) return Task.FromResult(S.Guidance.GetValueOrDefault(tenant)?.GetValueOrDefault(component.ComponentId + "/" + component.ComponentVersionId));
    }
}

/// <summary>Scripted model: responders are tried in order; the first non-null answer wins. Token usage is deterministic (≈ 4 chars / token).</summary>
public sealed class FakeModelState
{
    readonly List<Func<ModelRequest, string?>> _responders = [];
    public IReadOnlyCollection<string>? AvailableModels { get; set; }

    /// <summary>Answer every request whose structured output is <paramref name="schemaName"/> (e.g. "triage_output").</summary>
    public FakeModelState RespondToSchema(string schemaName, Func<ModelRequest, string> answer)
    {
        lock (_responders) _responders.Add(r => r.Output?.Name == schemaName ? answer(r) : null);
        return this;
    }

    public FakeModelState Respond(Func<ModelRequest, string?> responder) { lock (_responders) _responders.Add(responder); return this; }

    internal string Answer(ModelRequest r)
    {
        lock (_responders)
            foreach (var x in _responders)
                if (x(r) is { } a) return a;
        throw new ConnectorException($"fake model: no scripted answer for output '{r.Output?.Name ?? "text"}' on {r.Model}");
    }

    public static long Tokens(string s) => (s.Length + 3) / 4;
}

public sealed class FakeModelProviderClient(FakeConnectorWorld world, string tenant) : IModelProviderClient
{
    public string ProviderFamily => "fake";

    public Task<ModelResponse> CompleteAsync(ModelRequest request, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.ModelProvider, "model.complete", ("model", request.Model), ("output", request.Output?.Name), ("agent", request.AgentName));
        var text = world.Models.Answer(request);
        var usage = new TokenUsage(request.Messages.Sum(m => FakeModelState.Tokens(m.Text)), FakeModelState.Tokens(text));
        return Task.FromResult(new ModelResponse(text, request.Model, "fake-" + FakeConnectorWorld.Sha(request.Model, text)[..12], usage));
    }

    public Task<IReadOnlyCollection<string>?> ListAvailableModelsAsync(CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.ModelProvider, "model.catalog");
        return Task.FromResult(world.Models.AvailableModels);
    }
}

public sealed class FakeNotifierState
{
    readonly List<(string Tenant, Notification Notification)> _sent = [];
    public IReadOnlyList<Notification> Sent(string? tenantId = null) { lock (_sent) return _sent.Where(s => tenantId == null || s.Tenant.Equals(tenantId, StringComparison.OrdinalIgnoreCase)).Select(s => s.Notification).ToList(); }
    internal void Add(string tenant, Notification n) { lock (_sent) _sent.Add((tenant, n)); }
}

public sealed class FakeNotifierClient(FakeConnectorWorld world, string tenant) : INotifierClient
{
    public Task NotifyAsync(Notification notification, CancellationToken ct)
    {
        world.Record(tenant, ConnectorKind.Notifier, "notification.send", ("title", notification.Title), ("level", notification.Level));
        world.Notifier.Add(tenant, notification);
        return Task.CompletedTask;
    }
}
