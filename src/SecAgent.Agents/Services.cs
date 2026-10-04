using SecAgent.Agents.Llm;
using SecAgent.Agents.Repo;
using SecAgent.Agents.Scanners;
using SecAgent.Core;

namespace SecAgent.Agents;

/// <summary>Composition root for one process (dashboard or CLI).</summary>
public sealed class AgentServices
{
    public required ConfigSnapshot Cfg { get; init; }
    public required SqlStore Store { get; init; }
    public required SecretMasker Masker { get; init; }
    public required LocalBlobStore Blob { get; init; }
    public required KillSwitch Kill { get; init; }
    public required RunEventBus Bus { get; init; }
    public required IMessageQueue Queue { get; init; }
    public required SchemaValidator Validator { get; init; }
    public required ContextBuilder Context { get; init; }
    public required ModelGateway Gateway { get; init; }
    public required ToolInvoker Tools { get; init; }
    public required ScannerHub Scanners { get; init; }
    public required GitWorkspace Git { get; init; }
    public required FindingStateMachine States { get; init; }
    public required Dictionary<string, IFixer> Fixers { get; init; }
    public required string DataRoot { get; init; }

    public static AgentServices Create(string repoRoot, string dataRoot, string sqlConnection)
    {
        var provider = ModelProviderSettings.Load(repoRoot);
        var cfg = ConfigSnapshot.Load(Path.Combine(repoRoot, "rules"), provider);
        var store = new SqlStore(sqlConnection);
        store.EnsureSchema(Path.Combine(repoRoot, "db", "schema.sql"));
        store.EnsureMigrations(Path.Combine(repoRoot, "db", "migrations"));   // 002: ModelUsage (+ backfill from RoutingDecision)
        var masker = new SecretMasker();
        var blob = new LocalBlobStore(Path.Combine(dataRoot, "blob"));
        var kill = new KillSwitch(Path.Combine(dataRoot, "control"), cfg.Policies.KillSwitch);
        var bus = new RunEventBus(masker) { Persist = store.InsertEvent };
        var validator = new SchemaValidator(cfg);
        var tools = new ToolInvoker(cfg, store, kill);
        var gateway = new ModelGateway(cfg, store, kill, validator);
        var adapters = new List<IScannerAdapter> { new GitleaksAdapter(masker, cfg), new TrivyAdapter(), new SemgrepAdapter(cfg), new BinaryCheckAdapter(cfg) };
        var s = new AgentServices
        {
            Cfg = cfg, Store = store, Masker = masker, Blob = blob, Kill = kill, Bus = bus, Queue = new InProcessQueue(), Validator = validator,
            Context = new ContextBuilder(cfg, masker, store, blob), Gateway = gateway, Tools = tools,
            Scanners = new ScannerHub(cfg, adapters, blob, store, validator), Git = new GitWorkspace(Path.Combine(dataRoot, "work")),
            States = new FindingStateMachine(store), Fixers = [], DataRoot = dataRoot,
        };
        SecAgent.Agents.Fixers.FixerTools.Register(s);
        // Plug-in registry: fixers are discovered by id; routing.yaml decides which issue types use which fixer.
        foreach (var f in new IFixer[] { new SecAgent.Agents.Fixers.LibraryFixer(s), new SecAgent.Agents.Fixers.SecretsFixer(s), new SecAgent.Agents.Fixers.UnsafeCodeFixer(s), new SecAgent.Agents.Fixers.BinaryLicenceFixer(s) })
            s.Fixers[f.Id] = f;
        foreach (var (type, route) in cfg.Routing.Routes)
            if (!s.Fixers.ContainsKey(route.Fixer)) throw new InvalidOperationException($"routing.yaml: issue type '{type}' references unknown fixer '{route.Fixer}'");
        return s;
    }
}
