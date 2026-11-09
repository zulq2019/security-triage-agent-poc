using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions;
using SecAgent.Abstractions.Agents;
using SecAgent.Agents;
using SecAgent.Agents.Scanners;
using SecAgent.Core;
using SecAgent.Hosting;

namespace SecAgent.Worker.Roles;

/// <summary>Section Agent:Scanner.</summary>
public sealed class ScannerRoleOptions
{
    /// <summary>Repositories are cloned from {CloneBaseUrl}{owner}/{name}.git. Private repos need a token (open item: GitHub App).</summary>
    public string CloneBaseUrl { get; set; } = "https://github.com/";
    /// <summary>Folder under which ScanRequest.LocalPath may point (local synthetic demos). Empty = local paths are refused.</summary>
    public string LocalReposRoot { get; set; } = "";
    public int FetchTimeoutSeconds { get; set; } = 300;
}

/// <summary>scanner: consumes <c>scan</c>, fetches the requested ref, runs the registered scanner adapters (gitleaks, Trivy, Semgrep,
/// binary check: the same adapters as the in-process pipeline), validates the canonical findings, stores raw + canonical output in the
/// write-once blob store and replies on <c>results</c>. Needs no database (the Bicep gives the scanner no SQL role).</summary>
public sealed class ScannerRole : IAgentRoleModule
{
    public string Role => "scanner";

    public void ConfigureServices(IServiceCollection services, AgentRoleContext context)
    {
        services.AddOptions<ScannerRoleOptions>().Bind(context.Configuration.GetSection("Agent:Scanner"));
        services.AddRulesAndSchema(context);
        services.AddLocalBlobStore(context);
        // Plug-in list: the same adapters AgentServices.Create uses; rules/routing/routing.yaml `scanners` decides which run.
        services.AddSingleton<IScannerAdapter>(sp => new GitleaksAdapter(sp.GetRequiredService<SecretMasker>(), sp.GetRequiredService<ConfigSnapshot>()));
        services.AddSingleton<IScannerAdapter, TrivyAdapter>();
        services.AddSingleton<IScannerAdapter>(sp => new SemgrepAdapter(sp.GetRequiredService<ConfigSnapshot>()));
        services.AddSingleton<IScannerAdapter>(sp => new BinaryCheckAdapter(sp.GetRequiredService<ConfigSnapshot>()));
        services.AddSingleton<IRepositoryFetcher, GitRepositoryFetcher>();
        services.AddAgentMessageHandler<ScanRequestHandler>(context, "scan");
    }
}

/// <summary>Port: get a working copy of one ref. Git in the image; a fake in tests.</summary>
public interface IRepositoryFetcher
{
    /// <returns>The working-copy folder and the commit SHA it is at.</returns>
    Task<(string Dir, string CommitSha)> FetchAsync(ScanRequest request, string workDir, CancellationToken ct);
}

/// <summary>Input checks shared by the fetcher and the handler. Refs and repo names reach git's argument list, so anything that could be
/// read as an option (leading '-') or a path escape is refused.</summary>
public static partial class ScanRequestRules
{
    [GeneratedRegex(@"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")] private static partial Regex RepoRule();
    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$")] private static partial Regex RefRule();
    [GeneratedRegex(@"^[a-z0-9_-]{1,40}$")] private static partial Regex LabelRule();

    public static void Validate(ScanRequest r)
    {
        if (!RepoRule().IsMatch(r.Repo) || r.Repo.Contains("..")) throw new AgentMessageRejectedException($"scan: invalid repo '{r.Repo}'");
        if (!RefRule().IsMatch(r.Ref) || r.Ref.Contains("..")) throw new AgentMessageRejectedException("scan: invalid ref");
        if (!LabelRule().IsMatch(r.Label)) throw new AgentMessageRejectedException("scan: invalid label");
    }

    /// <summary>Resolves LocalPath strictly under the configured root, or refuses.</summary>
    public static string LocalPathUnder(string root, string localPath)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new AgentMessageRejectedException("scan: local paths are disabled (Agent:Scanner:LocalReposRoot is empty)");
        var full = Path.GetFullPath(Path.Combine(root, localPath));
        var rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(rootFull, StringComparison.Ordinal)) throw new AgentMessageRejectedException("scan: local path is outside Agent:Scanner:LocalReposRoot");
        return full;
    }
}

/// <summary>Shallow fetch of exactly one ref (branch, tag or commit SHA): git init → fetch --depth 1 origin &lt;ref&gt; → checkout FETCH_HEAD.</summary>
public sealed class GitRepositoryFetcher(IOptions<ScannerRoleOptions> options) : IRepositoryFetcher
{
    public async Task<(string Dir, string CommitSha)> FetchAsync(ScanRequest r, string workDir, CancellationToken ct)
    {
        var o = options.Value;
        var source = r.LocalPath is { Length: > 0 } lp ? ScanRequestRules.LocalPathUnder(o.LocalReposRoot, lp) : $"{o.CloneBaseUrl.TrimEnd('/')}/{r.Repo}.git";
        Directory.CreateDirectory(workDir);
        async Task<string> Git(params string[] args)
        {
            var res = await Proc.RunAsync("git", ["-c", "protocol.file.allow=always", "-c", "advice.detachedHead=false", .. args], workDir, ct, timeoutSeconds: o.FetchTimeoutSeconds);
            if (res.ExitCode != 0) throw new InvalidOperationException($"git {args[0]} failed: {res.StdErr.Trim()}");
            return res.StdOut.Trim();
        }
        await Git("init", "--quiet");
        // Local synthetic repos are mounted read-only and owned by the host user, not the container user, so git's ownership check
        // (safe.directory) refuses them. Git drops -c settings for local transports, hence the constant (no interpolation) upload-pack
        // command; it applies only to LocalPath sources, never to remote clones.
        string[] uploadPack = r.LocalPath is { Length: > 0 } ? ["--upload-pack", "git -c safe.directory=* upload-pack"] : [];
        await Git(["fetch", "--quiet", "--depth", "1", .. uploadPack, "--", source, r.Ref]);
        await Git("checkout", "--quiet", "FETCH_HEAD");
        return (workDir, await Git("rev-parse", "HEAD"));
    }
}

/// <summary>Handles one scan request end to end.</summary>
public sealed class ScanRequestHandler(
    IRepositoryFetcher fetcher, IEnumerable<IScannerAdapter> adapters, ConfigSnapshot cfg, IFindingSchemaValidator validator, LocalBlobStore blob,
    IAgentQueuePublisher publisher, AgentRoleContext context, ILogger<ScanRequestHandler> log) : IAgentMessageHandler
{
    public async Task HandleAsync(AgentDeliveryContext delivery, CancellationToken ct)
    {
        var req = delivery.Message.Payload<ScanRequest>();
        ScanRequestRules.Validate(req);
        var work = Path.Combine(context.DataRoot, "work", "scan", req.RunId.ToString("N"), $"{req.Label}-{Guid.NewGuid():N}"[..20]);
        try
        {
            var (dir, sha) = await fetcher.FetchAsync(req, work, ct);
            var target = new ScanTarget(req.RunId, req.Label, dir, req.Repo, req.Ref, sha, null);
            var tracked = BinaryCheckAdapter.GitFiles(dir).ToHashSet();
            var active = adapters.Where(a => cfg.Routing.Scanners.Contains(a.Id)).ToList();
            var results = await Task.WhenAll(active.Select(async a =>
            {
                var raw = await a.ScanAsync(target, ct);
                var findings = a.Normalise(raw, target, tracked);
                var (rawUri, _) = blob.Put("raw", $"{req.RunId}/{req.Label}/{a.Id}.json", raw.StoredContent);
                foreach (var f in findings) { f.RawEvidenceRef = rawUri; f.CreatedByRun = req.RunId; f.FilePath = f.FilePath?.Replace('\\', '/'); }
                if (findings.Select(validator.ValidateFinding).FirstOrDefault(e => e != null) is { } error)
                    throw new InvalidDataException($"{a.Id} output failed canonical schema validation: {error}");
                return (a.Id, raw.ScannerVersion, findings);
            }));
            var all = results.SelectMany(r => r.findings).ToList();
            var (findingsUri, hash) = blob.Put("raw", $"{req.RunId}/{req.Label}/canonical-findings.json", JsonSerializer.Serialize(all, Schema.Json));
            var data = new Dictionary<string, string> { ["findings_uri"] = findingsUri, ["findings_hash"] = hash, ["commit_sha"] = sha, ["label"] = req.Label };
            foreach (var r in results) data[$"count.{r.Id}"] = r.findings.Count.ToString();
            await publisher.PublishAsync("results", AgentMessage.Create($"{delivery.Message.MessageId}:result", req.RunId, AgentMessageTypes.WorkResult,
                new WorkResult(req.RunId, context.Spec.Name, WorkResultStatus.Completed, $"{all.Count} findings from {string.Join(", ", results.Select(r => r.Id))}", data)), ct);
            log.LogInformation("scan {RunId}/{Label} at {Sha}: {Count} findings", req.RunId, req.Label, sha[..Math.Min(7, sha.Length)], all.Count);
        }
        finally { DeleteTree(work); }
    }

    static void DeleteTree(string dir)
    {
        if (!Directory.Exists(dir)) return;
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(dir, recursive: true);
        }
        catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
