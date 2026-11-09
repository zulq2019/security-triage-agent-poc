using Xunit;
using System.Net;
using System.Text.Json.Nodes;
using SecAgent.Connectors;
using SecAgent.Connectors.GitHub;

namespace SecAgent.Tests.Connectors;

/// <summary>Stateful in-memory GitHub REST API (the subset the connector uses), behind an HttpMessageHandler. Synthetic data only.</summary>
public sealed class GitHubSimulator : HttpStub
{
    public sealed class Pr
    {
        public int Number; public string Title = ""; public string Head = ""; public string Base = ""; public string HeadSha = ""; public string BaseSha = "";
        public PullRequestState State = PullRequestState.Open; public List<ChangedFile> Files = []; public string Body = ""; public bool Draft;
    }

    public string Repo { get; }
    public string DefaultBranch { get; set; }
    public string? Token { get; set; }
    public Dictionary<string, string> Branches { get; } = new(StringComparer.Ordinal);
    public List<Pr> Prs { get; } = [];
    public List<(int Pr, string Body)> Comments { get; } = [];
    public Dictionary<string, List<CheckRunInfo>> CheckRuns { get; } = new();
    readonly Dictionary<string, string> _commitTrees = new();
    int _seq;

    public GitHubSimulator(string repo, string defaultBranch = "main") { Repo = repo; DefaultBranch = defaultBranch; }

    string Html(int n) => $"https://github.com/{Repo}/pull/{n}";

    JsonObject PrJson(Pr p) => new()
    {
        ["number"] = p.Number, ["title"] = p.Title, ["html_url"] = Html(p.Number), ["state"] = p.State == PullRequestState.Open ? "open" : "closed",
        ["merged_at"] = p.State == PullRequestState.Merged ? "2026-01-01T00:00:00Z" : null, ["changed_files"] = p.Files.Count,
        ["additions"] = p.Files.Sum(f => f.Additions), ["deletions"] = p.Files.Sum(f => f.Deletions),
        ["head"] = new JsonObject { ["ref"] = p.Head, ["sha"] = p.HeadSha, ["repo"] = new JsonObject { ["full_name"] = Repo } },
        ["base"] = new JsonObject { ["ref"] = p.Base, ["sha"] = p.BaseSha },
    };

    static HttpResponseMessage Unprocessable(string message) => Json(new JsonObject { ["message"] = message }, HttpStatusCode.UnprocessableEntity);

    protected override HttpResponseMessage Handle(SeenRequest r)
    {
        if (Token != null && r.AuthParameter != Token) return Status(HttpStatusCode.Unauthorized);
        var path = Uri.UnescapeDataString(r.Path.TrimStart('/'));
        var query = System.Web.HttpUtility.ParseQueryString(r.PathAndQuery.Contains('?') ? r.PathAndQuery[(r.PathAndQuery.IndexOf('?') + 1)..] : "");
        if (path == "rate_limit") return Json(new JsonObject { ["resources"] = new JsonObject { ["core"] = new JsonObject { ["remaining"] = 4999 } } });
        var prefix = "repos/" + Repo;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return Status(HttpStatusCode.NotFound);
        var rest = path[prefix.Length..].TrimStart('/');
        var m = r.Method.Method;

        if (rest == "" && m == "GET") return Json(new JsonObject { ["full_name"] = Repo, ["default_branch"] = DefaultBranch });
        if (rest == "pulls" && m == "GET")
        {
            var head = query["head"]!; var branch = head[(head.IndexOf(':') + 1)..];
            return Json(new JsonArray(Prs.Where(p => p.Head == branch).Select(p => (JsonNode)PrJson(p)).ToArray()));
        }
        if (rest == "pulls" && m == "POST")
        {
            var j = r.Json!;
            var head = (string)j["head"]!; var bas = (string)j["base"]!;
            if (!Branches.ContainsKey(head)) return Unprocessable("head invalid");
            if (Prs.Any(p => p.Head == head && p.Base == bas && p.State == PullRequestState.Open)) return Unprocessable("A pull request already exists");
            var pr = new Pr { Number = Prs.Count == 0 ? 1 : Prs.Max(p => p.Number) + 1, Title = (string)j["title"]!, Head = head, Base = bas, HeadSha = Branches[head],
                BaseSha = Branches.GetValueOrDefault(bas, ""), Body = (string?)j["body"] ?? "", Draft = (bool?)j["draft"] ?? false };
            Prs.Add(pr);
            return Json(PrJson(pr), HttpStatusCode.Created);
        }
        var seg = rest.Split('/');
        if (seg[0] == "pulls" && seg.Length >= 2 && int.TryParse(seg[1], out var n))
        {
            var pr = Prs.FirstOrDefault(p => p.Number == n);
            if (pr == null) return Status(HttpStatusCode.NotFound);
            if (seg.Length == 2 && m == "GET") return Json(PrJson(pr));
            if (seg.Length == 3 && seg[2] == "files" && m == "GET")
            {
                var per = int.Parse(query["per_page"] ?? "30"); var page = int.Parse(query["page"] ?? "1");
                return Json(new JsonArray(pr.Files.Skip((page - 1) * per).Take(per).Select(f => (JsonNode)new JsonObject
                    { ["filename"] = f.Path, ["status"] = f.Status, ["additions"] = f.Additions, ["deletions"] = f.Deletions, ["previous_filename"] = f.PreviousPath }).ToArray()));
            }
        }
        if (seg[0] == "issues" && seg.Length == 3 && seg[2] == "comments" && m == "POST" && int.TryParse(seg[1], out var ci))
        {
            if (Prs.All(p => p.Number != ci)) return Status(HttpStatusCode.NotFound);
            Comments.Add((ci, (string)r.Json!["body"]!));
            return Json(new JsonObject { ["id"] = 1000L + Comments.Count, ["html_url"] = $"{Html(ci)}#issuecomment-{1000 + Comments.Count}" }, HttpStatusCode.Created);
        }
        if (seg[0] == "branches" && m == "GET")
            return Branches.ContainsKey(string.Join('/', seg.Skip(1))) ? Json(new JsonObject { ["name"] = string.Join('/', seg.Skip(1)) }) : Status(HttpStatusCode.NotFound);
        if (rest == "git/refs" && m == "POST")
        {
            var name = ((string)r.Json!["ref"]!)["refs/heads/".Length..];
            if (!Branches.TryAdd(name, (string)r.Json!["sha"]!)) return Unprocessable("Reference already exists");
            return Json(new JsonObject { ["ref"] = "refs/heads/" + name }, HttpStatusCode.Created);
        }
        if (rest.StartsWith("git/ref/heads/") && m == "GET")
            return Branches.TryGetValue(rest["git/ref/heads/".Length..], out var sha) ? Json(new JsonObject { ["object"] = new JsonObject { ["sha"] = sha } }) : Status(HttpStatusCode.NotFound);
        if (rest.StartsWith("git/commits/") && m == "GET")
            return Json(new JsonObject { ["tree"] = new JsonObject { ["sha"] = _commitTrees.GetValueOrDefault(rest["git/commits/".Length..], "tree-base") } });
        if (rest == "git/trees" && m == "POST") return Json(new JsonObject { ["sha"] = $"tree-{++_seq}" }, HttpStatusCode.Created);
        if (rest == "git/commits" && m == "POST")
        {
            var sha = $"c0ffee{++_seq:D34}";
            _commitTrees[sha] = (string)r.Json!["tree"]!;
            return Json(new JsonObject { ["sha"] = sha }, HttpStatusCode.Created);
        }
        if (rest.StartsWith("git/refs/heads/") && m == "PATCH")
        {
            var name = rest["git/refs/heads/".Length..];
            if ((bool?)r.Json!["force"] != false) return Unprocessable("force updates are not simulated");
            if (!Branches.ContainsKey(name)) return Unprocessable("Reference does not exist");
            Branches[name] = (string)r.Json!["sha"]!;
            return Json(new JsonObject { ["ref"] = "refs/heads/" + name });
        }
        if (seg[0] == "commits" && seg.Length == 3 && seg[2] == "check-runs" && m == "GET")
            return Json(new JsonObject { ["check_runs"] = new JsonArray(CheckRuns.GetValueOrDefault(seg[1], []).Select(c => (JsonNode)new JsonObject
                { ["name"] = c.Name, ["status"] = c.Status, ["conclusion"] = c.Conclusion, ["details_url"] = c.DetailsUrl }).ToArray()) });
        return Status(HttpStatusCode.NotFound);
    }
}

/// <summary>Stands in for `git push` / `git rev-parse` against the simulator: a plain push of a new branch works, an existing branch is rejected.</summary>
public sealed class SimulatedGitRunner(GitHubSimulator sim) : IGitCommandRunner
{
    public List<string[]> Calls { get; } = [];

    public Task<GitResult> RunAsync(string workingDirectory, IReadOnlyList<string> args, CancellationToken ct)
    {
        Calls.Add(args.ToArray());
        if (args[0] == "rev-parse") return Task.FromResult(new GitResult(0, "5eed000000000000000000000000000000000001\n", ""));
        if (args[0] == "push")
        {
            var branch = args[^1]["HEAD:refs/heads/".Length..];
            lock (sim)
            {
                if (sim.Branches.ContainsKey(branch)) return Task.FromResult(new GitResult(1, "", " ! [rejected]        HEAD -> " + branch + " (fetch first)\n"));
                sim.Branches[branch] = "5eed000000000000000000000000000000000001";
            }
            return Task.FromResult(new GitResult(0, "", ""));
        }
        return Task.FromResult(new GitResult(1, "", "unsupported"));
    }
}
