using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Core;
using SecAgent.Eval.Composition;

namespace SecAgent.Eval.Cases;

/// <summary>Where golden cases come from.</summary>
public interface ICaseSource
{
    IReadOnlyList<GoldenCase> Load(IReadOnlyCollection<string>? filter = null);
}

/// <summary>Reads eval/golden/cases/*/case.json. A filter matches a case id or category (exact) or an id prefix ending in '*'.</summary>
public sealed class FileSystemCaseSource(IOptions<EvalOptions> options) : ICaseSource
{
    public IReadOnlyList<GoldenCase> Load(IReadOnlyCollection<string>? filter = null)
    {
        var root = Path.Combine(options.Value.CasesRoot, "cases");
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException($"golden cases folder not found: {root}");
        var cases = new List<GoldenCase>();
        foreach (var dir in Directory.GetDirectories(root).Order(StringComparer.Ordinal))
        {
            var file = Path.Combine(dir, "case.json");
            if (!File.Exists(file)) continue;
            var c = JsonSerializer.Deserialize<GoldenCase>(File.ReadAllText(file), Schema.Json) ?? throw new InvalidDataException($"empty case file {file}");
            c.Directory = dir;
            if (c.Id != Path.GetFileName(dir)) throw new InvalidDataException($"{file}: id '{c.Id}' must equal its folder name");
            cases.Add(c);
        }
        if (filter is { Count: > 0 })
            cases = cases.Where(c => filter.Any(f => f == c.Id || f == c.Category || (f.EndsWith('*') && c.Id.StartsWith(f[..^1], StringComparison.Ordinal)))).ToList();
        return cases;
    }
}
