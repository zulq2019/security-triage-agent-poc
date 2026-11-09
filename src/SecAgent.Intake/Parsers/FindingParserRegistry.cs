using SecAgent.Abstractions.Intake;

namespace SecAgent.Intake.Parsers;

/// <summary>Resolves the parser strategy for a format. Open/closed: a new format is a new <see cref="IFindingParser"/> registration
/// (services.AddIntakeParser&lt;T&gt;()); nothing here or in the pipeline changes.</summary>
public interface IFindingParserRegistry
{
    IReadOnlyCollection<string> Formats { get; }
    bool TryGet(string format, out IFindingParser parser);
    /// <summary>Format whose parser recognises this file name (<see cref="IFileNameFormatHint"/>), else null.</summary>
    string? InferFormat(string fileName);
}

public sealed class FindingParserRegistry : IFindingParserRegistry
{
    readonly Dictionary<string, IFindingParser> _byFormat = new(StringComparer.OrdinalIgnoreCase);
    readonly IFindingParser[] _ordered;

    public FindingParserRegistry(IEnumerable<IFindingParser> parsers)
    {
        _ordered = parsers.ToArray();
        foreach (var p in _ordered)
            if (!_byFormat.TryAdd(p.Format, p))
                throw new InvalidOperationException($"two intake parsers registered for format '{p.Format}': {_byFormat[p.Format].GetType().Name} and {p.GetType().Name}");
    }

    public IReadOnlyCollection<string> Formats => _byFormat.Keys;
    public bool TryGet(string format, out IFindingParser parser) => _byFormat.TryGetValue(format, out parser!);
    public string? InferFormat(string fileName) => _ordered.FirstOrDefault(p => p is IFileNameFormatHint h && h.Recognises(fileName))?.Format;
}
