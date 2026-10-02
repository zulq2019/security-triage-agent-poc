using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.ML.Tokenizers;

namespace SecAgent.Core;

/// <summary>Masks secret values before any model call, log, trace, event, DB write or PR text (NFR-02, D-08).</summary>
public sealed class SecretMasker
{
    readonly ConcurrentDictionary<string, string> _known = new();
    int _maskCount;
    public int MaskCount => _maskCount;

    static readonly Regex[] Patterns =
    [
        new(@"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", RegexOptions.Compiled),
        new(@"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b", RegexOptions.Compiled),
        new(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", RegexOptions.Compiled),
        new(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", RegexOptions.Compiled),
    ];

    /// <summary>Registers a detected secret value so it is masked everywhere. The value itself is never stored.</summary>
    public void Register(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 6) return;
        _known.TryAdd(value, MaskOf(value));
    }

    public static string MaskOf(string value) =>
        value.Length <= 8 ? new string('•', value.Length) : value[..4] + new string('•', Math.Min(12, value.Length - 8)) + value[^4..];

    public string Mask(string? text, bool count = true)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var result = text;
        foreach (var (value, mask) in _known)
        {
            if (result.Contains(value, StringComparison.Ordinal))
            {
                result = result.Replace(value, mask, StringComparison.Ordinal);
                if (count) Interlocked.Increment(ref _maskCount);
            }
        }
        foreach (var re in Patterns)
        {
            result = re.Replace(result, m => { if (count) Interlocked.Increment(ref _maskCount); return MaskOf(m.Value); });
        }
        return result;
    }

    /// <summary>True if any known secret value or secret pattern is present (used by the D-08 store check).</summary>
    public bool ContainsSecret(string text) =>
        _known.Keys.Any(k => text.Contains(k, StringComparison.Ordinal)) || Patterns.Any(p => p.IsMatch(text));
}

/// <summary>Detects instruction-like text inside repository / scanner content (NFR-03). Such text is flagged and neutralised: it is data, never instruction.</summary>
public static class InjectionDetector
{
    static readonly Regex Pattern = new(
        @"(ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(previous|above)|\bas an ai\b|for (ai|llm|gpt|copilot|agent)s? (reviewers?|agents?)|note for (ai|llm|the agent)|mark (all|every|this|these) (findings?|issues?)[^.\n]* (as )?(false positive|safe|resolved)|pre-?approved by|you are now|system prompt|do not (report|flag))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed record Hit(int Line, string Text);

    public static List<Hit> Scan(string text, int firstLineNo = 1)
    {
        var hits = new List<Hit>();
        var lines = text.Replace("\r", "").Split('\n');
        for (int i = 0; i < lines.Length; i++)
            if (Pattern.IsMatch(lines[i])) hits.Add(new Hit(firstLineNo + i, lines[i].Trim()));
        return hits;
    }

    /// <summary>Replaces instruction-like lines with a neutral marker so the model never receives them as text it could follow.</summary>
    public static string Neutralise(string text)
    {
        var lines = text.Replace("\r", "").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (!Pattern.IsMatch(lines[i])) continue;
            var indent = lines[i][..(lines[i].Length - lines[i].TrimStart().Length)];
            lines[i] = indent + "// [secagent: instruction-like comment removed from model context; flagged for AppSec]";
        }
        return string.Join('\n', lines);
    }
}

/// <summary>Token counter used by the context builder. Uses the o200k tokenizer as an estimate; the gateway records actual model-reported tokens.</summary>
public static class Tokens
{
    static readonly Lazy<Tokenizer> Tok = new(() => TiktokenTokenizer.CreateForEncoding("o200k_base"));
    public static int Count(string text) => string.IsNullOrEmpty(text) ? 0 : Tok.Value.CountTokens(text);
    public const string Method = "o200k_base estimate";
}
