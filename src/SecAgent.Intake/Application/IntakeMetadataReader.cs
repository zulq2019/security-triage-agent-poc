using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecAgent.Abstractions.Intake;
using SecAgent.Intake.Configuration;
using SecAgent.Intake.Parsers;

namespace SecAgent.Intake.Application;

/// <summary>Builds and validates <see cref="IntakeMetadata"/> from header-like key/values (webhook headers or blob metadata).</summary>
public interface IIntakeMetadataReader
{
    /// <summary>Accepts "X-SecAgent-Repo" style keys or their snake_case form without the prefix ("repo", "head_sha").
    /// Throws <see cref="IntakeRejectedException"/>: 404 unknown format, 403 repo not allowed, 400 anything malformed.</summary>
    IntakeMetadata Read(string format, IReadOnlyDictionary<string, string> values);
}

public sealed partial class IntakeMetadataReader(IOptions<IntakeOptions> options, IFindingParserRegistry parsers) : IIntakeMetadataReader
{
    [GeneratedRegex(@"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9._-]{1,100}$")] private static partial Regex RepoRe();
    [GeneratedRegex(@"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")] private static partial Regex ShaRe();
    [GeneratedRegex(@"^[a-z0-9][a-z0-9_-]{0,39}$")] private static partial Regex ScannerRe();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")] private static partial Regex RunIdRe();
    [GeneratedRegex(@"^[A-Za-z0-9._/@+-]{1,200}$")] private static partial Regex RefRe();

    public IntakeMetadata Read(string format, IReadOnlyDictionary<string, string> values)
    {
        var o = options.Value;
        string? V(string header)
        {
            var bare = header[IntakeHeaders.Prefix.Length..];
            return values.TryGetValue(header, out var v) || values.TryGetValue(bare.Replace("-", "_").ToLowerInvariant(), out v)
                || values.TryGetValue(bare.ToLowerInvariant(), out v) ? v?.Trim() : null;
        }
        if (!parsers.TryGet(format, out _)) throw new IntakeRejectedException(404, $"unknown intake format '{format}' (expected {string.Join(" | ", parsers.Formats)})");
        var repo = V(IntakeHeaders.Repo) ?? throw Bad($"{IntakeHeaders.Repo} is required (owner/name)");
        if (!RepoRe().IsMatch(repo)) throw Bad($"{IntakeHeaders.Repo} must look like owner/name");
        if (!o.RepoAllowed(repo)) throw new IntakeRejectedException(403, $"repo {repo} is not in Intake:AllowedRepos");
        var sha = (V(IntakeHeaders.HeadSha) ?? throw Bad($"{IntakeHeaders.HeadSha} is required (full commit SHA)")).ToLowerInvariant();
        if (!ShaRe().IsMatch(sha)) throw Bad($"{IntakeHeaders.HeadSha} must be a full 40- or 64-character hex commit SHA");
        var scanner = (V(IntakeHeaders.Scanner) ?? throw Bad($"{IntakeHeaders.Scanner} is required")).ToLowerInvariant();
        if (!ScannerRe().IsMatch(scanner) || !o.AllowedScanners.Contains(scanner, StringComparer.OrdinalIgnoreCase))
            throw Bad($"{IntakeHeaders.Scanner} '{scanner}' is not accepted (Intake:AllowedScanners: {string.Join(", ", o.AllowedScanners)})");
        var runId = V(IntakeHeaders.RunId) ?? throw Bad($"{IntakeHeaders.RunId} is required (e.g. <github.run_id>-<github.run_attempt>)");
        if (!RunIdRe().IsMatch(runId)) throw Bad($"{IntakeHeaders.RunId} has invalid characters");
        int? pr = null;
        if (V(IntakeHeaders.Pr) is { Length: > 0 } p)
        {
            if (!int.TryParse(p, out var n) || n <= 0) throw Bad($"{IntakeHeaders.Pr} must be a positive integer (omit it for backlog/branch scans)");
            pr = n;
        }
        var gitRef = V(IntakeHeaders.Ref) is { Length: > 0 } r ? r : null;
        if (gitRef != null && (!RefRe().IsMatch(gitRef) || gitRef.Contains(".."))) throw Bad($"{IntakeHeaders.Ref} is not a valid branch name");
        return new IntakeMetadata { Format = format.ToLowerInvariant(), Repo = repo, PrNumber = pr, Ref = gitRef, HeadSha = sha, Scanner = scanner, RunId = runId };
    }

    static IntakeRejectedException Bad(string m) => new(400, m);
}
