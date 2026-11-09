using System.Text.RegularExpressions;

namespace SecAgent.Connectors.GitHub;

/// <summary>Defence in depth for FR-17: even if code (or a future change) tried, the GitHub HttpClient refuses merge, approve-review,
/// branch-protection and ref-deletion endpoints before the request leaves the process.</summary>
public sealed partial class NoMergeGuardHandler : DelegatingHandler
{
    [GeneratedRegex(@"/pulls/\d+/merge/?$|/merges/?$|/merge-upstream/?$", RegexOptions.IgnoreCase)] private static partial Regex LandingPath();
    [GeneratedRegex(@"/pulls/\d+/reviews(/|$)|/branches/.+/protection(/|$)|/rulesets(/|$)|/collaborators(/|$)|/actions/workflows/", RegexOptions.IgnoreCase)] private static partial Regex WriteGuarded();
    [GeneratedRegex(@"/git/refs/", RegexOptions.IgnoreCase)] private static partial Regex RefPath();

    public static bool IsForbidden(HttpMethod method, Uri? uri)
    {
        var path = uri?.AbsolutePath ?? "";
        if (LandingPath().IsMatch(path)) return true;
        if (method != HttpMethod.Get && method != HttpMethod.Head && WriteGuarded().IsMatch(path)) return true;
        if (method == HttpMethod.Delete && RefPath().IsMatch(path)) return true;
        return false;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        IsForbidden(request.Method, request.RequestUri)
            ? throw new ForbiddenConnectorOperationException($"github: {request.Method} {request.RequestUri?.AbsolutePath} is never allowed (no merge / approve / branch protection)")
            : base.SendAsync(request, cancellationToken);
}
