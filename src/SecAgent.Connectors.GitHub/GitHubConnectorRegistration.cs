using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecAgent.Connectors.Http;

namespace SecAgent.Connectors.GitHub;

public static class GitHubConnectorRegistration
{
    /// <summary>Registers the GitHub plug-in, its resilient HttpClient (with the no-merge guard) and the local-dev "gh-cli" secret source.</summary>
    public static ConnectorsBuilder AddGitHubConnector(this ConnectorsBuilder builder)
    {
        builder.Services.TryAddSingleton<IGitCommandRunner, ProcessGitCommandRunner>();
        builder.Services.AddTransient<NoMergeGuardHandler>();
        builder.Services.AddConnectorHttpClient(GitHubConnector.Id).AddHttpMessageHandler<NoMergeGuardHandler>();
        builder.AddSecretSource<GhCliTokenSecretSource>();
        return builder.AddConnector<GitHubConnector, ISourceControlClient>();
    }
}
