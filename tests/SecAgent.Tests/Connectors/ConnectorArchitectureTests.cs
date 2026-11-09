using Xunit;
using System.Reflection;
using System.Xml.Linq;
using SecAgent.Connectors;

namespace SecAgent.Tests.Connectors;

/// <summary>Dependency rules for the connector layer (ports and adapters): agents depend on contracts only; plug-ins never depend on agents.</summary>
public class ConnectorArchitectureTests
{
    static readonly string[] ConnectorImplementations =
        ["SecAgent.Connectors", "SecAgent.Connectors.GitHub", "SecAgent.Connectors.Jira", "SecAgent.Connectors.BlackDuck", "SecAgent.Connectors.OpenAI",
         "SecAgent.Connectors.Teams", "SecAgent.Connectors.KeyVault", "SecAgent.Connectors.Fakes"];

    static IEnumerable<string> ProjectRefs(string project) =>
        XDocument.Load(Path.Combine(TestEnv.RepoRoot, "src", project, project + ".csproj")).Descendants("ProjectReference")
            .Select(e => Path.GetFileNameWithoutExtension(e.Attribute("Include")!.Value));

    static IEnumerable<string> PackageRefs(string project) =>
        XDocument.Load(Path.Combine(TestEnv.RepoRoot, "src", project, project + ".csproj")).Descendants("PackageReference").Select(e => e.Attribute("Include")!.Value);

    [Fact]
    public void Agents_depend_only_on_connector_abstractions()
    {
        var refs = ProjectRefs("SecAgent.Agents").ToList();
        Assert.Contains("SecAgent.Connectors.Abstractions", refs);
        Assert.DoesNotContain(refs, r => ConnectorImplementations.Contains(r));
        Assert.DoesNotContain(PackageRefs("SecAgent.Agents"), p => p.Contains("OpenAI") || p.Contains("Octokit") || p.Contains("Polly") || p.Contains("Http.Resilience"));
        // Compiled assembly too: no implementation (or OpenAI SDK) assembly is referenced by the pipeline.
        var asm = typeof(SecAgent.Agents.AgentServices).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToList();
        Assert.Contains("SecAgent.Connectors.Abstractions", asm);
        Assert.DoesNotContain(asm, a => ConnectorImplementations.Contains(a) || a is "OpenAI" or "Microsoft.Agents.AI.OpenAI");
    }

    [Fact]
    public void Core_knows_nothing_about_connectors()
    {
        Assert.DoesNotContain(typeof(SecAgent.Core.SqlStore).Assembly.GetReferencedAssemblies(), a => a.Name!.StartsWith("SecAgent.Connectors"));
    }

    [Fact]
    public void Connector_abstractions_have_no_dependencies()
    {
        Assert.Empty(ProjectRefs("SecAgent.Connectors.Abstractions"));
        Assert.Empty(PackageRefs("SecAgent.Connectors.Abstractions"));
        Assert.DoesNotContain(typeof(ISourceControlClient).Assembly.GetReferencedAssemblies(), a => a.Name!.StartsWith("SecAgent.") || a.Name!.StartsWith("Microsoft.Extensions"));
    }

    [Theory]
    [InlineData("SecAgent.Connectors")]
    [InlineData("SecAgent.Connectors.GitHub")]
    [InlineData("SecAgent.Connectors.Jira")]
    [InlineData("SecAgent.Connectors.BlackDuck")]
    [InlineData("SecAgent.Connectors.OpenAI")]
    [InlineData("SecAgent.Connectors.Teams")]
    [InlineData("SecAgent.Connectors.KeyVault")]
    [InlineData("SecAgent.Connectors.Fakes")]
    public void Plugins_depend_on_contracts_and_the_runtime_only(string project)
    {
        var allowed = new[] { "SecAgent.Connectors.Abstractions", "SecAgent.Connectors" };
        Assert.All(ProjectRefs(project), r => Assert.Contains(r, allowed));   // never Agents, Core, Intake or Dashboard
    }

    [Fact]
    public void Only_the_composition_root_references_connector_implementations()
    {
        var src = Path.Combine(TestEnv.RepoRoot, "src");
        var referencing = Directory.GetDirectories(src).Select(Path.GetFileName).Where(p => File.Exists(Path.Combine(src, p!, p + ".csproj")))
            .Where(p => !p!.StartsWith("SecAgent.Connectors"))
            .Where(p => ProjectRefs(p!).Any(r => ConnectorImplementations.Contains(r))).ToList();
        Assert.Equal(["SecAgent.Dashboard"], referencing);
        // The worker host gets the same plug-ins only through the shared connector composition (SecAgent.Connectors.Hosting).
        Assert.Contains("SecAgent.Connectors.Hosting", ProjectRefs("SecAgent.Worker"));
    }

    [Fact]
    public void Pipeline_types_take_connector_ports_not_implementations()
    {
        var agents = typeof(SecAgent.Agents.AgentServices).Assembly;
        var leaks = agents.GetTypes().SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).SelectMany(c => c.GetParameters())
                .Concat(t.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Select(p => (ParameterInfo?)null!).Where(_ => false)))
            .Where(p => p.ParameterType.Namespace?.StartsWith("SecAgent.Connectors") == true && !p.ParameterType.Assembly.GetName().Name!.Equals("SecAgent.Connectors.Abstractions"))
            .Select(p => p.Member.DeclaringType!.FullName + ":" + p.ParameterType.FullName).ToList();
        Assert.Empty(leaks);
    }
}
