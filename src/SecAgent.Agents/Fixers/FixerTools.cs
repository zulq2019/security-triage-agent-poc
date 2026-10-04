using System.ComponentModel;
using System.Net.Http.Json;
using System.Text.Json;
using SecAgent.Core;

namespace SecAgent.Agents.Fixers;

/// <summary>Function tools (AIFunction) used by fixers. Registered once; access is gated by the per-agent allow-list.</summary>
public static class FixerTools
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static void Register(AgentServices s)
    {
        s.Tools.Register("nuget.resolve", async ([Description("Package id")] string package, [Description("Minimum safe version")] string minVersion) =>
        {
            var idx = await Http.GetFromJsonAsync<JsonElement>($"https://api.nuget.org/v3-flatcontainer/{package.ToLowerInvariant()}/index.json");
            var versions = idx.GetProperty("versions").EnumerateArray().Select(v => v.GetString()!).Where(v => !v.Contains('-')).ToList();
            var min = Version.Parse(Norm(minVersion));
            var safe = versions.Where(v => Version.TryParse(Norm(v), out var x) && x >= min).OrderBy(v => Version.Parse(Norm(v))).ToList();
            return new { package, lowest_safe = safe.FirstOrDefault(), latest = versions.LastOrDefault(), exists = safe.Count > 0 };
        }, "Resolve the lowest published stable version of a NuGet package that is >= minVersion.");

        s.Tools.Register("keyvault.reference", ([Description("Key Vault secret name")] string secretName, [Description("Vault name")] string vaultName) =>
            new { reference = FixEdits.KeyVaultReference(vaultName, secretName), note = "App Service / Container Apps Key Vault reference syntax; no secret is read or written by the agent." },
            "Compose a Key Vault reference string. Never reads or writes secret values.");

        s.Tools.Register("ticket.rotation_task", (Guid runId, Guid findingId, string title, string details) =>
        {
            var t = new HumanTask { RunId = runId, Type = "rotation", Title = title, Details = s.Masker.Mask(details), FindingIds = [findingId], Owner = "[owner team of sample-orders-api]" };
            s.Store.InsertTask(t);
            return new { task_id = t.TaskId, t.Type, t.Owner };
        }, "Raise a secret rotation task for the owning team (ticketing stand-in). The agent never rotates secrets.");

        s.Tools.Register("ticket.human_task", (Guid runId, Guid findingId, string type, string title, string details) =>
        {
            var t = new HumanTask { RunId = runId, Type = type, Title = title, Details = s.Masker.Mask(details), FindingIds = [findingId], Owner = "[AppSec / legal]" };
            s.Store.InsertTask(t);
            return new { task_id = t.TaskId, t.Type, t.Owner };
        }, "Raise a human decision task (licence decision, suppression sign-off, failed fix).");

        s.Tools.Register("licence.policy", (string spdx) =>
        {
            var rp = s.Cfg.RulePacks["licence"];
            var verdict = FixEdits.LicenceVerdict(rp, spdx);
            return new { spdx, verdict, app_licence = rp.Policy.GetValueOrDefault("app_licence")?.ToString(), authority = rp.Policy.GetValueOrDefault("decision_authority")?.ToString() };
        }, "Check an SPDX licence against the licence policy in the licence rule pack.");
    }

    static string Norm(string v) { var p = v.Split('.'); return string.Join('.', p.Concat(Enumerable.Repeat("0", Math.Max(0, 2 - p.Length)))); }
}
