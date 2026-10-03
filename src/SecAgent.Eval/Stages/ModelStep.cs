using System.Text.Json;
using SecAgent.Agents;
using SecAgent.Agents.Llm;
using SecAgent.Core;
using SecAgent.Eval.Models;

namespace SecAgent.Eval.Stages;

public sealed record ModelStepResult(JsonElement Json, ContextPack Pack);

/// <summary>One model call of a stage: assemble the context pack with the pipeline's ContextAssembler (rules/gateway/context.yaml: required
/// components, token budget, masking, injection neutralisation), call the model port, validate the output against the rules/schema JSON schema.</summary>
public interface IModelStep
{
    Task<ModelStepResult> RunAsync(CaseContext ctx, string step, string agentId, string taskType, string schemaName, string? severity,
        IEnumerable<ComponentInput> components, CancellationToken ct);
}

public sealed class ModelStep(ContextAssembler assembler, IEvalModelClient model, SchemaValidator validator, SecretMasker masker) : IModelStep
{
    public async Task<ModelStepResult> RunAsync(CaseContext ctx, string step, string agentId, string taskType, string schemaName, string? severity,
        IEnumerable<ComponentInput> components, CancellationToken ct)
    {
        var a = assembler.Assemble(ctx.PackRunId, agentId, ctx.Finding.FindingId, null, components);
        if (a.Pack.OverBudget) throw new OverBudgetPackException($"required context {a.Pack.TokenTotal} > budget {a.Pack.TokenBudget} for {agentId}");
        lock (ctx) { ctx.Prompts.Add(a.Pack.SystemText + "\n" + a.Pack.UserText); ctx.InjectionHits.AddRange(a.InjectionHits); }
        var reply = await model.CompleteAsync(new ModelRequest(ctx.Case, step, agentId, taskType, schemaName, severity, a.Pack.SystemText, a.Pack.UserText), ct);
        lock (ctx) { ctx.Usage.Add(reply.Usage); ctx.ModelOutputs.Add(masker.Mask(reply.Json.GetRawText(), false)); }
        var error = validator.Validate(schemaName, reply.Json);
        if (error != null) throw new SchemaInvalidException($"{step}: model output failed schema '{schemaName}': {error}");
        return new ModelStepResult(reply.Json, a.Pack);
    }
}
