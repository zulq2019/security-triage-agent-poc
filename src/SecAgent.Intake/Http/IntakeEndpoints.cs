using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;
using SecAgent.Intake.Application;

namespace SecAgent.Intake.Http;

/// <summary>Thin HTTP adapter. POST /api/intake/{format} takes the raw file as the body (application/json or application/sarif+json) and the
/// metadata as signed X-SecAgent-* headers; everything else is <see cref="IIntakeWebhookHandler"/>'s job.
/// Order of checks: enabled/secret configured (503) → size (413) → signature (401) → metadata (400/403/404) → payload (400/413/422) → dedupe (200/409) → 202.</summary>
public static class IntakeEndpoints
{
    static readonly JsonSerializerOptions Json = new(Schema.Json);

    public static IEndpointRouteBuilder MapSecAgentIntake(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/intake/{format}", async (string format, HttpContext ctx, IIntakeWebhookHandler handler) =>
        {
            if (handler.Precheck(ctx.Request.ContentLength) is { } early) return ToHttp(early);
            var body = await ReadLimitedAsync(ctx, handler.MaxBodyBytes);
            if (body == null) return ToHttp(IntakeResult.Rejected(413, $"payload exceeds {handler.MaxBodyBytes} bytes"));
            var headers = ctx.Request.Headers.Where(h => h.Key.StartsWith(IntakeHeaders.Prefix, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            return ToHttp(await handler.HandleAsync(format, headers, body, ctx.RequestAborted));
        });
        // Read-only view of recent intakes (metadata, counts, status; never payload content).
        app.MapGet("/api/intake", (IIntakeRecordQuery records) => Results.Json(records.All().OrderByDescending(r => r.ReceivedAt).Take(100).Select(r => new
        {
            r.IntakeId, r.Status, r.Meta?.Repo, pr = r.Meta?.PrNumber, r.Meta?.Ref, head_sha = r.Meta?.HeadSha, r.Meta?.Scanner, format = r.Meta?.Format,
            producer_run = r.Meta?.RunId, r.Findings, r.RawUri, r.RunTicket, r.RunId, r.Detail, r.ReceivedAt, r.UpdatedAt,
        }), Json));
        return app;
    }

    static IResult ToHttp(IntakeResult r) => Results.Json(r.Body, Json, statusCode: r.StatusCode);

    /// <summary>Reads at most max bytes; null when the body is larger (chunked uploads have no Content-Length to check up front).</summary>
    static async Task<byte[]?> ReadLimitedAsync(HttpContext ctx, long max)
    {
        if (ctx.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } f) f.MaxRequestBodySize = max + 1;
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        int n;
        try
        {
            while ((n = await ctx.Request.Body.ReadAsync(buf, ctx.RequestAborted)) > 0)
            {
                if (ms.Length + n > max) return null;
                ms.Write(buf, 0, n);
            }
        }
        catch (BadHttpRequestException e) when (e.StatusCode == StatusCodes.Status413PayloadTooLarge) { return null; }
        return ms.ToArray();
    }
}
