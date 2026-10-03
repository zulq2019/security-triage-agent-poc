using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using SecAgent.Core;

namespace SecAgent.Intake;

/// <summary>Minimal-API endpoints. POST /api/intake/sarif and POST /api/intake/blackduck-rapid take the raw file as the body
/// (Content-Type application/json or application/sarif+json) and the metadata as signed X-SecAgent-* headers.
/// Order of checks: enabled/secret configured (503) → size (413) → signature (401) → metadata (400/403) → payload (400/413/422) → dedupe (200/409) → 202.</summary>
public static class IntakeEndpoints
{
    public static IEndpointRouteBuilder MapIntake(this IEndpointRouteBuilder app, IntakeService intake, IIntakeAuthenticator auth, TimeProvider? clock = null)
    {
        var json = new JsonSerializerOptions(Schema.Json);
        clock ??= TimeProvider.System;
        app.MapPost("/api/intake/{format}", async (string format, HttpContext ctx) =>
        {
            var o = intake.Options;
            if (!o.Enabled) return Results.Json(new { status = "rejected", error = "intake is disabled (Intake:Enabled)" }, json, statusCode: 503);
            if (o.HmacSecret == null) return Results.Json(new { status = "rejected", error = $"intake is not configured: set {o.HmacSecretEnv}" }, json, statusCode: 503);
            if (ctx.Request.ContentLength is { } len && len > o.MaxBodyBytes)
                return Results.Json(new { status = "rejected", error = $"payload is {len} bytes; the limit is {o.MaxBodyBytes}" }, json, statusCode: 413);
            var body = await ReadLimitedAsync(ctx, o.MaxBodyBytes);
            if (body == null) return Results.Json(new { status = "rejected", error = $"payload exceeds {o.MaxBodyBytes} bytes" }, json, statusCode: 413);

            var headers = ctx.Request.Headers.Where(h => h.Key.StartsWith("X-SecAgent-", StringComparison.OrdinalIgnoreCase))
                .ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            var a = auth.Authenticate(format, headers, body, clock.GetUtcNow());
            if (!a.Ok) return Results.Json(new { status = "rejected", error = "unauthorized: " + a.Error }, json, statusCode: 401);

            IntakeMetadata meta;
            try { meta = intake.ReadMetadata(format, headers); }
            catch (IntakeRejectedException e) { return Results.Json(new { status = "rejected", error = e.Message }, json, statusCode: e.StatusCode); }
            var r = await intake.AcceptAsync(meta, body, "webhook", ctx.RequestAborted);
            return Results.Json(r.Body, json, statusCode: r.StatusCode);
        });
        // Read-only view of recent intakes (metadata, counts, status; never payload content).
        app.MapGet("/api/intake", () => Results.Json(intake.Ledger.All().OrderByDescending(r => r.ReceivedAt).Take(100).Select(r => new
        {
            r.IntakeId, r.Status, r.Meta?.Repo, pr = r.Meta?.PrNumber, r.Meta?.Ref, head_sha = r.Meta?.HeadSha, r.Meta?.Scanner, format = r.Meta?.Format,
            producer_run = r.Meta?.RunId, r.Findings, r.RawUri, r.RunTicket, r.RunId, r.Detail, r.ReceivedAt, r.UpdatedAt,
        }), json));
        return app;
    }

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
