using Aegis.Core.Fleet;

var builder = WebApplication.CreateBuilder(args);

// Shared-secret auth for the MVP: every request must carry the configured API key. This is
// the minimum viable control for a hub that only ever receives small, non-sensitive
// summaries (rule IDs + a risk score, never raw events) - see docs/ARCHITECTURE.md for the
// mutual-TLS upgrade path recommended before exposing this across an untrusted network.
// IsNullOrWhiteSpace, not just null-coalescing: appsettings.json ships FleetHub:ApiKey as ""
// (deliberately, so it's a visible placeholder rather than a secret in source control) - a
// plain `??` would treat that empty string as "configured" and the Hub would silently
// require an empty header value, which is not a real access control.
var configuredApiKey = builder.Configuration["FleetHub:ApiKey"];
var apiKey = !string.IsNullOrWhiteSpace(configuredApiKey)
    ? configuredApiKey
    : Environment.GetEnvironmentVariable("AEGIS_FLEETHUB_API_KEY");
if (string.IsNullOrWhiteSpace(apiKey))
{
    throw new InvalidOperationException(
        "No API key configured. Set FleetHub:ApiKey in appsettings.json/command line, or the AEGIS_FLEETHUB_API_KEY environment variable, before starting the Fleet Hub.");
}

var correlationWindowMinutes = builder.Configuration.GetValue("FleetHub:CorrelationWindowMinutes", 15);

builder.Services.AddSingleton(new FleetCorrelationStore(TimeSpan.FromMinutes(correlationWindowMinutes)));

var app = builder.Build();

app.Use(async (context, next) =>
{
    // Health checks (load balancer / orchestrator probes) must be reachable without a secret.
    if (context.Request.Path.StartsWithSegments("/healthz"))
    {
        await next();
        return;
    }

    if (!context.Request.Headers.TryGetValue("X-Aegis-Api-Key", out var provided) ||
        !FixedTimeEquals(provided.ToString(), apiKey))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Missing or invalid X-Aegis-Api-Key header.");
        return;
    }
    await next();
});

app.MapPost("/api/v1/heartbeat", (FleetHeartbeat heartbeat, FleetCorrelationStore store) =>
{
    store.RecordHeartbeat(heartbeat);
    return Results.Ok();
});

app.MapGet("/api/v1/correlation", (FleetCorrelationStore store) =>
    Results.Ok(store.GetCorrelation(DateTimeOffset.UtcNow)));

app.MapGet("/api/v1/fleet/status", (FleetCorrelationStore store) =>
    Results.Ok(store.GetHostStatuses()));

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", timestamp = DateTimeOffset.UtcNow }));

app.Run();

// Constant-time comparison so response timing doesn't leak how many leading characters of
// the API key a guess got right.
static bool FixedTimeEquals(string a, string b)
{
    var aBytes = System.Text.Encoding.UTF8.GetBytes(a);
    var bBytes = System.Text.Encoding.UTF8.GetBytes(b);
    return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
}

/// <summary>Exposed for WebApplicationFactory-based integration tests.</summary>
public partial class Program;
