using System.Net;
using System.Net.Http.Json;
using Aegis.Core.Fleet;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Aegis.Tests;

/// <summary>
/// End-to-end HTTP tests against the real Fleet Hub minimal API (in-process TestServer),
/// proving the auth middleware and heartbeat/correlation round trip actually work over
/// HTTP, not just at the FleetCorrelationStore unit level. Each test gets its own factory
/// (not a shared IClassFixture) so per-test configuration overrides (the API key) can never
/// leak between tests via any internal WebApplicationFactory state caching.
/// </summary>
public class FleetHubIntegrationTests : IDisposable
{
    private const string ApiKey = "test-api-key-12345";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public FleetHubIntegrationTests()
    {
        // Program.cs reads configuration eagerly, before WebApplicationBuilder.Build() - a
        // WithWebHostBuilder(...).ConfigureAppConfiguration(...) override arrives too late to
        // affect that read for a minimal-API (top-level statement) Program.cs. The environment
        // variable fallback path doesn't have that problem: it's read directly from the process
        // environment, which this test process shares with the in-process TestServer, so setting
        // it here before the factory builds the host is reliably visible.
        Environment.SetEnvironmentVariable("AEGIS_FLEETHUB_API_KEY", ApiKey);
        _factory = new WebApplicationFactory<Program>();
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
        Environment.SetEnvironmentVariable("AEGIS_FLEETHUB_API_KEY", null);
    }

    [Fact]
    public async Task Heartbeat_WithoutApiKey_IsRejected()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/heartbeat", new FleetHeartbeat
        {
            HostId = "host-1",
            Timestamp = DateTimeOffset.UtcNow,
            RuleIdsFired = new[] { "AEG-002" },
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Heartbeat_WithWrongApiKey_IsRejected()
    {
        _client.DefaultRequestHeaders.Add("X-Aegis-Api-Key", "wrong-key");

        var response = await _client.PostAsJsonAsync("/api/v1/heartbeat", new FleetHeartbeat
        {
            HostId = "host-1",
            Timestamp = DateTimeOffset.UtcNow,
            RuleIdsFired = new[] { "AEG-002" },
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Heartbeat_ThenCorrelation_RoundTripsAcrossTwoHosts()
    {
        _client.DefaultRequestHeaders.Add("X-Aegis-Api-Key", ApiKey);
        var now = DateTimeOffset.UtcNow;

        var post1 = await _client.PostAsJsonAsync("/api/v1/heartbeat", new FleetHeartbeat
        {
            HostId = "host-A", Timestamp = now, RuleIdsFired = new[] { "AEG-002", "AEG-014" }, RiskScore = 60,
        });
        var post2 = await _client.PostAsJsonAsync("/api/v1/heartbeat", new FleetHeartbeat
        {
            HostId = "host-B", Timestamp = now, RuleIdsFired = new[] { "AEG-002" }, RiskScore = 40,
        });

        Assert.Equal(HttpStatusCode.OK, post1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, post2.StatusCode);

        var correlation = await _client.GetFromJsonAsync<FleetCorrelationSnapshot>("/api/v1/correlation");
        Assert.NotNull(correlation);
        Assert.Equal(2, correlation!.DistinctHostsByRuleId["AEG-002"]);
        Assert.Equal(1, correlation.DistinctHostsByRuleId["AEG-014"]);

        var statuses = await _client.GetFromJsonAsync<List<FleetHostStatus>>("/api/v1/fleet/status");
        Assert.NotNull(statuses);
        Assert.Equal(2, statuses!.Count);
    }

    [Fact]
    public async Task HealthCheck_DoesNotRequireApiKey()
    {
        // Deliberately not attaching the header - health checks (e.g. a load balancer probe) must work unauthenticated.
        var response = await _client.GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
