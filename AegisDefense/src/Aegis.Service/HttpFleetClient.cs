using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Aegis.Core.Diagnostics;
using Aegis.Core.Fleet;

namespace Aegis.Service;

/// <summary>
/// net48-compatible HTTP client for the Fleet Hub (v2). Every call is wrapped so a
/// Hub outage/unreachable network never blocks or slows down local detection - reporting
/// and correlation lookups are both best-effort background activity.
/// </summary>
public sealed class HttpFleetClient : IFleetClient, IDisposable
{
    private readonly HttpClient _http;
    private readonly IAegisLogger _logger;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public HttpFleetClient(string hubUrl, string apiKey, IAegisLogger logger)
    {
        _logger = logger;
        _http = new HttpClient { BaseAddress = new Uri(hubUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.Add("X-Aegis-Api-Key", apiKey);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task ReportHeartbeatAsync(FleetHeartbeat heartbeat, CancellationToken ct = default)
    {
        try
        {
            var json = JsonSerializer.Serialize(heartbeat, JsonOptions);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync("api/v1/heartbeat", content, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger.Warn(nameof(HttpFleetClient), $"Heartbeat rejected by Fleet Hub: {(int)response.StatusCode} {response.ReasonPhrase}.");
            }
        }
        catch (Exception ex)
        {
            _logger.Warn(nameof(HttpFleetClient), $"Failed to report heartbeat to Fleet Hub: {ex.Message}");
        }
    }

    public async Task<FleetCorrelationSnapshot?> GetCorrelationAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await _http.GetAsync("api/v1/correlation", ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<FleetCorrelationSnapshot>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            _logger.Warn(nameof(HttpFleetClient), $"Failed to fetch correlation from Fleet Hub: {ex.Message}");
            return null;
        }
    }

    public void Dispose() => _http.Dispose();
}
