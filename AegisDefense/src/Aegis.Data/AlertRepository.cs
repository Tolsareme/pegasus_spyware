using System.Text.Json;
using Aegis.Core.Events;
using Aegis.Core.Scoring;
using Microsoft.Data.Sqlite;

namespace Aegis.Data;

public sealed class AlertRepository
{
    private readonly AegisDatabase _db;

    public AlertRepository(AegisDatabase db) => _db = db;

    public async Task UpsertAsync(Alert alert, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
INSERT INTO alerts
 (alert_id, created_at, host_id, user_id, title, source, severity, status, estimated_state,
  confidence, risk_breakdown_json, evidence_event_ids_json, evidence_summary_json,
  recommended_response, applied_response, campaign_id)
VALUES
 ($alert_id, $created_at, $host_id, $user_id, $title, $source, $severity, $status, $estimated_state,
  $confidence, $risk_breakdown_json, $evidence_event_ids_json, $evidence_summary_json,
  $recommended_response, $applied_response, $campaign_id)
ON CONFLICT(alert_id) DO UPDATE SET
  status=excluded.status, severity=excluded.severity, confidence=excluded.confidence,
  risk_breakdown_json=excluded.risk_breakdown_json, applied_response=excluded.applied_response,
  campaign_id=excluded.campaign_id;";

        cmd.Parameters.AddWithValue("$alert_id", alert.AlertId.ToString());
        cmd.Parameters.AddWithValue("$created_at", alert.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$host_id", alert.HostId);
        cmd.Parameters.AddWithValue("$user_id", (object?)alert.UserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$title", alert.Title);
        cmd.Parameters.AddWithValue("$source", alert.Source);
        cmd.Parameters.AddWithValue("$severity", alert.Severity.ToString());
        cmd.Parameters.AddWithValue("$status", alert.Status.ToString());
        cmd.Parameters.AddWithValue("$estimated_state", alert.EstimatedState.ToString());
        cmd.Parameters.AddWithValue("$confidence", alert.Confidence);
        cmd.Parameters.AddWithValue("$risk_breakdown_json", alert.RiskBreakdown is null ? DBNull.Value : JsonSerializer.Serialize(alert.RiskBreakdown));
        cmd.Parameters.AddWithValue("$evidence_event_ids_json", JsonSerializer.Serialize(alert.EvidenceEventIds));
        cmd.Parameters.AddWithValue("$evidence_summary_json", JsonSerializer.Serialize(alert.EvidenceSummary));
        cmd.Parameters.AddWithValue("$recommended_response", alert.RecommendedResponse.ToString());
        cmd.Parameters.AddWithValue("$applied_response", alert.AppliedResponse is null ? DBNull.Value : alert.AppliedResponse.Value.ToString());
        cmd.Parameters.AddWithValue("$campaign_id", (object?)alert.CampaignId ?? DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> UpdateStatusAsync(Guid alertId, AlertStatus status, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "UPDATE alerts SET status = $status WHERE alert_id = $alert_id;";
        cmd.Parameters.AddWithValue("$status", status.ToString());
        cmd.Parameters.AddWithValue("$alert_id", alertId.ToString());
        var rows = await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task<IReadOnlyList<Alert>> QueryAsync(string? hostId = null, AlertStatus? status = null, int take = 200, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();

        var where = new List<string>();
        if (hostId is not null) where.Add("host_id = $host_id");
        if (status is not null) where.Add("status = $status");
        var whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";

        cmd.CommandText = $"SELECT * FROM alerts {whereClause} ORDER BY created_at DESC LIMIT $take;";
        if (hostId is not null) cmd.Parameters.AddWithValue("$host_id", hostId);
        if (status is not null) cmd.Parameters.AddWithValue("$status", status.Value.ToString());
        cmd.Parameters.AddWithValue("$take", take);

        var results = new List<Alert>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(ReadAlert(reader));
        }
        return results;
    }

    public async Task<int> CountSinceAsync(DateTimeOffset since, AlertSeverity? minSeverity = null, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = minSeverity is null
            ? "SELECT COUNT(*) FROM alerts WHERE created_at >= $since;"
            : "SELECT COUNT(*) FROM alerts WHERE created_at >= $since AND severity = $severity;";
        cmd.Parameters.AddWithValue("$since", since.ToString("O"));
        if (minSeverity is not null) cmd.Parameters.AddWithValue("$severity", minSeverity.Value.ToString());
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return Convert.ToInt32(result);
    }

    public async Task<IReadOnlyDictionary<string, int>> GetOpenCountsByHostAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT host_id, COUNT(*) FROM alerts WHERE status NOT IN ('Resolved','FalsePositive') GROUP BY host_id;";

        var results = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) results[reader.GetString(0)] = reader.GetInt32(1);
        return results;
    }

    public async Task<int> CountOpenAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('Resolved','FalsePositive');";
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return Convert.ToInt32(result);
    }

    public async Task<IReadOnlyDictionary<string, int>> CountBySeverityAsync(DateTimeOffset since, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT severity, COUNT(*) FROM alerts WHERE created_at >= $since GROUP BY severity;";
        cmd.Parameters.AddWithValue("$since", since.ToString("O"));

        var results = new Dictionary<string, int>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) results[reader.GetString(0)] = reader.GetInt32(1);
        return results;
    }

    private static Alert ReadAlert(SqliteDataReader r)
    {
        var riskJson = EventRepository.GetNullableString(r, "risk_breakdown_json");
        var appliedResponseStr = EventRepository.GetNullableString(r, "applied_response");

        return new Alert
        {
            AlertId = Guid.Parse(r.GetString(r.GetOrdinal("alert_id"))),
            CreatedAt = DateTimeOffset.Parse(r.GetString(r.GetOrdinal("created_at"))),
            HostId = r.GetString(r.GetOrdinal("host_id")),
            UserId = EventRepository.GetNullableString(r, "user_id"),
            Title = r.GetString(r.GetOrdinal("title")),
            Source = r.GetString(r.GetOrdinal("source")),
            Severity = EnumCompat.Parse<AlertSeverity>(r.GetString(r.GetOrdinal("severity"))),
            Status = EnumCompat.Parse<AlertStatus>(r.GetString(r.GetOrdinal("status"))),
            EstimatedState = EnumCompat.Parse<AttackState>(r.GetString(r.GetOrdinal("estimated_state"))),
            Confidence = r.GetDouble(r.GetOrdinal("confidence")),
            RiskBreakdown = riskJson is null ? null : JsonSerializer.Deserialize<HostRiskBreakdown>(riskJson),
            EvidenceEventIds = JsonSerializer.Deserialize<List<Guid>>(r.GetString(r.GetOrdinal("evidence_event_ids_json"))) ?? new List<Guid>(),
            EvidenceSummary = JsonSerializer.Deserialize<List<string>>(r.GetString(r.GetOrdinal("evidence_summary_json"))) ?? new List<string>(),
            RecommendedResponse = EnumCompat.Parse<ResponseLevel>(r.GetString(r.GetOrdinal("recommended_response"))),
            AppliedResponse = appliedResponseStr is null ? null : EnumCompat.Parse<ResponseLevel>(appliedResponseStr),
            CampaignId = EventRepository.GetNullableString(r, "campaign_id"),
        };
    }
}
