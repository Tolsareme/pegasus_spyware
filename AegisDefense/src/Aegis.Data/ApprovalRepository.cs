using System.Text.Json;
using Aegis.Core.Events;
using Aegis.Core.Policy;

namespace Aegis.Data;

public sealed class ApprovalRepository
{
    private readonly AegisDatabase _db;

    public ApprovalRepository(AegisDatabase db) => _db = db;

    public async Task CreateAsync(PendingApproval approval, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
INSERT INTO pending_approvals (approval_id, host_id, alert_id, requested_level, rationale_json, requested_at, resolution)
VALUES ($id, $host_id, $alert_id, $level, $rationale, $requested_at, 'Pending');";
        cmd.Parameters.AddWithValue("$id", approval.ApprovalId.ToString());
        cmd.Parameters.AddWithValue("$host_id", approval.HostId);
        cmd.Parameters.AddWithValue("$alert_id", approval.AlertId.ToString());
        cmd.Parameters.AddWithValue("$level", approval.RequestedLevel.ToString());
        cmd.Parameters.AddWithValue("$rationale", JsonSerializer.Serialize(approval.Rationale));
        cmd.Parameters.AddWithValue("$requested_at", approval.RequestedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> ResolveAsync(Guid approvalId, ApprovalResolution resolution, string resolvedBy, string? note, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
UPDATE pending_approvals
SET resolution = $resolution, resolved_at = $resolved_at, resolved_by = $resolved_by, resolution_note = $note
WHERE approval_id = $id AND resolution = 'Pending';";
        cmd.Parameters.AddWithValue("$resolution", resolution.ToString());
        cmd.Parameters.AddWithValue("$resolved_at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$resolved_by", resolvedBy);
        cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$id", approvalId.ToString());
        var rows = await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task<IReadOnlyList<PendingApproval>> ListPendingAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM pending_approvals WHERE resolution = 'Pending' ORDER BY requested_at ASC;";

        var results = new List<PendingApproval>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new PendingApproval
            {
                ApprovalId = Guid.Parse(reader.GetString(reader.GetOrdinal("approval_id"))),
                HostId = reader.GetString(reader.GetOrdinal("host_id")),
                AlertId = Guid.Parse(reader.GetString(reader.GetOrdinal("alert_id"))),
                RequestedLevel = EnumCompat.Parse<ResponseLevel>(reader.GetString(reader.GetOrdinal("requested_level"))),
                Rationale = JsonSerializer.Deserialize<List<string>>(reader.GetString(reader.GetOrdinal("rationale_json"))) ?? new List<string>(),
                RequestedAt = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("requested_at"))),
                Resolution = EnumCompat.Parse<ApprovalResolution>(reader.GetString(reader.GetOrdinal("resolution"))),
            });
        }
        return results;
    }
}
