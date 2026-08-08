using System.Text.Json;
using Aegis.Core.Policy;

namespace Aegis.Data;

/// <summary>Stores every policy version ever accepted (audit trail) and tracks which one is active.</summary>
public sealed class PolicyRepository
{
    private readonly AegisDatabase _db;

    public PolicyRepository(AegisDatabase db) => _db = db;

    public async Task SetActiveAsync(DefensePolicy policy, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var tx = connection.BeginTransaction();

        using (var deactivate = connection.CreateCommand())
        {
            deactivate.Transaction = tx;
            deactivate.CommandText = "UPDATE policies SET is_active = 0;";
            await deactivate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = @"
INSERT INTO policies (policy_id, version, is_active, policy_json, stored_at)
VALUES ($policy_id, $version, 1, $policy_json, $stored_at)
ON CONFLICT(policy_id) DO UPDATE SET is_active = 1, policy_json = excluded.policy_json;";
            insert.Parameters.AddWithValue("$policy_id", policy.PolicyId);
            insert.Parameters.AddWithValue("$version", policy.Version);
            insert.Parameters.AddWithValue("$policy_json", JsonSerializer.Serialize(policy));
            insert.Parameters.AddWithValue("$stored_at", DateTimeOffset.UtcNow.ToString("O"));
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        tx.Commit();
    }

    public async Task<DefensePolicy?> GetActiveAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT policy_json FROM policies WHERE is_active = 1 ORDER BY stored_at DESC LIMIT 1;";
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return result is string json ? JsonSerializer.Deserialize<DefensePolicy>(json) : null;
    }

    public async Task<IReadOnlyList<DefensePolicy>> GetHistoryAsync(int take = 50, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT policy_json FROM policies ORDER BY stored_at DESC LIMIT $take;";
        cmd.Parameters.AddWithValue("$take", take);

        var results = new List<DefensePolicy>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var policy = JsonSerializer.Deserialize<DefensePolicy>(reader.GetString(0));
            if (policy is not null) results.Add(policy);
        }
        return results;
    }
}
