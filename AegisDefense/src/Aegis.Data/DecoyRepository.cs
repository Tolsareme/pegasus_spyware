using System.Text.Json;
using Aegis.Core.Deception;

namespace Aegis.Data;

public sealed class DecoyRepository
{
    private readonly AegisDatabase _db;

    public DecoyRepository(AegisDatabase db) => _db = db;

    public async Task UpsertAsync(DecoyResourceDefinition decoy, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
INSERT INTO decoys (decoy_id, decoy_json) VALUES ($id, $json)
ON CONFLICT(decoy_id) DO UPDATE SET decoy_json = excluded.decoy_json;";
        cmd.Parameters.AddWithValue("$id", decoy.Id);
        cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(decoy));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> RemoveAsync(string decoyId, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM decoys WHERE decoy_id = $id;";
        cmd.Parameters.AddWithValue("$id", decoyId);
        var rows = await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task<IReadOnlyList<DecoyResourceDefinition>> ListAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT decoy_json FROM decoys;";

        var results = new List<DecoyResourceDefinition>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var decoy = JsonSerializer.Deserialize<DecoyResourceDefinition>(reader.GetString(0));
            if (decoy is not null) results.Add(decoy);
        }
        return results;
    }
}
