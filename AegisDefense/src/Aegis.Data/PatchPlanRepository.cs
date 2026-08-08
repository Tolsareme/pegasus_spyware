using System.Text.Json;
using Aegis.Core.Patching;

namespace Aegis.Data;

public sealed class PatchPlanRepository
{
    private readonly AegisDatabase _db;

    public PatchPlanRepository(AegisDatabase db) => _db = db;

    public async Task UpsertAsync(PatchRolloutPlan plan, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
INSERT INTO patch_rollout_plans (plan_id, component, stage, plan_json, updated_at)
VALUES ($id, $component, $stage, $json, $updatedAt)
ON CONFLICT(plan_id) DO UPDATE SET component = excluded.component, stage = excluded.stage,
    plan_json = excluded.plan_json, updated_at = excluded.updated_at;";
        cmd.Parameters.AddWithValue("$id", plan.PlanId.ToString());
        cmd.Parameters.AddWithValue("$component", plan.Component);
        cmd.Parameters.AddWithValue("$stage", plan.Stage.ToString());
        cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(plan));
        cmd.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<PatchRolloutPlan?> GetAsync(Guid planId, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT plan_json FROM patch_rollout_plans WHERE plan_id = $id;";
        cmd.Parameters.AddWithValue("$id", planId.ToString());

        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        return JsonSerializer.Deserialize<PatchRolloutPlan>(reader.GetString(0));
    }

    public async Task<IReadOnlyList<PatchRolloutPlan>> ListAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT plan_json FROM patch_rollout_plans ORDER BY updated_at DESC;";

        var results = new List<PatchRolloutPlan>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var plan = JsonSerializer.Deserialize<PatchRolloutPlan>(reader.GetString(0));
            if (plan is not null) results.Add(plan);
        }
        return results;
    }
}
