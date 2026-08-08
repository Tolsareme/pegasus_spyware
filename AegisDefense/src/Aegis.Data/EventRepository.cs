using System.Text.Json;
using Aegis.Core.Events;
using Aegis.Core.Integrity;
using Microsoft.Data.Sqlite;

namespace Aegis.Data;

/// <summary>Append-only store for normalized events - the durable record behind every alert's evidence trail.</summary>
public sealed class EventRepository
{
    private readonly AegisDatabase _db;

    public EventRepository(AegisDatabase db) => _db = db;

    /// <summary>
    /// Inserts one event. <paramref name="sequence"/>/<paramref name="chainHash"/>/
    /// <paramref name="prevChainHash"/> are optional so callers that don't care about the
    /// tamper-evidence chain (e.g. most unit tests) can omit them; <c>DefenseEngine</c>
    /// always supplies them in production.
    /// </summary>
    public async Task InsertAsync(NormalizedEvent evt, long? sequence = null, string? chainHash = null, string? prevChainHash = null, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO events
 (event_id, timestamp, host_id, user_id, process_id, parent_process_id, process_hash, signer,
  image_path, parent_image_path, host_role, logon_type, action_type, object_type, object_id,
  source_ip, destination_ip, destination_port, privilege_context, result, confidence,
  raw_event_reference, command_line, tags_json, sequence, chain_hash, prev_chain_hash)
VALUES
 ($event_id, $timestamp, $host_id, $user_id, $process_id, $parent_process_id, $process_hash, $signer,
  $image_path, $parent_image_path, $host_role, $logon_type, $action_type, $object_type, $object_id,
  $source_ip, $destination_ip, $destination_port, $privilege_context, $result, $confidence,
  $raw_event_reference, $command_line, $tags_json, $sequence, $chain_hash, $prev_chain_hash);";

        BindEvent(cmd, evt);
        cmd.Parameters.AddWithValue("$sequence", (object?)sequence ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$chain_hash", (object?)chainHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$prev_chain_hash", (object?)prevChainHash ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Last-written chain link, used to resume the hash chain across service restarts. Null if no chained event has ever been written.</summary>
    public async Task<(long Sequence, string ChainHash)?> GetLastChainLinkAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT sequence, chain_hash FROM events WHERE sequence IS NOT NULL ORDER BY sequence DESC LIMIT 1;";
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        return (reader.GetInt64(0), reader.GetString(1));
    }

    /// <summary>Every chained event in ascending sequence order, for <see cref="Aegis.Core.Integrity.EventChainVerifier"/>.</summary>
    public async Task<IReadOnlyList<(long Sequence, string PreviousHash, string ChainHash, NormalizedEvent Event)>> GetChainAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM events WHERE sequence IS NOT NULL ORDER BY sequence ASC;";

        var results = new List<(long, string, string, NormalizedEvent)>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var sequence = reader.GetInt64(reader.GetOrdinal("sequence"));
            var chainHash = reader.GetString(reader.GetOrdinal("chain_hash"));
            var prevHash = GetNullableString(reader, "prev_chain_hash") ?? EventChainSigner.GenesisHash;
            results.Add((sequence, prevHash, chainHash, ReadEvent(reader)));
        }
        return results;
    }

    /// <summary>Deletes raw events older than <paramref name="cutoff"/> (retention/rollup - doc v2). Alerts and the audit log are never pruned by this; only the raw telemetry that backs them, so old alerts may end up with evidence-event references that no longer resolve - expected and documented in docs/OPERATIONS.md.</summary>
    public async Task<int> PruneOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM events WHERE timestamp < $cutoff;";
        cmd.Parameters.AddWithValue("$cutoff", cutoff.ToString("O"));
        return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<NormalizedEvent>> QueryAsync(string? hostId = null, DateTimeOffset? since = null, int take = 500, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();

        var where = new List<string>();
        if (hostId is not null) where.Add("host_id = $host_id");
        if (since is not null) where.Add("timestamp >= $since");
        var whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";

        cmd.CommandText = $"SELECT * FROM events {whereClause} ORDER BY timestamp DESC LIMIT $take;";
        if (hostId is not null) cmd.Parameters.AddWithValue("$host_id", hostId);
        if (since is not null) cmd.Parameters.AddWithValue("$since", since.Value.ToString("O"));
        cmd.Parameters.AddWithValue("$take", take);

        var results = new List<NormalizedEvent>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(ReadEvent(reader));
        }
        return results;
    }

    public async Task<int> CountSinceAsync(DateTimeOffset since, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM events WHERE timestamp >= $since;";
        cmd.Parameters.AddWithValue("$since", since.ToString("O"));
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return Convert.ToInt32(result);
    }

    /// <summary>Per-host event count and last-seen timestamp since <paramref name="since"/> - the data behind the GUI's Hosts inventory tab.</summary>
    public async Task<IReadOnlyDictionary<string, (int Count, DateTimeOffset LastSeen)>> GetHostSummariesAsync(DateTimeOffset since, CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT host_id, COUNT(*), MAX(timestamp) FROM events WHERE timestamp >= $since GROUP BY host_id;";
        cmd.Parameters.AddWithValue("$since", since.ToString("O"));

        var results = new Dictionary<string, (int, DateTimeOffset)>(StringComparer.OrdinalIgnoreCase);
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results[reader.GetString(0)] = (reader.GetInt32(1), DateTimeOffset.Parse(reader.GetString(2)));
        }
        return results;
    }

    public async Task<IReadOnlyList<string>> DistinctHostIdsAsync(CancellationToken ct = default)
    {
        using var connection = _db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT DISTINCT host_id FROM events;";
        var results = new List<string>();
        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) results.Add(reader.GetString(0));
        return results;
    }

    private static void BindEvent(SqliteCommand cmd, NormalizedEvent evt)
    {
        cmd.Parameters.AddWithValue("$event_id", evt.EventId.ToString());
        cmd.Parameters.AddWithValue("$timestamp", evt.Timestamp.ToString("O"));
        cmd.Parameters.AddWithValue("$host_id", evt.HostId);
        cmd.Parameters.AddWithValue("$user_id", (object?)evt.UserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$process_id", (object?)evt.ProcessId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$parent_process_id", (object?)evt.ParentProcessId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$process_hash", (object?)evt.ProcessHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$signer", (object?)evt.Signer ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$image_path", (object?)evt.ImagePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$parent_image_path", (object?)evt.ParentImagePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$host_role", (object?)evt.HostRole ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$logon_type", (object?)evt.LogonType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$action_type", evt.ActionType.ToString());
        cmd.Parameters.AddWithValue("$object_type", evt.ObjectType.ToString());
        cmd.Parameters.AddWithValue("$object_id", (object?)evt.ObjectId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$source_ip", (object?)evt.SourceIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$destination_ip", (object?)evt.DestinationIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$destination_port", (object?)evt.DestinationPort ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$privilege_context", (object?)evt.PrivilegeContext ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$result", evt.Result.ToString());
        cmd.Parameters.AddWithValue("$confidence", evt.Confidence);
        cmd.Parameters.AddWithValue("$raw_event_reference", (object?)evt.RawEventReference ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$command_line", (object?)evt.CommandLine ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$tags_json", evt.Tags is null ? DBNull.Value : JsonSerializer.Serialize(evt.Tags));
    }

    private static NormalizedEvent ReadEvent(SqliteDataReader r)
    {
        IReadOnlyDictionary<string, string>? tags = null;
        var tagsOrdinal = r.GetOrdinal("tags_json");
        if (!r.IsDBNull(tagsOrdinal))
        {
            tags = JsonSerializer.Deserialize<Dictionary<string, string>>(r.GetString(tagsOrdinal));
        }

        return new NormalizedEvent
        {
            EventId = Guid.Parse(r.GetString(r.GetOrdinal("event_id"))),
            Timestamp = DateTimeOffset.Parse(r.GetString(r.GetOrdinal("timestamp"))),
            HostId = r.GetString(r.GetOrdinal("host_id")),
            UserId = GetNullableString(r, "user_id"),
            ProcessId = GetNullableInt(r, "process_id"),
            ParentProcessId = GetNullableInt(r, "parent_process_id"),
            ProcessHash = GetNullableString(r, "process_hash"),
            Signer = GetNullableString(r, "signer"),
            ImagePath = GetNullableString(r, "image_path"),
            ParentImagePath = GetNullableString(r, "parent_image_path"),
            HostRole = GetNullableString(r, "host_role"),
            LogonType = GetNullableInt(r, "logon_type"),
            ActionType = EnumCompat.Parse<ActionType>(r.GetString(r.GetOrdinal("action_type"))),
            ObjectType = EnumCompat.Parse<ObjectType>(r.GetString(r.GetOrdinal("object_type"))),
            ObjectId = GetNullableString(r, "object_id"),
            SourceIp = GetNullableString(r, "source_ip"),
            DestinationIp = GetNullableString(r, "destination_ip"),
            DestinationPort = GetNullableInt(r, "destination_port"),
            PrivilegeContext = GetNullableString(r, "privilege_context"),
            Result = EnumCompat.Parse<ActionResult>(r.GetString(r.GetOrdinal("result"))),
            Confidence = r.GetDouble(r.GetOrdinal("confidence")),
            RawEventReference = GetNullableString(r, "raw_event_reference"),
            CommandLine = GetNullableString(r, "command_line"),
            Tags = tags,
        };
    }

    internal static string? GetNullableString(SqliteDataReader r, string column)
    {
        var ordinal = r.GetOrdinal(column);
        return r.IsDBNull(ordinal) ? null : r.GetString(ordinal);
    }

    internal static int? GetNullableInt(SqliteDataReader r, string column)
    {
        var ordinal = r.GetOrdinal(column);
        return r.IsDBNull(ordinal) ? null : r.GetInt32(ordinal);
    }
}
