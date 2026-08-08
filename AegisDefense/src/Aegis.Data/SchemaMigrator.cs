using Microsoft.Data.Sqlite;

namespace Aegis.Data;

/// <summary>
/// Applies additive schema changes to a pre-existing v1 database (which predates the
/// hash-chain columns added in v2) without losing data. <c>CREATE TABLE IF NOT EXISTS</c>
/// alone can't add columns to a table that already exists, so this runs
/// <c>ALTER TABLE ... ADD COLUMN</c> for anything missing, checked via
/// <c>PRAGMA table_info</c> so it's safe to run on every startup.
/// </summary>
internal static class SchemaMigrator
{
    public static void Migrate(SqliteConnection connection)
    {
        EnsureColumn(connection, "events", "sequence", "INTEGER");
        EnsureColumn(connection, "events", "chain_hash", "TEXT");
        EnsureColumn(connection, "events", "prev_chain_hash", "TEXT");
    }

    private static void EnsureColumn(SqliteConnection connection, string table, string column, string sqlType)
    {
        if (ColumnExists(connection, table, column)) return;

        using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {sqlType} NULL;";
        alter.ExecuteNonQuery();
    }

    private static bool ColumnExists(SqliteConnection connection, string table, string column)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table});";
        using var reader = cmd.ExecuteReader();
        var nameOrdinal = reader.GetOrdinal("name");
        while (reader.Read())
        {
            if (string.Equals(reader.GetString(nameOrdinal), column, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
