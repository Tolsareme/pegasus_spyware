using Microsoft.Data.Sqlite;

namespace Aegis.Data;

/// <summary>
/// Owns the SQLite connection string/lifetime and applies the schema. One instance is
/// shared by all repositories. File-backed databases open/close a connection per
/// operation (SQLite handles this cheaply and it plays well with a Windows Service that
/// may be paused/resumed); the in-memory mode used by unit tests keeps one connection
/// open for the process lifetime, because a SQLite ":memory:" database only exists while
/// at least one connection to it is open.
/// </summary>
public sealed class AegisDatabase : IDisposable
{
    private readonly string _connectionString;
    private readonly SqliteConnection? _keepAliveConnection;

    private AegisDatabase(string connectionString, SqliteConnection? keepAliveConnection)
    {
        _connectionString = connectionString;
        _keepAliveConnection = keepAliveConnection;
    }

    public static AegisDatabase OpenFile(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Default,
        }.ToString();

        var db = new AegisDatabase(connectionString, keepAliveConnection: null);
        db.InitializeSchema();
        return db;
    }

    public static AegisDatabase OpenInMemoryForTests()
    {
        var connectionString = "Data Source=file:aegis-tests?mode=memory&cache=shared";
        var keepAlive = new SqliteConnection(connectionString);
        keepAlive.Open();

        var db = new AegisDatabase(connectionString, keepAlive);
        db.InitializeSchema();
        return db;
    }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
            pragma.ExecuteNonQuery();
        }
        return connection;
    }

    private void InitializeSchema()
    {
        using var connection = OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = Schema.CreateStatements;
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _keepAliveConnection?.Dispose();
}
