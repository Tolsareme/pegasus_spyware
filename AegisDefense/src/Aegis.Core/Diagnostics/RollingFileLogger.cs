using System.Text;

namespace Aegis.Core.Diagnostics;

/// <summary>
/// Simple daily-rotating, append-only file logger. No external dependency, no admin
/// action needed to view logs (plain text), and audit entries are written to a
/// dedicated <c>audit-*.log</c> file that is never subject to a lower log-level filter -
/// deployments that turn logging down to Error still keep a complete audit trail.
/// Safe to share across threads: each write takes a short lock and appends.
/// </summary>
public sealed class RollingFileLogger : IAegisLogger
{
    private readonly string _logDirectory;
    private readonly LogLevel _minLevel;
    private readonly object _lock = new();

    public RollingFileLogger(string logDirectory, LogLevel minLevel = LogLevel.Info)
    {
        _logDirectory = logDirectory;
        _minLevel = minLevel;
        Directory.CreateDirectory(_logDirectory);
    }

    public void Log(LogLevel level, string component, string message, Exception? exception = null)
    {
        if (level < _minLevel) return;

        var line = new StringBuilder()
            .Append(DateTimeOffset.UtcNow.ToString("O")).Append(" [").Append(level).Append("] ")
            .Append(component).Append(": ").Append(message);
        if (exception is not null)
        {
            line.Append(" | Exception: ").Append(exception);
        }

        Append($"aegis-{DateTimeOffset.UtcNow:yyyy-MM-dd}.log", line.ToString());
    }

    public void LogAudit(string component, string action, string hostId, string outcome, string detail)
    {
        var line = $"{DateTimeOffset.UtcNow:O} | component={component} | action={action} | host={hostId} | outcome={outcome} | detail={detail}";
        Append($"audit-{DateTimeOffset.UtcNow:yyyy-MM-dd}.log", line);
    }

    private void Append(string fileName, string line)
    {
        var path = Path.Combine(_logDirectory, fileName);
        lock (_lock)
        {
            File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
        }
    }
}
