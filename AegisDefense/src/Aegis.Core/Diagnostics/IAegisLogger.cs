namespace Aegis.Core.Diagnostics;

public enum LogLevel { Debug, Info, Warn, Error }

/// <summary>
/// Minimal logging seam so Aegis.Core stays dependency-free (no Microsoft.Extensions.Logging
/// or similar pulled into a security-sensitive, minimal-attack-surface agent) while every
/// component still gets structured, leveled logging. High-impact actions additionally use
/// <see cref="LogAudit"/> so operator/GUI review never has to reconstruct "what did the
/// service actually do" from free-text logs alone (doc §29: "log every automated decision").
/// </summary>
public interface IAegisLogger
{
    void Log(LogLevel level, string component, string message, Exception? exception = null);

    /// <summary>A structured, always-persisted record of one automated or approved decision/action - never filtered out regardless of configured log level.</summary>
    void LogAudit(string component, string action, string hostId, string outcome, string detail);
}

public static class AegisLoggerExtensions
{
    public static void Debug(this IAegisLogger logger, string component, string message) => logger.Log(LogLevel.Debug, component, message);
    public static void Info(this IAegisLogger logger, string component, string message) => logger.Log(LogLevel.Info, component, message);
    public static void Warn(this IAegisLogger logger, string component, string message) => logger.Log(LogLevel.Warn, component, message);
    public static void Error(this IAegisLogger logger, string component, string message, Exception? ex = null) => logger.Log(LogLevel.Error, component, message, ex);
}
