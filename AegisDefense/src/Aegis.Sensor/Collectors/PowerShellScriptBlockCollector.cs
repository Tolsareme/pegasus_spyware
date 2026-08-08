using System.Diagnostics.Eventing.Reader;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Subscribes to PowerShell Script Block Logging (event ID 4104 in the
/// "Microsoft-Windows-PowerShell/Operational" channel) - doc §5's "PowerShell / AMSI" row.
/// Requires Script Block Logging to be enabled via Group Policy/registry; if the channel or
/// policy isn't present the collector logs a warning and simply produces no events rather
/// than failing sensor startup, since this is an optional-but-recommended signal.
/// </summary>
public sealed class PowerShellScriptBlockCollector : ITelemetryCollector
{
    public string Name => "PowerShellScriptBlock";

    private const string ChannelName = "Microsoft-Windows-PowerShell/Operational";
    private const int ScriptBlockLoggingEventId = 4104;

    private readonly string _hostId;
    private readonly string _hostRole;
    private EventLogWatcher? _watcher;

    public PowerShellScriptBlockCollector(string hostId, string hostRole)
    {
        _hostId = hostId;
        _hostRole = hostRole;
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        try
        {
            var query = new EventLogQuery(ChannelName, PathType.LogName, $"*[System[(EventID={ScriptBlockLoggingEventId})]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += (_, e) =>
            {
                if (e.EventRecord is null) return;
                try
                {
                    using (e.EventRecord)
                    {
                        var scriptText = e.EventRecord.Properties.Count > 2 ? e.EventRecord.Properties[2].Value?.ToString() : null;
                        onEvent(new NormalizedEvent
                        {
                            EventId = Guid.NewGuid(),
                            Timestamp = e.EventRecord.TimeCreated.HasValue ? new DateTimeOffset(e.EventRecord.TimeCreated.Value) : DateTimeOffset.UtcNow,
                            HostId = _hostId,
                            HostRole = _hostRole,
                            ProcessId = (int?)e.EventRecord.ProcessId,
                            ActionType = ActionType.ScriptExecution,
                            ObjectType = ObjectType.Process,
                            CommandLine = scriptText,
                            Result = ActionResult.Success,
                            RawEventReference = $"PowerShell:{e.EventRecord.RecordId}",
                        });
                    }
                }
                catch (Exception ex)
                {
                    logger.Error(Name, "Failed to normalize a PowerShell script-block event.", ex);
                }
            };

            _watcher.Enabled = true;
            logger.Info(Name, "PowerShell script block collector started.");
        }
        catch (EventLogNotFoundException)
        {
            logger.Warn(Name, $"Channel '{ChannelName}' not found - PowerShell Script Block Logging may not be enabled via policy. Skipping this signal.");
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to start the PowerShell script block collector.", ex);
        }
    }

    public void Stop()
    {
        if (_watcher is not null) _watcher.Enabled = false;
    }

    public void Dispose()
    {
        Stop();
        _watcher?.Dispose();
    }
}
