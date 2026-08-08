using System.Management;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Real-time process create/terminate telemetry via WMI's <c>Win32_ProcessStartTrace</c> /
/// <c>Win32_ProcessStopTrace</c> - available and stable from Windows XP through Server 2025,
/// no audit-policy changes required (unlike Security 4688). Requires the sensor to run
/// elevated (LocalSystem, as the Windows Service does).
/// </summary>
public sealed class ProcessTraceCollector : ITelemetryCollector
{
    public string Name => "ProcessTrace";

    private readonly string _hostId;
    private readonly string _hostRole;
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;
    private readonly Dictionary<int, string> _recentImageByPid = new();
    private readonly object _lock = new();

    public ProcessTraceCollector(string hostId, string hostRole)
    {
        _hostId = hostId;
        _hostRole = hostRole;
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        _startWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        _startWatcher.EventArrived += (_, e) =>
        {
            try
            {
                var processName = (string)e.NewEvent["ProcessName"];
                var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                var parentPid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);

                lock (_lock) { _recentImageByPid[pid] = processName; }

                var parentImage = TryLookupParentImage(parentPid);

                onEvent(new NormalizedEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = DateTimeOffset.UtcNow,
                    HostId = _hostId,
                    HostRole = _hostRole,
                    ProcessId = pid,
                    ParentProcessId = parentPid,
                    ImagePath = processName,
                    ParentImagePath = parentImage,
                    ActionType = ActionType.ProcessCreate,
                    ObjectType = ObjectType.Process,
                    Result = ActionResult.Success,
                    RawEventReference = $"Win32_ProcessStartTrace:{pid}:{DateTimeOffset.UtcNow.Ticks}",
                });
            }
            catch (Exception ex)
            {
                logger.Error(Name, "Failed to process a Win32_ProcessStartTrace event.", ex);
            }
        };

        _stopWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
        _stopWatcher.EventArrived += (_, e) =>
        {
            try
            {
                var processName = (string)e.NewEvent["ProcessName"];
                var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                lock (_lock) { _recentImageByPid.Remove(pid); }

                onEvent(new NormalizedEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = DateTimeOffset.UtcNow,
                    HostId = _hostId,
                    HostRole = _hostRole,
                    ProcessId = pid,
                    ImagePath = processName,
                    ActionType = ActionType.ProcessTerminate,
                    ObjectType = ObjectType.Process,
                    Result = ActionResult.Success,
                    RawEventReference = $"Win32_ProcessStopTrace:{pid}:{DateTimeOffset.UtcNow.Ticks}",
                });
            }
            catch (Exception ex)
            {
                logger.Error(Name, "Failed to process a Win32_ProcessStopTrace event.", ex);
            }
        };

        try
        {
            _startWatcher.Start();
            _stopWatcher.Start();
            logger.Info(Name, "Process trace collector started.");
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to start WMI process trace watchers - is the sensor running elevated?", ex);
        }
    }

    private string? TryLookupParentImage(int parentPid)
    {
        lock (_lock)
        {
            if (_recentImageByPid.TryGetValue(parentPid, out var image)) return image;
        }

        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT Name FROM Win32_Process WHERE ProcessId={parentPid}");
            foreach (ManagementObject proc in searcher.Get())
            {
                return (string)proc["Name"];
            }
        }
        catch
        {
            // Parent may have already exited by the time we look it up - acceptable, lineage rarity just falls back to "?".
        }
        return null;
    }

    public void Stop()
    {
        _startWatcher?.Stop();
        _stopWatcher?.Stop();
    }

    public void Dispose()
    {
        Stop();
        _startWatcher?.Dispose();
        _stopWatcher?.Dispose();
    }
}
