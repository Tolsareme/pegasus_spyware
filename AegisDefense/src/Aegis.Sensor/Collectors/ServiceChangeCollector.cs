using System.Management;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// WMI instance-creation/modification events on <c>Win32_Service</c> - persistence and
/// privileged-execution telemetry (doc §5 "Services / tasks" row) that doesn't depend on the
/// Security log's "audit object access" policy being enabled, so it works out of the box.
/// </summary>
public sealed class ServiceChangeCollector : ITelemetryCollector
{
    public string Name => "ServiceChange";

    private readonly string _hostId;
    private readonly string _hostRole;
    private ManagementEventWatcher? _createdWatcher;
    private ManagementEventWatcher? _modifiedWatcher;

    public ServiceChangeCollector(string hostId, string hostRole)
    {
        _hostId = hostId;
        _hostRole = hostRole;
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        _createdWatcher = new ManagementEventWatcher(new WqlEventQuery(
            "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'"));
        _createdWatcher.EventArrived += (_, e) => Handle(e, ActionType.ServiceCreate, onEvent, logger);

        _modifiedWatcher = new ManagementEventWatcher(new WqlEventQuery(
            "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'"));
        _modifiedWatcher.EventArrived += (_, e) => Handle(e, ActionType.ServiceChange, onEvent, logger);

        try
        {
            _createdWatcher.Start();
            _modifiedWatcher.Start();
            logger.Info(Name, "Service change collector started.");
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to start WMI service watchers.", ex);
        }
    }

    private void Handle(EventArrivedEventArgs e, ActionType actionType, Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        try
        {
            var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var name = instance["Name"]?.ToString() ?? "unknown";
            var pathName = instance["PathName"]?.ToString();
            var startMode = instance["StartMode"]?.ToString();

            onEvent(new NormalizedEvent
            {
                EventId = Guid.NewGuid(),
                Timestamp = DateTimeOffset.UtcNow,
                HostId = _hostId,
                HostRole = _hostRole,
                ActionType = actionType,
                ObjectType = ObjectType.Service,
                ObjectId = name,
                ImagePath = pathName,
                Result = ActionResult.Success,
                Tags = startMode is null ? null : new Dictionary<string, string> { ["StartMode"] = startMode },
                RawEventReference = $"Win32_Service:{name}:{DateTimeOffset.UtcNow.Ticks}",
            });
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to normalize a Win32_Service change event.", ex);
        }
    }

    public void Stop()
    {
        _createdWatcher?.Stop();
        _modifiedWatcher?.Stop();
    }

    public void Dispose()
    {
        Stop();
        _createdWatcher?.Dispose();
        _modifiedWatcher?.Dispose();
    }
}
