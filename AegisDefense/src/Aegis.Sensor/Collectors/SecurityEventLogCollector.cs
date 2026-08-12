using System.Diagnostics.Eventing.Reader;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Subscribes to the Windows Security event log for authentication, privilege and
/// account-management events (doc §5 "Identity" telemetry row: 4624/4625/4648/4672 and
/// related). Uses <see cref="EventLogWatcher"/> (push-based, no polling) which has been
/// available since Windows Vista / Server 2008 - safe baseline for "old Windows machines".
/// </summary>
public sealed class SecurityEventLogCollector : ITelemetryCollector
{
    public string Name => "SecurityEventLog";

    private readonly string _hostId;
    private readonly string _hostRole;
    private EventLogWatcher? _watcher;

    // Event IDs this collector understands - see doc §5 Identity/Services/Registry rows.
    private static readonly HashSet<int> InterestingIds = new()
    {
        4624, // successful logon
        4625, // failed logon
        4648, // explicit-credential logon (runas / lateral movement indicator)
        4672, // special/admin privileges assigned at logon
        4697, // service installed
        4698, // scheduled task created
        4702, // scheduled task updated
        4720, // user account created
        4732, // member added to a privileged local group
        4735, // local group changed
        4964, // special group assigned to new logon
        4663, // object access (used for decoy file/directory access - see WindowsDecoyMaterializer)
    };

    public SecurityEventLogCollector(string hostId, string hostRole)
    {
        _hostId = hostId;
        _hostRole = hostRole;
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        var idFilter = string.Join(" or ", InterestingIds.Select(id => $"EventID={id}"));
        var query = new EventLogQuery("Security", PathType.LogName, $"*[System[({idFilter})]]");

        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += (_, e) =>
        {
            if (e.EventRecord is null) return;
            try
            {
                using (e.EventRecord)
                {
                    var normalized = Normalize(e.EventRecord);
                    if (normalized is not null) onEvent(normalized);
                }
            }
            catch (Exception ex)
            {
                logger.Error(Name, $"Failed to normalize Security event id {e.EventRecord.Id}.", ex);
            }
        };

        try
        {
            _watcher.Enabled = true;
            logger.Info(Name, "Security event log watcher started.");
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to start Security event log watcher - the sensor account may lack 'Manage auditing and security log' rights.", ex);
        }
    }

    private NormalizedEvent? Normalize(EventRecord record)
    {
        var props = record.Properties;
        string? Prop(int index) => props.Count > index ? props[index].Value?.ToString() : null;

        switch (record.Id)
        {
            case 4624: // successful logon: TargetUserName=idx5, LogonType=idx8
                return Base(record, ActionType.AuthenticationSuccess, ObjectType.UserAccount, Prop(5))
                    with
                    { LogonType = int.TryParse(Prop(8), out var lt) ? lt : null, SourceIp = Prop(18) };

            case 4625: // failed logon
                return Base(record, ActionType.AuthenticationFailure, ObjectType.UserAccount, Prop(5), ActionResult.Failure)
                    with
                    { LogonType = int.TryParse(Prop(10), out var lt2) ? lt2 : null, SourceIp = Prop(19) };

            case 4648: // explicit credential logon (e.g. runas, or a service authenticating outbound)
                return Base(record, ActionType.RemoteAuthentication, ObjectType.UserAccount, Prop(5))
                    with
                    { DestinationIp = Prop(12) };

            case 4672: // special privileges assigned
                return Base(record, ActionType.PrivilegeAssigned, ObjectType.UserAccount, Prop(1));

            case 4697: // service installed
                return Base(record, ActionType.ServiceCreate, ObjectType.Service, Prop(4));

            case 4698: // scheduled task created
                return Base(record, ActionType.ScheduledTaskCreate, ObjectType.ScheduledTask, Prop(4));

            case 4702: // scheduled task updated
                return Base(record, ActionType.ScheduledTaskChange, ObjectType.ScheduledTask, Prop(4));

            case 4720: // user account created
                return Base(record, ActionType.DirectoryObjectChange, ObjectType.UserAccount, Prop(0));

            case 4732:
            case 4735: // privileged group membership change
                return Base(record, ActionType.SecurityControlChange, ObjectType.GroupPolicyObject, Prop(2));

            case 4964: // special groups assigned to new logon
                return Base(record, ActionType.PrivilegeAssigned, ObjectType.UserAccount, Prop(0));

            case 4663: // object access: SubjectUserName=idx1, ObjectName=idx6, ProcessId=idx12, ProcessName=idx13
                return Base(record, ActionType.FileAccess, ObjectType.File, Prop(6))
                    with
                    {
                        UserId = Prop(1),
                        ProcessId = int.TryParse(Prop(12), out var pid) ? pid : null,
                        ImagePath = Prop(13),
                    };

            default:
                return null;
        }
    }

    private NormalizedEvent Base(EventRecord record, ActionType actionType, ObjectType objectType, string? objectId, ActionResult result = ActionResult.Success) => new()
    {
        EventId = Guid.NewGuid(),
        // See the identical comment in PowerShellScriptBlockCollector - EventRecord.TimeCreated
        // is local time; normalize to UTC so this collector's events compare correctly against
        // every other collector's DateTimeOffset.UtcNow-based timestamps.
        Timestamp = record.TimeCreated.HasValue ? new DateTimeOffset(record.TimeCreated.Value).ToUniversalTime() : DateTimeOffset.UtcNow,
        HostId = _hostId,
        HostRole = _hostRole,
        UserId = objectType == ObjectType.UserAccount ? objectId : null,
        ActionType = actionType,
        ObjectType = objectType,
        ObjectId = objectId,
        Result = result,
        RawEventReference = $"Security:{record.RecordId}",
    };

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
