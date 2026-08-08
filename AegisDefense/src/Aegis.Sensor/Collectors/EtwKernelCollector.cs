using System.Security.Principal;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Kernel ETW collector via <c>Microsoft.Diagnostics.Tracing.TraceEvent</c> - the "ETW-based
/// process/image/file telemetry where useful" upgrade doc §19/§24 calls out over the MVP's
/// WMI/EventLog baseline. Lower overhead and higher fidelity (catches process/image/network
/// activity the classic providers can miss or rate-limit), at the cost of requiring
/// elevation and exclusive use of the single system-wide "NT Kernel Logger" session - if
/// another tool (AV, another APM agent) already owns that session, or the process isn't
/// elevated, this collector logs why and simply doesn't run; the WMI/EventLog collectors
/// keep providing baseline coverage either way, so ETW is additive, never load-bearing.
/// </summary>
public sealed class EtwKernelCollector : ITelemetryCollector
{
    public string Name => "EtwKernel";

    private readonly string _hostId;
    private readonly string _hostRole;
    private TraceEventSession? _session;
    private Task? _processingTask;

    /// <summary>True once the kernel session is actually up and pumping events. <see cref="CollectorHost"/> uses this to decide whether the WMI-based process/network collectors are still needed as a fallback, so the same process-start/network-connect activity isn't reported twice.</summary>
    public bool IsRunning { get; private set; }

    public EtwKernelCollector(string hostId, string hostRole)
    {
        _hostId = hostId;
        _hostRole = hostRole;
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        if (!IsElevated())
        {
            logger.Warn(Name, "Process is not elevated - the kernel ETW session requires administrator rights. Skipping; WMI/EventLog collectors still provide baseline telemetry.");
            return;
        }

        try
        {
            // Only one "NT Kernel Logger" session can exist system-wide. If a previous, uncleanly
            // shut down instance of this sensor left one running, reclaim it rather than failing.
            if (TraceEventSession.GetActiveSessionNames().Contains(KernelTraceEventParser.KernelSessionName))
            {
                logger.Warn(Name, "An existing NT Kernel Logger session was found (possibly from an unclean previous shutdown, or another tool) - stopping it to reclaim the session.");
                TraceEventSession.GetActiveSession(KernelTraceEventParser.KernelSessionName)?.Stop();
            }

            _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            _session.Source.Kernel.ProcessStart += data =>
            {
                Emit(onEvent, new NormalizedEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = data.TimeStamp,
                    HostId = _hostId,
                    HostRole = _hostRole,
                    ProcessId = data.ProcessID,
                    ParentProcessId = data.ParentID,
                    ImagePath = data.ImageFileName,
                    CommandLine = data.CommandLine,
                    ActionType = ActionType.ProcessCreate,
                    ObjectType = ObjectType.Process,
                    Result = ActionResult.Success,
                    RawEventReference = $"ETW:Process/Start:{data.ProcessID}:{data.TimeStampRelativeMSec}",
                });
            };

            _session.Source.Kernel.ImageLoad += data =>
            {
                Emit(onEvent, new NormalizedEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = data.TimeStamp,
                    HostId = _hostId,
                    HostRole = _hostRole,
                    ProcessId = data.ProcessID,
                    ImagePath = data.FileName,
                    Signer = null, // signature verification is a separate, expensive catalog lookup - left to a future enrichment pass rather than done inline on the ETW callback thread
                    ActionType = ActionType.ImageLoad,
                    ObjectType = ObjectType.File,
                    Result = ActionResult.Success,
                    RawEventReference = $"ETW:Image/Load:{data.ProcessID}:{data.TimeStampRelativeMSec}",
                });
            };

            _session.Source.Kernel.TcpIpConnect += data =>
            {
                Emit(onEvent, new NormalizedEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = data.TimeStamp,
                    HostId = _hostId,
                    HostRole = _hostRole,
                    ProcessId = data.ProcessID,
                    ActionType = ActionType.NetworkConnect,
                    ObjectType = ObjectType.NetworkDestination,
                    DestinationIp = data.daddr.ToString(),
                    DestinationPort = data.dport,
                    Result = ActionResult.Success,
                    RawEventReference = $"ETW:TcpIp/Connect:{data.ProcessID}:{data.TimeStampRelativeMSec}",
                });
            };

            // Source.Process() blocks pumping the ETW buffer until the session is stopped -
            // run it on a dedicated background thread, never the caller's thread.
            _processingTask = Task.Factory.StartNew(() => _session.Source.Process(), TaskCreationOptions.LongRunning);

            IsRunning = true;
            logger.Info(Name, "ETW kernel session started (Process/ImageLoad/NetworkTCPIP).");
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to start the ETW kernel session - falling back to WMI/EventLog collectors only. This is expected if another tool already owns the NT Kernel Logger session, or on an unsupported TraceEvent/OS combination.", ex);
            _session?.Dispose();
            _session = null;
            IsRunning = false;
        }
    }

    private static void Emit(Action<NormalizedEvent> onEvent, NormalizedEvent evt)
    {
        try { onEvent(evt); }
        catch { /* isolated per-event, consistent with CollectorHost's own isolation - never let a downstream fault kill the ETW pump */ }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Stop() => _session?.Stop();

    public void Dispose()
    {
        Stop();
        _session?.Dispose();
    }
}
