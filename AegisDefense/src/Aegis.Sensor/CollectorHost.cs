using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;
using Aegis.Sensor.Collectors;

namespace Aegis.Sensor;

/// <summary>
/// Owns the lifecycle of every telemetry collector and funnels their output through one
/// callback. This is the whole surface Aegis.Service needs to know about - it never talks
/// to an individual collector directly, so adding/removing a telemetry source never touches
/// the service host.
///
/// Process-start and network-connect telemetry has two possible sources: the always-available
/// WMI-based collectors, and the higher-fidelity ETW kernel collector (v2). Only one of each
/// pair is ever active at a time - running both would double-report the same activity and
/// skew every feature/score that counts events - so <see cref="Start"/> tries ETW first and
/// only falls back to WMI for whichever slice ETW couldn't actually start.
/// </summary>
public sealed class CollectorHost : IDisposable
{
    private readonly List<ITelemetryCollector> _collectors = new();
    private readonly IAegisLogger _logger;
    private readonly bool _preferEtw;
    private bool _started;

    public string HostId { get; }
    public string HostRole { get; }

    public CollectorHost(IAegisLogger logger, string? hostId = null, string? hostRole = null, bool preferEtw = true)
    {
        _logger = logger;
        _preferEtw = preferEtw;
        HostId = hostId ?? HostIdentity.GetHostId();
        HostRole = hostRole ?? HostIdentity.GetHostRole();
    }

    public void Start(Action<NormalizedEvent> onEvent)
    {
        if (_started) throw new InvalidOperationException("Already started.");
        _started = true;

        var etwCoveredProcessAndNetwork = false;
        if (_preferEtw)
        {
            var etw = new EtwKernelCollector(HostId, HostRole);
            StartCollector(etw, onEvent);
            if (etw.IsRunning)
            {
                _collectors.Add(etw);
                etwCoveredProcessAndNetwork = true;
            }
            else
            {
                etw.Dispose();
            }
        }

        var baseline = new List<ITelemetryCollector>
        {
            new SecurityEventLogCollector(HostId, HostRole),
            new ServiceChangeCollector(HostId, HostRole),
            new RegistryPersistenceCollector(HostId, HostRole),
            new PowerShellScriptBlockCollector(HostId, HostRole),
        };

        if (!etwCoveredProcessAndNetwork)
        {
            baseline.Add(new ProcessTraceCollector(HostId, HostRole));
            baseline.Add(new NetworkConnectionCollector(HostId, HostRole));
        }
        else
        {
            _logger.Info(nameof(CollectorHost), "ETW kernel collector is covering process/image/network telemetry - WMI-based ProcessTrace/NetworkConnection collectors are not started, to avoid double-reporting the same activity.");
        }

        _logger.Info(nameof(CollectorHost), $"Starting {baseline.Count} collector(s) for host '{HostId}' (role: {HostRole}){(etwCoveredProcessAndNetwork ? " (+ ETW kernel collector)" : "")}.");
        foreach (var collector in baseline)
        {
            StartCollector(collector, onEvent);
            _collectors.Add(collector);
        }
    }

    private void StartCollector(ITelemetryCollector collector, Action<NormalizedEvent> onEvent)
    {
        try
        {
            collector.Start(evt => SafeForward(collector.Name, evt, onEvent), _logger);
        }
        catch (Exception ex)
        {
            // One collector failing to start (missing audit policy, disabled channel, ...)
            // should not prevent the others from running.
            _logger.Error(nameof(CollectorHost), $"Collector '{collector.Name}' failed to start.", ex);
        }
    }

    private void SafeForward(string collectorName, NormalizedEvent evt, Action<NormalizedEvent> onEvent)
    {
        try
        {
            onEvent(evt);
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(CollectorHost), $"Downstream handler threw while processing an event from '{collectorName}'.", ex);
        }
    }

    public void Stop()
    {
        foreach (var collector in _collectors)
        {
            try { collector.Stop(); }
            catch (Exception ex) { _logger.Error(nameof(CollectorHost), $"Collector '{collector.Name}' failed to stop cleanly.", ex); }
        }
        _started = false;
    }

    public void Dispose()
    {
        Stop();
        foreach (var collector in _collectors)
        {
            collector.Dispose();
        }
        _collectors.Clear();
    }
}
