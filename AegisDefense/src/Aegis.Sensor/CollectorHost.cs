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
/// </summary>
public sealed class CollectorHost : IDisposable
{
    private readonly List<ITelemetryCollector> _collectors;
    private readonly IAegisLogger _logger;
    private bool _started;

    public string HostId { get; }
    public string HostRole { get; }

    public CollectorHost(IAegisLogger logger, string? hostId = null, string? hostRole = null)
    {
        _logger = logger;
        HostId = hostId ?? HostIdentity.GetHostId();
        HostRole = hostRole ?? HostIdentity.GetHostRole();

        _collectors = new List<ITelemetryCollector>
        {
            new ProcessTraceCollector(HostId, HostRole),
            new SecurityEventLogCollector(HostId, HostRole),
            new ServiceChangeCollector(HostId, HostRole),
            new RegistryPersistenceCollector(HostId, HostRole),
            new PowerShellScriptBlockCollector(HostId, HostRole),
            new NetworkConnectionCollector(HostId, HostRole),
        };
    }

    public void Start(Action<NormalizedEvent> onEvent)
    {
        if (_started) throw new InvalidOperationException("Already started.");
        _started = true;

        _logger.Info(nameof(CollectorHost), $"Starting {_collectors.Count} collectors for host '{HostId}' (role: {HostRole}).");
        foreach (var collector in _collectors)
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
    }
}
