using Aegis.Core.Diagnostics;
using Aegis.Core.Events;

namespace Aegis.Core.Telemetry;

/// <summary>
/// One source of Windows telemetry (Security event log, process creation trace, network
/// connections, ...). Every collector's only job is to turn provider-specific data into
/// <see cref="NormalizedEvent"/>s and hand them to the callback - correlation, scoring and
/// decisions all happen downstream so no collector needs to know about any other. This
/// interface has no Windows dependency; concrete collectors live in <c>Aegis.Sensor</c>.
/// </summary>
public interface ITelemetryCollector : IDisposable
{
    string Name { get; }

    void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger);

    void Stop();
}
