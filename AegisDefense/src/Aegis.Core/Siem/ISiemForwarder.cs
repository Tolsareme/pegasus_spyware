using Aegis.Core.Events;

namespace Aegis.Core.Siem;

/// <summary>
/// Forwards alerts to an external SIEM (Splunk, Sentinel, Elastic, ...) so this platform
/// doesn't have to be a standalone silo. Portable/OS-agnostic - just a socket write - so it
/// lives in Aegis.Core and is exercised in tests with a local loopback listener.
/// </summary>
public interface ISiemForwarder
{
    Task ForwardAlertAsync(Alert alert, CancellationToken ct = default);
}

/// <summary>Default no-op forwarder - used whenever SIEM forwarding is disabled in policy, so callers never need to null-check.</summary>
public sealed class NullSiemForwarder : ISiemForwarder
{
    public Task ForwardAlertAsync(Alert alert, CancellationToken ct = default) => Task.CompletedTask;
}
