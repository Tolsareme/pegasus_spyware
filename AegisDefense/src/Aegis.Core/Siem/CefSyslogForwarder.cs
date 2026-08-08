using System.Net.Sockets;
using System.Text;
using Aegis.Core.Events;

namespace Aegis.Core.Siem;

/// <summary>
/// Formats each alert as a CEF (Common Event Format) message wrapped in an RFC 3164 syslog
/// header and sends it over UDP (default, fire-and-forget, matches how most SIEM syslog
/// listeners are deployed) or TCP. CEF is the de-facto standard most SIEMs (Splunk,
/// ArcSight, Sentinel via a syslog connector, Elastic via Logstash) already know how to
/// parse without a custom integration.
///
/// Forwarding is always best-effort: a SIEM outage or unreachable host must never block or
/// slow down detection/response, so every failure is swallowed here (the caller can still
/// see forwarding health via <see cref="LastError"/> for the GUI's engine-status display).
/// </summary>
public sealed class CefSyslogForwarder : ISiemForwarder, IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _useTcp;
    private readonly string _deviceVendor;
    private readonly UdpClient? _udpClient;

    public string? LastError { get; private set; }

    public CefSyslogForwarder(string host, int port, bool useTcp, string deviceVendor)
    {
        _host = host;
        _port = port;
        _useTcp = useTcp;
        _deviceVendor = string.IsNullOrWhiteSpace(deviceVendor) ? "AegisDefense" : deviceVendor;
        if (!useTcp) _udpClient = new UdpClient();
    }

    public async Task ForwardAlertAsync(Alert alert, CancellationToken ct = default)
    {
        var message = FormatSyslogCef(alert);
        var bytes = Encoding.UTF8.GetBytes(message);

        try
        {
            if (_useTcp)
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(_host, _port).ConfigureAwait(false);
                using var stream = tcp.GetStream();
                await stream.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
            }
            else
            {
                await _udpClient!.SendAsync(bytes, bytes.Length, _host, _port).ConfigureAwait(false);
            }
            LastError = null;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
    }

    /// <summary>Public/static so it's independently unit-testable without a real socket.</summary>
    public string FormatSyslogCef(Alert alert)
    {
        var severity = SeverityToCef(alert.Severity);
        var name = Sanitize(alert.Title);
        var signatureId = Sanitize(alert.Source);

        var extension =
            $"src={alert.HostId} " +
            $"suser={Sanitize(alert.UserId) ?? "-"} " +
            $"cat={Sanitize(alert.EstimatedState.ToString())} " +
            $"cs1Label=Confidence cs1={alert.Confidence:F2} " +
            $"cs2Label=RecommendedResponse cs2={alert.RecommendedResponse} " +
            $"cs3Label=AppliedResponse cs3={(alert.AppliedResponse?.ToString() ?? "None")} " +
            $"cs4Label=AlertId cs4={alert.AlertId} " +
            $"rt={DateTimeOffset.UtcNow:MMM dd yyyy HH:mm:ss}";

        var cef = $"CEF:0|{_deviceVendor}|AegisDefense|1.0|{signatureId}|{name}|{severity}|{extension}";

        // RFC 3164 header: <PRI>Timestamp Hostname Tag: message. Facility local0 (16), severity
        // "informational" (6) -> PRI = 16*8+6 = 134; the meaningful severity for the receiving
        // SIEM is the CEF field above, not the syslog PRI, which most CEF-aware listeners ignore.
        var syslogHeader = $"<134>{DateTimeOffset.UtcNow:MMM dd HH:mm:ss} {Environment.MachineName} AegisDefense:";
        return $"{syslogHeader} {cef}";
    }

    private static int SeverityToCef(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => 10,
        AlertSeverity.High => 8,
        AlertSeverity.Medium => 5,
        AlertSeverity.Low => 3,
        _ => 1,
    };

    private static string? Sanitize(string? s) => s?.Replace("\\", "\\\\").Replace("|", "\\|").Replace("\n", " ").Replace("\r", " ");

    public void Dispose() => _udpClient?.Dispose();
}
