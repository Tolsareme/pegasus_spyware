using System.Net;
using System.Net.Sockets;
using System.Text;
using Aegis.Core.Events;
using Aegis.Core.Siem;
using Xunit;

namespace Aegis.Tests;

public class CefSyslogForwarderTests
{
    private static Alert MakeAlert(string title = "Rapid technique switching after failure") => new()
    {
        HostId = "host-1",
        UserId = "alice",
        Title = title,
        Source = "AEG-002",
        Severity = AlertSeverity.Critical,
        EstimatedState = AttackState.LateralMovement,
        Confidence = 0.87,
        RecommendedResponse = ResponseLevel.Contain,
    };

    [Fact]
    public void FormatSyslogCef_ProducesWellFormedCefMessage()
    {
        var forwarder = new CefSyslogForwarder("127.0.0.1", 514, useTcp: false, deviceVendor: "TestVendor");
        var message = forwarder.FormatSyslogCef(MakeAlert());

        Assert.Contains("CEF:0|TestVendor|AegisDefense|1.0|AEG-002|Rapid technique switching after failure|10|", message);
        Assert.Contains("src=host-1", message);
        Assert.Contains("suser=alice", message);
        Assert.Contains("cat=LateralMovement", message);
        Assert.Contains("cs2=Contain", message);
    }

    [Fact]
    public void FormatSyslogCef_EscapesPipesInFreeTextFields()
    {
        var forwarder = new CefSyslogForwarder("127.0.0.1", 514, useTcp: false, deviceVendor: "V");
        var alert = MakeAlert(title: "Suspicious | injected | title");

        var message = forwarder.FormatSyslogCef(alert);

        Assert.Contains("Suspicious \\| injected \\| title", message);
    }

    [Fact]
    public async Task ForwardAlertAsync_SendsUdpDatagram_ReceivedByLoopbackListener()
    {
        using var listener = new UdpClient(0);
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;

        using var forwarder = new CefSyslogForwarder("127.0.0.1", port, useTcp: false, deviceVendor: "TestVendor");

        var receiveTask = listener.ReceiveAsync();
        await forwarder.ForwardAlertAsync(MakeAlert());

        var completed = await Task.WhenAny(receiveTask, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(receiveTask, completed);

        var result = await receiveTask;
        var received = Encoding.UTF8.GetString(result.Buffer);
        Assert.Contains("CEF:0|TestVendor|AegisDefense", received);
        Assert.Null(forwarder.LastError);
    }

    [Fact]
    public async Task NullSiemForwarder_NeverThrows_AndCompletesImmediately()
    {
        var forwarder = new NullSiemForwarder();
        await forwarder.ForwardAlertAsync(MakeAlert());
        // No assertion needed beyond "didn't throw" - this is the always-safe default.
    }
}
