using System.IO.Pipes;
using Aegis.Ipc;
using Aegis.Ipc.Contracts;
using Xunit;

namespace Aegis.Tests;

public class IpcTests
{
    [Fact]
    public async Task Client_CanRoundTrip_ServiceHealthRequest_ThroughRealNamedPipe()
    {
        var pipeName = "aegis-tests-" + Guid.NewGuid().ToString("N");
        var startedAt = DateTimeOffset.UtcNow;

        await using var server = new AegisPipeServer(
            pipeFactory: () => new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous),
            handler: (envelope, ct) =>
            {
                if (envelope.MessageType == MessageTypes.GetServiceHealth)
                {
                    var response = new GetServiceHealthResponse(true, "1.0.0-test", startedAt, Array.Empty<string>());
                    return Task.FromResult(envelope.CreateResponse(MessageTypes.GetServiceHealth, response));
                }
                return Task.FromResult(envelope.CreateErrorResponse("unknown message type"));
            });
        server.Start();

        await using var client = new AegisPipeClient(pipeName);
        await client.ConnectAsync();

        var health = await client.RequestAsync<GetServiceHealthRequest, GetServiceHealthResponse>(
            MessageTypes.GetServiceHealth, new GetServiceHealthRequest());

        Assert.True(health.Healthy);
        Assert.Equal("1.0.0-test", health.Version);
    }

    [Fact]
    public async Task Client_Throws_WhenServerReturnsError()
    {
        var pipeName = "aegis-tests-" + Guid.NewGuid().ToString("N");

        await using var server = new AegisPipeServer(
            pipeFactory: () => new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous),
            handler: (envelope, ct) => Task.FromResult(envelope.CreateErrorResponse("policy signature invalid")));
        server.Start();

        await using var client = new AegisPipeClient(pipeName);
        await client.ConnectAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.RequestAsync<GetPolicyRequest, GetPolicyResponse>(MessageTypes.GetPolicy, new GetPolicyRequest()));

        Assert.Contains("policy signature invalid", ex.Message);
    }

    [Fact]
    public void Envelope_RoundTrips_ThroughLineSerialization()
    {
        var request = IpcEnvelope.CreateRequest(MessageTypes.GetAlerts, new GetAlertsRequest("host-1", null, 50));
        var line = request.ToLine();
        var parsed = IpcEnvelope.FromLine(line);

        Assert.Equal(request.RequestId, parsed.RequestId);
        Assert.Equal(MessageTypes.GetAlerts, parsed.MessageType);
        var payload = parsed.DeserializePayload<GetAlertsRequest>();
        Assert.Equal("host-1", payload?.HostId);
        Assert.Equal(50, payload?.Take);
    }
}
