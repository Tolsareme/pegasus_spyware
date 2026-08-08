using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.Ipc;

/// <summary>
/// Wire envelope for every request/response crossing the named pipe: one JSON object per
/// line (NDJSON), so framing is trivial (ReadLine) and messages stay human-readable in a
/// packet capture for audit purposes. <see cref="MessageType"/> is a plain string
/// discriminator (e.g. "GetAlerts.Request") so client and server can evolve independently
/// without a shared enum forcing lock-step deploys.
/// </summary>
public sealed class IpcEnvelope
{
    public required Guid RequestId { get; init; }

    public required string MessageType { get; init; }

    /// <summary>Nullable so an error response with no payload serializes as JSON <c>null</c> instead of an unrepresentable "undefined" <see cref="JsonElement"/> (the default struct value), which is not valid JSON and would fail to serialize.</summary>
    public JsonElement? Payload { get; init; }

    /// <summary>Set on responses only, when the server-side handler faulted or rejected the request (e.g. unauthenticated, unsigned policy).</summary>
    public string? Error { get; init; }

    private static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static IpcEnvelope CreateRequest<T>(string messageType, T payload)
    {
        var json = JsonSerializer.SerializeToElement(payload, Options);
        return new IpcEnvelope { RequestId = Guid.NewGuid(), MessageType = messageType, Payload = json };
    }

    public IpcEnvelope CreateResponse<T>(string messageType, T payload, string? error = null)
    {
        var json = JsonSerializer.SerializeToElement(payload, Options);
        return new IpcEnvelope { RequestId = RequestId, MessageType = messageType, Payload = json, Error = error };
    }

    public IpcEnvelope CreateErrorResponse(string error) =>
        new() { RequestId = RequestId, MessageType = MessageType + ".Error", Payload = null, Error = error };

    public T? DeserializePayload<T>() => Payload is null || Payload.Value.ValueKind == JsonValueKind.Undefined
        ? default
        : Payload.Value.Deserialize<T>(Options);

    public string ToLine() => JsonSerializer.Serialize(this, Options);

    public static IpcEnvelope FromLine(string line) =>
        JsonSerializer.Deserialize<IpcEnvelope>(line, Options)
        ?? throw new InvalidDataException("Empty or invalid IPC line.");
}
