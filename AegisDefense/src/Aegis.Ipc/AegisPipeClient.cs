using System.IO.Pipes;
using System.Text;

namespace Aegis.Ipc;

/// <summary>Thin request/response client for the GUI (or any other local tool) to talk to the Aegis.Service control pipe.</summary>
public sealed class AegisPipeClient : IAsyncDisposable
{
    private readonly string _serverName;
    private readonly string _pipeName;
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    public AegisPipeClient(string pipeName = PipeConstants.PipeName, string serverName = ".")
    {
        _pipeName = pipeName;
        _serverName = serverName;
    }

    public bool IsConnected => _pipe?.IsConnected == true;

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        var pipe = new NamedPipeClientStream(_serverName, _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(PipeConstants.ConnectTimeout);
        await pipe.ConnectAsync(timeoutCts.Token).ConfigureAwait(false);

        _pipe = pipe;
        _reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
        _writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
    }

    /// <summary>Sends one request and waits for its correlated response. Not safe to call concurrently from multiple callers on the same client instance without external synchronization beyond what's needed for the single in-flight request this method already serializes.</summary>
    public async Task<IpcEnvelope> SendAsync(IpcEnvelope request, CancellationToken ct = default)
    {
        if (_pipe is null || _reader is null || _writer is null)
            throw new InvalidOperationException("Not connected - call ConnectAsync first.");

        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(PipeConstants.DefaultRequestTimeout);

            await _writer.WriteLineAsync(request.ToLine()).ConfigureAwait(false);

            var readTask = _reader.ReadLineAsync();
            var completed = await Task.WhenAny(readTask, Task.Delay(Timeout.Infinite, timeoutCts.Token)).ConfigureAwait(false);
            if (completed != readTask)
            {
                throw new TimeoutException($"No response for request '{request.MessageType}' ({request.RequestId}) within {PipeConstants.DefaultRequestTimeout}.");
            }

            var line = await readTask.ConfigureAwait(false);
            if (line is null) throw new IOException("Pipe closed by server before responding.");
            return IpcEnvelope.FromLine(line);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async Task<TResponse> RequestAsync<TRequest, TResponse>(string messageType, TRequest payload, CancellationToken ct = default)
    {
        var request = IpcEnvelope.CreateRequest(messageType, payload);
        var response = await SendAsync(request, ct).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(response.Error))
        {
            throw new InvalidOperationException($"Service returned an error for '{messageType}': {response.Error}");
        }
        return response.DeserializePayload<TResponse>()
               ?? throw new InvalidOperationException($"Service returned an empty payload for '{messageType}'.");
    }

    public ValueTask DisposeAsync()
    {
        _reader?.Dispose();
        _writer?.Dispose();
        _pipe?.Dispose();
        _sendLock.Dispose();
        return default;
    }
}
