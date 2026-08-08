using System.IO.Pipes;
using System.Text;

namespace Aegis.Ipc;

/// <summary>
/// Generic accept-loop + NDJSON framing over a <see cref="NamedPipeServerStream"/>.
/// Deliberately knows nothing about pipe security (ACLs) or naming - the host
/// (Aegis.Service, a net48-only project) supplies a factory that constructs each new
/// pipe instance with the correct <c>PipeSecurity</c> restricting access to
/// Administrators + LocalSystem. That keeps this library free of Windows-only
/// <c>System.IO.Pipes.AccessControl</c> types and buildable/testable on any OS.
/// </summary>
public sealed class AegisPipeServer : IAsyncDisposable
{
    private readonly Func<NamedPipeServerStream> _pipeFactory;
    private readonly Func<IpcEnvelope, CancellationToken, Task<IpcEnvelope>> _handler;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public AegisPipeServer(Func<NamedPipeServerStream> pipeFactory, Func<IpcEnvelope, CancellationToken, Task<IpcEnvelope>> handler)
    {
        _pipeFactory = pipeFactory;
        _handler = handler;
    }

    public void Start()
    {
        if (_acceptLoop is not null) throw new InvalidOperationException("Already started.");
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = _pipeFactory();
            }
            catch (Exception)
            {
                // Factory failure (e.g. transient ACL/handle exhaustion) - back off and retry rather than crash the service.
                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                pipe.Dispose();
                break;
            }
            catch (IOException)
            {
                pipe.Dispose();
                continue;
            }

            // Fire-and-forget: keep accepting new connections while this one is served.
            _ = HandleClientAsync(pipe, ct);
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

                while (pipe.IsConnected && !ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (line is null) break;
                    if (line.Length == 0) continue;

                    IpcEnvelope response;
                    IpcEnvelope request;
                    try
                    {
                        request = IpcEnvelope.FromLine(line);
                    }
                    catch (Exception ex)
                    {
                        await writer.WriteLineAsync($"{{\"RequestId\":\"{Guid.Empty}\",\"MessageType\":\"ParseError\",\"Error\":{System.Text.Json.JsonSerializer.Serialize(ex.Message)}}}").ConfigureAwait(false);
                        continue;
                    }

                    try
                    {
                        response = await _handler(request, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        response = request.CreateErrorResponse(ex.Message);
                    }

                    await writer.WriteLineAsync(response.ToLine()).ConfigureAwait(false);
                }
            }
            catch (IOException)
            {
                // Client disconnected mid-message - not exceptional for a control-plane pipe.
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); }
            catch (Exception) { /* best-effort shutdown */ }
        }
        _cts.Dispose();
    }
}
