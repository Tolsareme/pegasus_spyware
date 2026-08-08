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
///
/// Likewise knows nothing about *who* the caller is or what role they map to (v2 RBAC) -
/// <paramref name="identifyCaller"/> (if supplied) is invoked once per connection and its
/// result is threaded through to every request on that connection as an opaque string; it
/// is up to the host to decide what that string means (e.g. "Administrator"/"Analyst") and
/// up to the handler to enforce it. When <paramref name="identifyCaller"/> is omitted, every
/// request gets a null caller context, which <c>Aegis.Service.IpcRequestHandler</c> treats
/// as fully trusted - matching the pre-RBAC behavior where the pipe's ACL alone was the gate.
/// </summary>
public sealed class AegisPipeServer : IAsyncDisposable
{
    private readonly Func<NamedPipeServerStream> _pipeFactory;
    private readonly Func<IpcEnvelope, string?, CancellationToken, Task<IpcEnvelope>> _handler;
    private readonly Func<NamedPipeServerStream, string?>? _identifyCaller;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public AegisPipeServer(
        Func<NamedPipeServerStream> pipeFactory,
        Func<IpcEnvelope, string?, CancellationToken, Task<IpcEnvelope>> handler,
        Func<NamedPipeServerStream, string?>? identifyCaller = null)
    {
        _pipeFactory = pipeFactory;
        _handler = handler;
        _identifyCaller = identifyCaller;
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
                // Resolved once per connection, not per message - the caller's identity/role
                // can't change mid-connection, and impersonation (what a real resolver does
                // under the hood) is comparatively expensive to redo for every request.
                // null is not a safe "untrusted" sentinel here: null caller context means "no
                // identifyCaller resolver is configured at all", which Aegis.Service.IpcRequestHandler
                // treats as pre-RBAC/fully-trusted (see class doc above). If a *configured* resolver
                // throws, falling back to null would silently upgrade a failed/untrusted resolution
                // into full trust - the opposite of fail-closed. So a resolver that throws gets an
                // explicit sentinel that can never parse as a valid role instead.
                const string ResolverFailedSentinel = "Unknown";
                string? callerContext = null;
                if (_identifyCaller is not null)
                {
                    try { callerContext = _identifyCaller(pipe); }
                    catch { callerContext = ResolverFailedSentinel; }
                }

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
                        response = await _handler(request, callerContext, ct).ConfigureAwait(false);
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
