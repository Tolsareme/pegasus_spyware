using System.Net;
using System.Runtime.InteropServices;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Polls the IPv4 TCP connection table via the IP Helper API (<c>GetExtendedTcpTable</c>,
/// stable since Windows XP SP2 / Server 2003) and diffs against the previous snapshot to
/// emit one <see cref="ActionType.NetworkConnect"/> event per newly observed remote
/// endpoint per process (doc §5 "Network" telemetry row). Polling instead of a kernel
/// callback keeps this collector dependency-free and safe on the oldest supported OS;
/// ETW's network provider is the natural higher-fidelity upgrade path (doc §19).
/// </summary>
public sealed class NetworkConnectionCollector : ITelemetryCollector, IDisposable
{
    public string Name => "NetworkConnection";

    private readonly string _hostId;
    private readonly string _hostRole;
    private readonly TimeSpan _pollInterval;
    private Timer? _timer;
    private readonly HashSet<(int Pid, string RemoteEndpoint)> _known = new();
    private readonly object _lock = new();
    private volatile bool _running;

    public NetworkConnectionCollector(string hostId, string hostRole, TimeSpan? pollInterval = null)
    {
        _hostId = hostId;
        _hostRole = hostRole;
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(5);
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        _running = true;
        _timer = new Timer(_ => Poll(onEvent, logger), null, TimeSpan.Zero, _pollInterval);
    }

    private void Poll(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        if (!_running) return;

        List<TcpConnectionInfo> connections;
        try
        {
            connections = TcpTable.GetEstablishedIPv4Connections();
        }
        catch (Exception ex)
        {
            logger.Error(Name, "Failed to read the TCP connection table.", ex);
            return;
        }

        lock (_lock)
        {
            var currentKeys = new HashSet<(int, string)>();
            foreach (var conn in connections)
            {
                // Loopback and link-local noise isn't useful for lateral-movement/C2 detection.
                if (IPAddress.IsLoopback(conn.RemoteAddress)) continue;

                var remoteEndpoint = $"{conn.RemoteAddress}:{conn.RemotePort}";
                var key = (conn.Pid, remoteEndpoint);
                currentKeys.Add(key);

                if (_known.Add(key))
                {
                    onEvent(new NormalizedEvent
                    {
                        EventId = Guid.NewGuid(),
                        Timestamp = DateTimeOffset.UtcNow,
                        HostId = _hostId,
                        HostRole = _hostRole,
                        ProcessId = conn.Pid,
                        ActionType = ActionType.NetworkConnect,
                        ObjectType = ObjectType.NetworkDestination,
                        DestinationIp = conn.RemoteAddress.ToString(),
                        DestinationPort = conn.RemotePort,
                        Result = ActionResult.Success,
                        RawEventReference = $"TcpTable:{conn.Pid}:{remoteEndpoint}",
                    });
                }
            }

            // Forget connections that have closed so a future reconnect to the same endpoint is reported again.
            _known.RemoveWhere(k => !currentKeys.Contains(k));
        }
    }

    public void Stop()
    {
        _running = false;
        _timer?.Change(Timeout.Infinite, Timeout.Infinite);
    }

    public void Dispose()
    {
        Stop();
        _timer?.Dispose();
    }

    private readonly struct TcpConnectionInfo
    {
        public readonly int Pid;
        public readonly IPAddress RemoteAddress;
        public readonly int RemotePort;

        public TcpConnectionInfo(int pid, IPAddress remoteAddress, int remotePort)
        {
            Pid = pid;
            RemoteAddress = remoteAddress;
            RemotePort = remotePort;
        }
    }

    /// <summary>Thin wrapper around GetExtendedTcpTable (iphlpapi.dll) - P/Invoke details isolated here so the collector above reads as plain business logic.</summary>
    private static class TcpTable
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int size, bool sort, int ipVersion, int tableClass, int reserved);

        private const int AfInet = 2;
        private const int TcpTableOwnerPidAll = 5;

        // Row layout for TCP_TABLE_OWNER_PID_ALL (MIB_TCPROW_OWNER_PID): DWORD state, DWORD
        // localAddr, DWORD localPort, DWORD remoteAddr, DWORD remotePort, DWORD pid - read by
        // fixed byte offset below rather than a marshaled struct, since the port fields are
        // big-endian-in-a-DWORD and easier to reason about as raw offsets than as a struct.
        public static List<TcpConnectionInfo> GetEstablishedIPv4Connections()
        {
            var results = new List<TcpConnectionInfo>();
            var size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
            if (size <= 0) return results;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var ret = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
                if (ret != 0) return results; // non-zero = Win32 error; fail soft, next poll tries again

                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, 4);
                // Each row is: DWORD state, DWORD localAddr, DWORD localPort, DWORD remoteAddr, DWORD remotePort, DWORD pid = 24 bytes.
                const int rowSize = 24;

                for (var i = 0; i < rowCount; i++)
                {
                    var current = IntPtr.Add(rowPtr, i * rowSize);
                    var state = (uint)Marshal.ReadInt32(current, 0);
                    var remoteAddr = (uint)Marshal.ReadInt32(current, 12);
                    var remotePortRaw = (uint)Marshal.ReadInt32(current, 16);
                    var pid = Marshal.ReadInt32(current, 20);

                    const uint mibTcpStateEstab = 5;
                    if (state != mibTcpStateEstab) continue;

                    var remotePort = (int)(((remotePortRaw & 0xFF) << 8) | ((remotePortRaw >> 8) & 0xFF));
                    var remoteIp = new IPAddress((long)remoteAddr);

                    results.Add(new TcpConnectionInfo(pid, remoteIp, remotePort));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }
    }
}
