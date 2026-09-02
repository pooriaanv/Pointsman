using System.Runtime.InteropServices;

namespace Pointsman.Core.Apps;

/// <summary>
/// Lists the PIDs that currently own TCP connections, via the same table Windows' own netstat
/// reads. This is how the app list finds the processes that actually matter for routing:
/// filtering by "has a visible window" misses exactly the wrong ones — Steam's downloader,
/// updaters, sync clients and other background workers do the networking while a separate
/// windowed process shows the UI.
/// </summary>
public static class ProcessNetworkTable
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;

    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    public static HashSet<int> GetPidsWithConnections()
    {
        var pids = new HashSet<int>();
        var size = 0;

        var result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        if (result != ErrorInsufficientBuffer && result != 0)
            return pids;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0)
                return pids;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var cursor = buffer + sizeof(int);

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(cursor);
                pids.Add((int)row.OwningPid);
                cursor += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return pids;
    }

    /// <summary>
    /// Finds the process owning a local port, straight from Windows' connection table.
    ///
    /// This is the authority the redirector falls back to. Socket-layer events normally say who
    /// owns a port, but they arrive on their own thread and a brand new connection's first packet
    /// can reach the redirector before that event has been recorded. A flow whose owner isn't
    /// known is left alone rather than half-redirected, so losing that race means the flow quietly
    /// stays on the default route — a ruled app's traffic escaping without a trace. Asking the
    /// table closes the race, because the entry exists from the moment the socket connects.
    /// </summary>
    public static bool TryGetOwningPid(byte protocol, ushort localPort, out int pid)
    {
        pid = 0;

        var tableClass = protocol switch
        {
            ProtocolTcp => TcpTableOwnerPidAll,
            ProtocolUdp => UdpTableOwnerPid,
            _ => -1,
        };

        if (tableClass < 0)
            return false;

        var size = 0;
        var probe = protocol == ProtocolTcp
            ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, tableClass, 0)
            : GetExtendedUdpTable(IntPtr.Zero, ref size, false, AfInet, tableClass, 0);

        if (probe != ErrorInsufficientBuffer && probe != 0)
            return false;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = protocol == ProtocolTcp
                ? GetExtendedTcpTable(buffer, ref size, false, AfInet, tableClass, 0)
                : GetExtendedUdpTable(buffer, ref size, false, AfInet, tableClass, 0);

            if (result != 0)
                return false;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = protocol == ProtocolTcp
                ? Marshal.SizeOf<MibTcpRowOwnerPid>()
                : Marshal.SizeOf<MibUdpRowOwnerPid>();
            var cursor = buffer + sizeof(int);

            for (var i = 0; i < count; i++)
            {
                uint rawPort, owningPid;
                if (protocol == ProtocolTcp)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(cursor);
                    rawPort = row.LocalPort;
                    owningPid = row.OwningPid;
                }
                else
                {
                    var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(cursor);
                    rawPort = row.LocalPort;
                    owningPid = row.OwningPid;
                }

                if (ToHostPort(rawPort) == localPort)
                {
                    pid = (int)owningPid;
                    return true;
                }

                cursor += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return false;
    }

    /// <summary>The table stores the port in network byte order inside the low half of a DWORD.</summary>
    private static ushort ToHostPort(uint raw) => (ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
}
