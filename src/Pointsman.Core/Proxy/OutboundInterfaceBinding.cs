using System.Net;
using System.Net.Sockets;

namespace Pointsman.Core.Proxy;

/// <summary>Bind an IPv4 socket to a specific Windows network interface.</summary>
internal static class OutboundInterfaceBinding
{
    // IP_UNICAST_IF from the Windows SDK (ws2ipdef.h). .NET's SocketOptionName enum does
    // not define a named member for this Windows-specific socket option.
    private const SocketOptionName IpUnicastInterface = (SocketOptionName)31;

    public static void Configure(Socket socket, IPAddress source, int interfaceIndex)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (source.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 outbound routing is supported", nameof(source));
        if (interfaceIndex <= 0)
            throw new ArgumentOutOfRangeException(nameof(interfaceIndex));

        socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface,
            IPAddress.HostToNetworkOrder(interfaceIndex));
        socket.Bind(new IPEndPoint(source, 0));
    }
}
