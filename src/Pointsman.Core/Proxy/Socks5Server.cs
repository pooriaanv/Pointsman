using System.Net;
using System.Net.Sockets;
using Pointsman.Core.Redirect;

namespace Pointsman.Core.Proxy;

/// <summary>
/// SOCKS5 server (CONNECT command only, no authentication) that binds every outbound socket to
/// a specific local network adapter's IP address before connecting, forcing that adapter to be
/// used for egress. Serves two kinds of clients on the same port:
///
///  - Manually-configured SOCKS5 clients (point an app's proxy setting at 127.0.0.1:&lt;Port&gt;).
///  - Transparently redirected connections from <see cref="TransparentRedirector"/>: when the
///    incoming connection's remote port matches an entry in the shared <see cref="NatTable"/>,
///    the SOCKS5 handshake is skipped entirely and the real destination is read from the table —
///    the app never configured anything and doesn't know redirection happened.
/// </summary>
public sealed class Socks5Server : IAsyncDisposable
{
    private readonly IPAddress _bindLocalAddress;
    private readonly NatTable? _natTable;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public IPAddress AdapterAddress { get; }
    public int Port { get; private set; }

    public Socks5Server(IPAddress adapterAddress, NatTable? natTable = null, int port = 0)
    {
        AdapterAddress = adapterAddress;
        _bindLocalAddress = adapterAddress;
        _natTable = natTable;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            _ = HandleClientAsync(client, token);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        using var _ = client;
        try
        {
            client.NoDelay = true;
            var stream = client.GetStream();

            IPAddress destAddress;
            int destPort;
            bool isSocksClient;

            var remotePort = (ushort)((IPEndPoint)client.Client.RemoteEndPoint!).Port;
            DebugLog.Write($"Socks5Server({_bindLocalAddress}:{Port}) ACCEPTED conn from {client.Client.RemoteEndPoint} (remotePort={remotePort})");

            if (_natTable is not null && _natTable.TryGet(NatTable.ProtocolTcp, remotePort, out var natEntry))
            {
                // Came in via TransparentRedirector, not a manually-configured SOCKS5 client:
                // the real destination was captured off the wire before the app's SYN even
                // got here, so there's no handshake to do.
                destAddress = natEntry.OriginalDestAddress;
                destPort = natEntry.OriginalDestPort;
                isSocksClient = false;
                DebugLog.Write($"  -> redirect-mode, real dest={destAddress}:{destPort}, binding out via {_bindLocalAddress}");
            }
            else
            {
                if (!await DoHandshakeAsync(stream, token).ConfigureAwait(false))
                    return;

                var (destHost, port, addressBytes, addressType) =
                    await ReadConnectRequestAsync(stream, token).ConfigureAwait(false);
                destPort = port;
                isSocksClient = true;

                if (addressType == 3) // domain name
                {
                    var resolved = await Dns.GetHostAddressesAsync(destHost!, token).ConfigureAwait(false);
                    destAddress = resolved.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                        ?? resolved.First();
                }
                else
                {
                    destAddress = new IPAddress(addressBytes!);
                }
            }

            using var outbound = new Socket(SocketType.Stream, ProtocolType.Tcp);
            // Binding the source address to the chosen adapter's IP forces Windows to
            // route this connection out via that adapter (assuming it has a valid route
            // to the destination, which the default gateway on each adapter provides).
            outbound.Bind(new IPEndPoint(_bindLocalAddress, 0));

            try
            {
                await outbound.ConnectAsync(destAddress, destPort, token).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                DebugLog.Write($"  -> outbound.ConnectAsync to {destAddress}:{destPort} FAILED: {ex.SocketErrorCode} {ex.Message}");
                if (isSocksClient)
                    await WriteReplyAsync(stream, replyCode: 0x05, token).ConfigureAwait(false); // connection refused
                return;
            }

            if (isSocksClient)
            {
                var boundEp = (IPEndPoint)outbound.LocalEndPoint!;
                await WriteReplyAsync(stream, replyCode: 0x00, token, boundEp).ConfigureAwait(false);
            }

            DebugLog.Write($"  -> outbound connected OK to {destAddress}:{destPort} from {outbound.LocalEndPoint}, relaying...");
            using var outboundStream = new NetworkStream(outbound, ownsSocket: false);
            var toRemote = stream.CopyToAsync(outboundStream, token);
            var toClient = outboundStream.CopyToAsync(stream, token);
            await Task.WhenAny(toRemote, toClient).ConfigureAwait(false);
            DebugLog.Write($"  -> relay ended for {destAddress}:{destPort} toRemoteFaulted={toRemote.IsFaulted} toRemoteEx={toRemote.Exception?.InnerException?.Message} toClientFaulted={toClient.IsFaulted} toClientEx={toClient.Exception?.InnerException?.Message}");
        }
        catch (Exception ex)
        {
            // Best-effort proxy: swallow per-connection errors so one bad connection
            // doesn't take down the accept loop.
            DebugLog.Write($"  -> HandleClientAsync EXCEPTION: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static async Task<bool> DoHandshakeAsync(NetworkStream stream, CancellationToken token)
    {
        var header = new byte[2];
        if (!await ReadExactAsync(stream, header, token).ConfigureAwait(false))
            return false;

        if (header[0] != 0x05) // SOCKS version 5
            return false;

        var methodCount = header[1];
        var methods = new byte[methodCount];
        if (!await ReadExactAsync(stream, methods, token).ConfigureAwait(false))
            return false;

        // No-auth only.
        await stream.WriteAsync(new byte[] { 0x05, 0x00 }, token).ConfigureAwait(false);
        return true;
    }

    private static async Task<(string? host, int port, byte[]? address, byte addressType)> ReadConnectRequestAsync(
        NetworkStream stream, CancellationToken token)
    {
        var head = new byte[4];
        await ReadExactAsync(stream, head, token).ConfigureAwait(false);
        // head[0]=ver, head[1]=cmd (0x01=CONNECT), head[2]=rsv, head[3]=addrType
        var addressType = head[3];

        string? host = null;
        byte[]? address = null;

        switch (addressType)
        {
            case 0x01: // IPv4
                address = new byte[4];
                await ReadExactAsync(stream, address, token).ConfigureAwait(false);
                break;
            case 0x03: // domain
                var lenBuf = new byte[1];
                await ReadExactAsync(stream, lenBuf, token).ConfigureAwait(false);
                var domainBuf = new byte[lenBuf[0]];
                await ReadExactAsync(stream, domainBuf, token).ConfigureAwait(false);
                host = System.Text.Encoding.ASCII.GetString(domainBuf);
                break;
            case 0x04: // IPv6
                address = new byte[16];
                await ReadExactAsync(stream, address, token).ConfigureAwait(false);
                break;
        }

        var portBuf = new byte[2];
        await ReadExactAsync(stream, portBuf, token).ConfigureAwait(false);
        var port = (portBuf[0] << 8) | portBuf[1];

        return (host, port, address, addressType);
    }

    private static async Task WriteReplyAsync(
        NetworkStream stream, byte replyCode, CancellationToken token, IPEndPoint? bound = null)
    {
        bound ??= new IPEndPoint(IPAddress.Any, 0);
        var addrBytes = bound.Address.GetAddressBytes();
        var reply = new byte[6 + addrBytes.Length];
        reply[0] = 0x05;
        reply[1] = replyCode;
        reply[2] = 0x00;
        reply[3] = bound.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
        Array.Copy(addrBytes, 0, reply, 4, addrBytes.Length);
        reply[^2] = (byte)(bound.Port >> 8);
        reply[^1] = (byte)(bound.Port & 0xFF);
        await stream.WriteAsync(reply, token).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken token)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), token).ConfigureAwait(false);
            if (n == 0)
                return false;
            read += n;
        }
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); }
            catch { /* ignore */ }
        }
        _cts.Dispose();
    }
}
