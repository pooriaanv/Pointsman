using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Pointsman.Core.Redirect;

namespace Pointsman.Core.Proxy;

/// <summary>
/// The UDP counterpart to <see cref="Socks5Server"/>: receives datagrams that
/// <see cref="TransparentRedirector"/> rewrote onto loopback, and re-sends them from a socket bound
/// to one adapter's IP so they leave by that adapter.
///
/// UDP needs more bookkeeping than TCP. There, the OS owns both halves of the connection and the
/// proxy just relays bytes; here there is no connection to hang state off, so this keeps one
/// outbound socket per app-side port and remembers where each came from, in order to route replies
/// back to the right app. Idle flows are reaped, since UDP gives no close to observe.
/// </summary>
public sealed class UdpRelay : IAsyncDisposable
{
    private static readonly TimeSpan FlowIdleTimeout = TimeSpan.FromMinutes(2);

    private sealed class Flow(UdpClient socket, ushort appPort)
    {
        public UdpClient Socket { get; } = socket;
        public ushort AppPort { get; } = appPort;
        public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;
    }

    private readonly IPAddress _bindLocalAddress;
    private readonly NatTable _natTable;
    private readonly ConcurrentDictionary<ushort, Flow> _flowsByAppPort = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly UdpClient _loopbackSocket;
    private readonly Timer _reaper;
    private Task? _receiveLoop;

    public IPAddress AdapterAddress { get; }
    public int Port { get; private set; }

    public UdpRelay(IPAddress adapterAddress, NatTable natTable)
    {
        AdapterAddress = adapterAddress;
        _bindLocalAddress = adapterAddress;
        _natTable = natTable;
        _loopbackSocket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        _reaper = new Timer(_ => ReapIdleFlows(), null, FlowIdleTimeout, FlowIdleTimeout);
    }

    public void Start()
    {
        Port = ((IPEndPoint)_loopbackSocket.Client.LocalEndPoint!).Port;
        _receiveLoop = Task.Run(() => ReceiveFromAppsAsync(_cts.Token));
    }

    /// <summary>Datagrams arriving here were sent by an app and steered onto loopback by the redirector.</summary>
    private async Task ReceiveFromAppsAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await _loopbackSocket.ReceiveAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            var appPort = (ushort)received.RemoteEndPoint.Port;
            DebugLog.Write($"UdpRelay({_bindLocalAddress}:{Port}) got {received.Buffer.Length}B from app port {appPort}");

            if (!_natTable.TryGet(NatTable.ProtocolUdp, appPort, out var nat))
            {
                DebugLog.Write($"  -> no NAT entry for app port {appPort}, dropping");
                continue; // no record of where this was originally headed — nothing sensible to do
            }

            _natTable.Touch(NatTable.ProtocolUdp, appPort);

            try
            {
                var flow = _flowsByAppPort.GetOrAdd(appPort, CreateFlow);
                flow.LastUsedUtc = DateTime.UtcNow;
                await flow.Socket
                    .SendAsync(received.Buffer, new IPEndPoint(nat.OriginalDestAddress, nat.OriginalDestPort), token)
                    .ConfigureAwait(false);
                DebugLog.Write($"  -> sent to {nat.OriginalDestAddress}:{nat.OriginalDestPort} from {flow.Socket.Client.LocalEndPoint}");
            }
            catch (OperationCanceledException) { return; }
            catch (SocketException ex) { DebugLog.Write($"  -> send FAILED: {ex.SocketErrorCode} {ex.Message}"); }
            catch (ObjectDisposedException) { /* flow reaped mid-send */ }
        }
    }

    private Flow CreateFlow(ushort appPort)
    {
        // Binding to the adapter's IP is the entire point: it is what makes Windows send this
        // datagram out of that adapter rather than down the default route.
        var socket = new UdpClient(new IPEndPoint(_bindLocalAddress, 0));
        var flow = new Flow(socket, appPort);
        _ = Task.Run(() => ReceiveRepliesAsync(flow, _cts.Token));
        return flow;
    }

    /// <summary>Replies from the real server, sent back to the app over loopback.</summary>
    private async Task ReceiveRepliesAsync(Flow flow, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult reply;
            try
            {
                reply = await flow.Socket.ReceiveAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            flow.LastUsedUtc = DateTime.UtcNow;
            _natTable.Touch(NatTable.ProtocolUdp, flow.AppPort);
            DebugLog.Write($"UdpRelay reply {reply.Buffer.Length}B from {reply.RemoteEndPoint} -> back to app port {flow.AppPort}");

            try
            {
                // Goes back over loopback; the redirector rewrites the source so the app sees a
                // reply from the server it actually addressed.
                await _loopbackSocket
                    .SendAsync(reply.Buffer, new IPEndPoint(IPAddress.Loopback, flow.AppPort), token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (SocketException ex) { DebugLog.Write($"  -> reply send FAILED: {ex.SocketErrorCode}"); }
            catch (ObjectDisposedException) { return; }
        }
    }

    private void ReapIdleFlows()
    {
        var cutoff = DateTime.UtcNow - FlowIdleTimeout;
        foreach (var (appPort, flow) in _flowsByAppPort)
        {
            if (flow.LastUsedUtc >= cutoff)
                continue;

            if (_flowsByAppPort.TryRemove(appPort, out var removed))
                removed.Socket.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _reaper.Dispose();
        _loopbackSocket.Dispose();

        foreach (var (_, flow) in _flowsByAppPort)
            flow.Socket.Dispose();
        _flowsByAppPort.Clear();

        if (_receiveLoop is not null)
        {
            try { await _receiveLoop.ConfigureAwait(false); }
            catch { /* ignore */ }
        }

        _cts.Dispose();
    }
}
