using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using Pointsman.Core.Apps;
using SharpDivert;

namespace Pointsman.Core.Redirect;

public readonly record struct FlowOwner(int ProcessId, string ExecutablePath);

/// <summary>
/// Watches WinDivert's Socket layer and remembers which process (PID + exe path) owns each local
/// port, so the packet-level redirector can decide whether a given flow should be rewritten. This
/// is the same PID-resolution approach as <see cref="Pointsman.Core.Apps.AppDiscovery"/>, just
/// keyed by socket instead of by process list.
/// </summary>
public sealed class FlowTracker : IDisposable
{
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;

    // Only the PID is recorded here, never the exe path: resolving a path costs a process-handle
    // open plus a module read (milliseconds), and doing that inside the socket-event loop meant the
    // app's SYN packet had already raced past the redirector before the port was registered — which
    // left flows half-redirected (SYN direct, rest to the proxy) and the proxy answering with RST.
    // The path is resolved on demand instead, on the packet path where blocking is safe because the
    // packet is being held anyway, and cached per PID so it's paid at most once per process.
    private readonly ConcurrentDictionary<(byte Protocol, ushort Port), int> _ownerPids = new();
    private readonly ConcurrentDictionary<int, string> _pathByPid = new();
    private readonly WinDivert _handle;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _captureLoop;

    public int SelfProcessId { get; } = Environment.ProcessId;

    public FlowTracker()
    {
        // BIND matters as much as CONNECT here: a UDP socket sending with sendto() — which is how
        // DNS resolvers and QUIC stacks usually work — never raises CONNECT, so binding is the only
        // point at which its local port becomes attributable to a process.
        //
        // CLOSE is tracked so a port's owner record is evicted as soon as that process is done with
        // it. Otherwise a stale entry can attribute a later, unrelated flow that happens to reuse
        // the same ephemeral port to the wrong process — which showed up as our own proxy's
        // outbound connections being redirected back into themselves.
        _handle = new WinDivert("event == CONNECT or event == BIND or event == CLOSE",
            WinDivert.Layer.Socket, 0, WinDivert.Flag.Sniff | WinDivert.Flag.RecvOnly);
        _captureLoop = Task.Run(CaptureLoop);
    }

    public bool TryGetOwner(byte protocol, ushort localPort, out FlowOwner owner)
    {
        owner = default;

        if (!_ownerPids.TryGetValue((protocol, localPort), out var pid))
        {
            // Socket events arrive on their own thread, and a new connection's first packet can
            // beat the event that says who owns it. Losing that race used to mean the flow was
            // left alone and stayed on the default route for good — a ruled app's traffic leaking
            // out silently, and often enough to matter: a blocked app set to a blocked adapter
            // would still come alive after enough retries, because eventually one attempt slipped
            // past. Windows' connection table knows the owner from the moment the socket connects,
            // so ask it rather than give up.
            if (!ProcessNetworkTable.TryGetOwningPid(protocol, localPort, out pid))
                return false;

            _ownerPids[(protocol, localPort)] = pid;
        }

        if (!_pathByPid.TryGetValue(pid, out var exePath))
        {
            var resolved = ResolveExecutablePath(pid);
            if (resolved is null)
                return false;

            exePath = resolved;
            _pathByPid[pid] = exePath;
        }

        owner = new FlowOwner(pid, exePath);
        return true;
    }

    /// <summary>
    /// Executable paths of the process's ancestors, nearest first — used so a rule set on an app
    /// also covers the helpers it spawns. Ancestors whose path can't be read are skipped rather
    /// than ending the walk, since an unreadable system process sitting in the middle of the chain
    /// shouldn't hide a legitimate parent further up.
    /// </summary>
    public IEnumerable<string> GetAncestorExecutables(int pid)
    {
        foreach (var ancestorPid in ProcessTree.GetAncestors(pid))
        {
            if (_pathByPid.TryGetValue(ancestorPid, out var cached))
            {
                yield return cached;
                continue;
            }

            var resolved = ResolveExecutablePath(ancestorPid);
            if (resolved is null)
                continue;

            _pathByPid[ancestorPid] = resolved;
            yield return resolved;
        }
    }

    private void CaptureLoop()
    {
        var recvBuf = new byte[1];
        var addrBuf = new WinDivertAddress[1];

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var (_, addrLen) = _handle.RecvEx(recvBuf, addrBuf);
                if (addrLen == 0)
                    continue;

                ref readonly var addr = ref addrBuf[0];
                var socket = addr.Socket;
                if (socket.Protocol is not (ProtocolTcp or ProtocolUdp))
                    continue;

                var key = (socket.Protocol, socket.LocalPort);

                if (addr.Event == WinDivert.Event.SocketClose)
                {
                    _ownerPids.TryRemove(key, out _);
                    continue;
                }

                // Deliberately just a dictionary write — see the field comment on why nothing
                // slower may happen here.
                _ownerPids[key] = (int)socket.ProcessId;
            }
            catch (WinDivertException)
            {
                // Handle closed (Dispose) or the driver went away — stop the loop either way.
                return;
            }
        }
    }

    // Service and protected processes refuse the access MainModule needs, and those are precisely
    // the ones worth routing — a VPN client's tunnel is opened by a SYSTEM daemon, not by its
    // window. See ProcessPathResolver for how that is worked around.
    private static string? ResolveExecutablePath(int pid) => ProcessPathResolver.TryGetPath(pid);

    public void Dispose()
    {
        _cts.Cancel();
        _handle.Dispose();
        try { _captureLoop.Wait(TimeSpan.FromSeconds(2)); } catch { /* ignore */ }
        _cts.Dispose();
    }
}
