using System.IO;
using System.Net;
using Pointsman.Core.Models;
using Pointsman.Core.Diagnostics;
using Pointsman.Core.Policies;
using Pointsman.Core.Proxy;
using Pointsman.Core.Rules;
using SharpDivert;

namespace Pointsman.Core.Redirect;

/// <summary>
/// The core of transparent per-app redirection: captures outbound TCP packets at the WinDivert
/// Network layer and, for flows owned by a process that has an adapter rule, rewrites the
/// destination to the matching local <see cref="Socks5Server"/> port before reinjecting —
/// then rewrites the proxy's replies back to look like they came from the real destination,
/// so the app never sees anything other than a normal connection to the server it asked for.
///
/// This only touches flows it recognizes; everything else passes through byte-for-byte.
///
/// The caller selects a capture filter. Exact-IP rules can be limited to those destinations
/// and the known proxy reply ports. Per-application rules still need non-loopback outbound
/// traffic because the NETWORK layer does not expose PIDs. Inbound internet replies are not
/// intercepted; the local relay's outgoing loopback replies are selectively captured.
/// A single receive loop preserves the SYN-before-payload ordering used by the NAT table.
/// </summary>
public sealed class TransparentRedirector : IDisposable
{
    private const byte ProtocolTcp = NatTable.ProtocolTcp;
    private const byte ProtocolUdp = NatTable.ProtocolUdp;
    private static readonly TimeSpan ProxyPortCacheInterval = TimeSpan.FromSeconds(2);

    private readonly FlowTracker _flowTracker;
    private readonly NatTable _natTable;
    private readonly RuleStore _ruleStore;
    private readonly PolicyEngine _policyEngine;
    private readonly DomainAddressIndex _domainIndex;
    private readonly ProxyManager _proxyManager;
    private readonly HashSet<string> _excludedExecutableNames;

    private readonly WinDivert _handle;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task[] _loops;
    private readonly Timer _proxyPortCacheTimer;
    private int _fatalErrorReported;

    /// <summary>
    /// Raised once if packet interception cannot continue safely. When the WinDivert handle
    /// is closed, Windows resumes normal routing; destination policies are no longer enforced.
    /// The UI must warn the user instead of silently claiming a policy is still active.
    /// </summary>
    public event EventHandler<Exception>? Faulted;

    // Refreshed periodically instead of on every packet — the ProxyManager lookups take a lock
    // and allocate, which is too expensive to do per-packet, and the ports only change when an
    // adapter connects/disconnects.
    private volatile HashSet<int> _proxyPortsCache = [];
    private volatile HashSet<int> _udpRelayPortsCache = [];

    /// <param name="excludedExecutableNames">
    /// Bare file names (e.g. "openvpn.exe"), not full paths — matched against the owning
    /// process's file name regardless of install location.
    /// </param>
    public TransparentRedirector(
        FlowTracker flowTracker,
        NatTable natTable,
        RuleStore ruleStore,
        PolicyEngine policyEngine,
        DomainAddressIndex domainIndex,
        ProxyManager proxyManager,
        IEnumerable<string> excludedExecutableNames,
        string captureFilter)
    {
        _flowTracker = flowTracker;
        _natTable = natTable;
        _ruleStore = ruleStore;
        _policyEngine = policyEngine;
        _domainIndex = domainIndex;
        _proxyManager = proxyManager;
        _excludedExecutableNames = new HashSet<string>(excludedExecutableNames, StringComparer.OrdinalIgnoreCase);

        ArgumentException.ThrowIfNullOrWhiteSpace(captureFilter);
        // Prepare managed state BEFORE opening a handle that can capture real traffic.
        RefreshProxyPortsCache();
        _handle = new WinDivert(captureFilter, WinDivert.Layer.Network, 0, 0);
        Timer? timer = null;
        try
        {
            _handle.QueueLength = WinDivert.QueueLengthMax;
            _handle.QueueTime = WinDivert.QueueTimeMax;
            _handle.QueueSize = WinDivert.QueueSizeMax;
            timer = new Timer(_ => RefreshProxyPortsCache(), null,
                ProxyPortCacheInterval, ProxyPortCacheInterval);
            _proxyPortCacheTimer = timer;
            _proxyManager.PortsChanged += OnProxyPortsChanged;

            // One receive loop maintains SYN / NAT ordering. If any of the setup
            // steps fail, the catch block immediately releases the capture handle.
            _loops = [Task.Run(RunLoop)];
            DiagnosticsLog.Write($"Packet interception started: {captureFilter}");
        }
        catch
        {
            _proxyManager.PortsChanged -= OnProxyPortsChanged;
            timer?.Dispose();
            _handle.Dispose(); // Never leave an undrained system-wide capture open.
            _cts.Dispose();
            throw;
        }
    }

    private void OnProxyPortsChanged(object? sender, EventArgs e) => RefreshProxyPortsCache();

    private void RefreshProxyPortsCache()
    {
        try
        {
            _proxyPortsCache = new HashSet<int>(_proxyManager.GetAllPorts().Values);
            _udpRelayPortsCache = new HashSet<int>(_proxyManager.GetAllUdpPorts());
        }
        catch (Exception ex)
        {
            // Timer callbacks run on ThreadPool. Exceptions must not terminate the
            // entire Windows process (which could leave driver state unclear).
            DiagnosticsLog.Error("Refresh local proxy port cache", ex);
        }
    }

    private void RunLoop()
    {
        var recvBuf = new byte[WinDivert.MTUMax];
        var addrBuf = new WinDivertAddress[1];

        while (!_cts.IsCancellationRequested)
        {
            uint recvLen, addrLen;
            try
            {
                (recvLen, addrLen) = _handle.RecvEx(recvBuf, addrBuf);
            }
            catch (WinDivertException ex)
            {
                if (!_cts.IsCancellationRequested) StopOnFatalError(ex);
                return; // handle closed or driver stopped
            }
            catch (Exception ex)
            {
                StopOnFatalError(ex);
                return;
            }

            if (addrLen == 0)
                continue;

            var packet = recvBuf.AsMemory(0, (int)recvLen);
            ref var addr = ref addrBuf[0];

            // TryProcessPacket mutates the packet in place through pointers pinned into this
            // same Memory<byte> — it must NOT be given a copy, or the rewrite would be lost.
            PacketAction action;
            string? debugTag;
            try
            {
                action = TryProcessPacket(packet, ref addr, out debugTag);
            }
            catch (Exception ex)
            {
                // If a parser/route decision faults, do not leave an active WinDivert handle
                // intercepting the entire machine with no receive loop to drain it.
                StopOnFatalError(ex);
                return;
            }

            if (action == PacketAction.Drop)
            {
                // Not reinjecting is what drops it: the handle isn't in sniff mode, so a packet
                // we don't send back never reaches the network.
                if (debugTag is not null)
                    DebugLog.Write($"DROP {debugTag}");
                continue;
            }

            try
            {
                if (action == PacketAction.Rewrite)
                {
                    // These flags mean "the checksum already in the packet is valid". A packet
                    // captured outbound on a real NIC often has them set because the NIC will
                    // compute the checksum via hardware offload — but a loopback packet has no
                    // NIC to do that, so it must carry a genuinely correct checksum. Clearing
                    // the flags first forces CalcChecksums to actually compute them; leaving
                    // them set makes Windows silently drop the reinjected packet (SendEx still
                    // reports success, which is what made this so hard to see).
                    addr.IPChecksum = false;
                    addr.TCPChecksum = false;
                    addr.UDPChecksum = false;
                    WinDivert.CalcChecksums(packet.Span, ref addr, 0);
                }
                _handle.SendEx(packet.Span, addrBuf.AsSpan(0, (int)addrLen));
                if (debugTag is not null)
                    DebugLog.Write($"SendEx OK  {debugTag} loopback={addr.Loopback} ifIdx={addr.Network.IfIdx} subIfIdx={addr.Network.SubIfIdx} impostor={addr.Impostor} ipCk={addr.IPChecksum} tcpCk={addr.TCPChecksum} udpCk={addr.UDPChecksum}");
            }
            catch (WinDivertException ex)
            {
                if (debugTag is not null)
                    DebugLog.Write($"SendEx FAIL {debugTag}: {ex.Message}");
                // Do not keep a system-wide packet capture open after reinjection fails.
                // Even one failure can affect connectivity, especially during VPN changes.
                StopOnFatalError(new IOException("WinDivert packet reinjection failed", ex));
                return;
            }
            catch (Exception ex)
            {
                StopOnFatalError(ex);
                return;
            }
        }
    }

    private void StopOnFatalError(Exception error)
    {
        if (Interlocked.Exchange(ref _fatalErrorReported, 1) != 0) return;
        DiagnosticsLog.Error("WinDivert packet interception failure", error);
        // A dead receive loop holding an interception handle can stall *all* TCP/UDP.
        // Closing the handle restores OS networking, but it does not enforce routing
        // policies. This is a fail-OPEN emergency recovery and must be visible to users.
        try { _handle.Dispose(); } catch (Exception ex) { DiagnosticsLog.Error("Close WinDivert", ex); }
        try { Faulted?.Invoke(this, error); }
        catch (Exception ex) { DiagnosticsLog.Error("Notify WinDivert failure", ex); }
    }

    private enum PacketAction
    {
        /// <summary>Reinject untouched.</summary>
        Forward,
        /// <summary>Reinject after the in-place rewrite (checksums are recalculated first).</summary>
        Rewrite,
        /// <summary>Don't reinject at all.</summary>
        Drop,
    }

    /// <summary>
    /// Decides what to do with one packet, rewriting it in place where needed (through pointers
    /// pinned into <paramref name="packet"/>'s own backing array — <paramref name="packet"/> must
    /// be the actual receive buffer, not a copy, or the rewrite would be silently lost).
    /// </summary>
    private unsafe PacketAction TryProcessPacket(Memory<byte> packet, ref WinDivertAddress addr, out string? debugTag)
    {
        debugTag = null;
        // The enumerator pins packet's backing array for as long as it's alive; it must stay
        // alive for the entire method (not just parsing) since ipv4Hdr/tcpHdr are raw pointers
        // into that pinned memory — disposing early would let the GC move/collect it under us.
        using var enumerator = new WinDivertPacketParser(packet).GetEnumerator();
        if (!enumerator.MoveNext())
            return PacketAction.Forward;

        var ipv4Hdr = enumerator.Current.IPv4Hdr;
        var tcpHdr = enumerator.Current.TCPHdr;
        var udpHdr = enumerator.Current.UDPHdr;

        if (ipv4Hdr == null)
            return ClassifyIPv6(packet, enumerator.Current.IPv6Hdr, tcpHdr, udpHdr, out debugTag);

        if (udpHdr != null)
            return TryProcessUdp(ipv4Hdr, udpHdr, ref addr, out debugTag);

        if (tcpHdr == null)
            return PacketAction.Forward; // ICMP and friends

        var srcAddr = IPAddress.Parse(((IPv4Addr)ipv4Hdr->SrcAddr).ToString());
        var dstAddr = IPAddress.Parse(((IPv4Addr)ipv4Hdr->DstAddr).ToString());
        var srcPort = (ushort)tcpHdr->SrcPort;
        var dstPort = (ushort)tcpHdr->DstPort;

        // TCP flags live at byte 13 of the TCP header, which starts right after the IPv4
        // header (whose length is the low nibble of byte 0, in 32-bit words).
        var packetSpan = packet.Span;
        if (packetSpan.Length < 20) return PacketAction.Forward;
        var tcpOffset = (packetSpan[0] & 0x0F) * 4;
        if (tcpOffset < 20 || tcpOffset + 14 > packetSpan.Length)
            return PacketAction.Forward;
        var tcpFlags = packetSpan[tcpOffset + 13];
        var isSyn = (tcpFlags & 0x02) != 0 && (tcpFlags & 0x10) == 0;

        if (TraceFlowPort != 0 && (srcPort == TraceFlowPort || dstPort == TraceFlowPort))
        {
            DebugLog.Write($"  PKT {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} len={packet.Length} flags={DescribeTcpFlags(tcpFlags)} loopback={addr.Loopback} ifIdx={addr.Network.IfIdx} impostor={addr.Impostor}");
        }

        // Case B: this is our own proxy replying to an app on a flow we already redirected —
        // restore both addresses so it looks like a normal reply from the real destination,
        // arriving at the app's real local address (not 127.0.0.1, which is what Case A rewrote
        // the app's own SYN to use so Windows would actually deliver it — see Case A's comment).
        if (IPAddress.IsLoopback(srcAddr) && IsKnownProxyPort(srcPort) && _natTable.TryGet(ProtocolTcp, dstPort, out var natEntry))
        {
            DebugLog.Write($"CaseB before: {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} loopback={addr.Loopback} ifIdx={addr.Network.IfIdx}/{addr.Network.SubIfIdx} => rewriting to {natEntry.OriginalDestAddress}:{natEntry.OriginalDestPort} -> {natEntry.OriginalSrcAddress}:{dstPort}");
            ipv4Hdr->SrcAddr = ToIPv4Addr(natEntry.OriginalDestAddress);
            ipv4Hdr->DstAddr = ToIPv4Addr(natEntry.OriginalSrcAddress);
            tcpHdr->SrcPort = natEntry.OriginalDestPort;
            _natTable.Touch(ProtocolTcp, dstPort);
            debugTag = "CaseB";
            return PacketAction.Rewrite;
        }

        // Case A: traffic from an app heading out to a real remote address. The redirect decision
        // is made once, on the SYN, and then replayed from the NAT table for the rest of the flow.
        // It must never be re-evaluated per packet: if the owning process isn't known yet when the
        // SYN goes past, re-deciding later would redirect the middle of a connection whose SYN went
        // out directly, and the proxy — which never saw that connection open — answers RST.
        if (IPAddress.IsLoopback(dstAddr))
            return PacketAction.Forward;

        if (_natTable.TryGet(ProtocolTcp, srcPort, out var tracked)
            && tracked.OriginalDestPort == dstPort
            && tracked.OriginalDestAddress.Equals(dstAddr))
        {
            _natTable.Touch(ProtocolTcp, srcPort);
            RewriteToProxy(ipv4Hdr, tcpHdr, ref addr, tracked.ProxyPort);
            debugTag = "CaseA-established";
            return PacketAction.Rewrite;
        }

        if (dstPort == 0)
            return PacketAction.Forward;

        if (!isSyn)
        {
            // Only flows whose SYN was redirected have a NAT record. A flow whose
            // SYN was allowed through (or beat socket owner discovery) is NOT proof
            // of an attempted route. Dropping its later packets based on a rule
            // evaluated after the fact breaks unrelated, already-established TCP.
            return PacketAction.Forward;
        }

        if (!_flowTracker.TryGetOwner(ProtocolTcp, srcPort, out var owner)
            || owner.ProcessId == _flowTracker.SelfProcessId
            || _excludedExecutableNames.Contains(Path.GetFileName(owner.ExecutablePath)))
            return PacketAction.Forward;

        var decision = ResolveRoute(owner, dstAddr, dstPort, ProtocolTcp);
        if (decision.Kind == RouteDecisionKind.Block)
        {
            debugTag = $"TCP blocked by {(decision.PolicyId?.ToString() ?? "legacy adapter rule")} to {dstAddr}:{dstPort}";
            return PacketAction.Drop;
        }
        if (decision.Kind != RouteDecisionKind.Route)
            return PacketAction.Forward;

        if (_proxyManager.GetPortForAdapter(decision.AdapterId!) is not int proxyPort)
        {
            debugTag = $"TCP route to {decision.AdapterId} unavailable, fail-closed";
            return PacketAction.Drop;
        }

        TraceFlowPort = srcPort;
        DebugLog.Write($"CaseA SYN: {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} owner={Path.GetFileName(owner.ExecutablePath)} => redirecting flow to 127.0.0.1:{proxyPort}");
        _natTable.Track(ProtocolTcp, srcPort, dstAddr, dstPort, srcAddr, (ushort)proxyPort);
        RewriteToProxy(ipv4Hdr, tcpHdr, ref addr, (ushort)proxyPort);
        debugTag = "CaseA-syn";
        return PacketAction.Rewrite;
    }

    /// <summary>
    /// IPv6 isn't redirected. Rather than let that silently become an escape hatch — where a rule
    /// looks applied but the app quietly reaches the internet over IPv6 through the default route —
    /// IPv6 traffic belonging to an app that has a rule is dropped, so it falls back to IPv4, which
    /// this engine does control. Apps without a rule are never touched.
    ///
    /// Only globally-routable destinations are dropped. Loopback, link-local and unique-local
    /// addresses carry local IPC and LAN discovery that has nothing to do with which adapter
    /// reaches the internet, and breaking those would break apps for no benefit.
    /// </summary>
    private unsafe PacketAction ClassifyIPv6(
        Memory<byte> packet, WinDivertIPv6Hdr* ipv6Hdr, WinDivertTCPHdr* tcpHdr, WinDivertUDPHdr* udpHdr, out string? debugTag)
    {
        debugTag = null;

        if (ipv6Hdr == null)
            return PacketAction.Forward;

        byte protocol;
        ushort srcPort;
        ushort dstPort;
        if (tcpHdr != null) { protocol = ProtocolTcp; srcPort = tcpHdr->SrcPort; dstPort = tcpHdr->DstPort; }
        else if (udpHdr != null) { protocol = ProtocolUdp; srcPort = udpHdr->SrcPort; dstPort = udpHdr->DstPort; }
        else return PacketAction.Forward;

        // The destination sits at a fixed offset in the 40-byte IPv6 header.
        var span = packet.Span;
        if (span.Length < 40)
            return PacketAction.Forward;

        var destination = new IPAddress(span.Slice(24, 16).ToArray());
        if (IPAddress.IsLoopback(destination)
            || destination.IsIPv6LinkLocal
            || destination.IsIPv6SiteLocal
            || destination.IsIPv6Multicast
            || IsUniqueLocal(destination))
            return PacketAction.Forward;

        if (!_flowTracker.TryGetOwner(protocol, srcPort, out var owner)
            || owner.ProcessId == _flowTracker.SelfProcessId
            || _excludedExecutableNames.Contains(Path.GetFileName(owner.ExecutablePath)))
            return PacketAction.Forward;

        if (dstPort == 0)
            return PacketAction.Forward;

        var decision = ResolveRoute(owner, destination, dstPort, protocol);
        if (decision.Kind is RouteDecisionKind.Unmatched or RouteDecisionKind.Direct)
            return PacketAction.Forward;

        // The IPv4-only transparent relay cannot carry IPv6. Block selected IPv6 routes
        // instead of silently sending them through the Windows default route.
        debugTag = $"IPv6 from {Path.GetFileName(owner.ExecutablePath)} to {destination} blocked: {decision.Explanation}";
        return PacketAction.Drop;
    }

    /// <summary>fc00::/7 — the IPv6 equivalent of a private range. .NET has no built-in check for it.</summary>
    private static bool IsUniqueLocal(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        return address.TryWriteBytes(bytes, out _) && (bytes[0] & 0xFE) == 0xFC;
    }

    /// <summary>
    /// The UDP counterpart. The shape mirrors TCP, but without a handshake there is no single
    /// packet that marks the start of a flow, so the rule is evaluated on any datagram that has no
    /// NAT entry yet and the answer is recorded for the rest of the flow. Rebinding a live flow
    /// mid-stream is still avoided: once an entry exists it is followed, never recomputed.
    /// </summary>
    private unsafe PacketAction TryProcessUdp(
        WinDivertIPv4Hdr* ipv4Hdr, WinDivertUDPHdr* udpHdr, ref WinDivertAddress addr, out string? debugTag)
    {
        debugTag = null;

        var srcAddr = IPAddress.Parse(((IPv4Addr)ipv4Hdr->SrcAddr).ToString());
        var dstAddr = IPAddress.Parse(((IPv4Addr)ipv4Hdr->DstAddr).ToString());
        var srcPort = (ushort)udpHdr->SrcPort;
        var dstPort = (ushort)udpHdr->DstPort;

        // A reply the relay is handing back to the app: restore the addresses so the app sees an
        // answer from the server it addressed, not from loopback.
        if (IPAddress.IsLoopback(srcAddr)
            && _udpRelayPortsCache.Contains(srcPort)
            && _natTable.TryGet(ProtocolUdp, dstPort, out var reply))
        {
            ipv4Hdr->SrcAddr = ToIPv4Addr(reply.OriginalDestAddress);
            ipv4Hdr->DstAddr = ToIPv4Addr(reply.OriginalSrcAddress);
            udpHdr->SrcPort = reply.OriginalDestPort;
            debugTag = "Udp-reply";
            return PacketAction.Rewrite;
        }

        if (IPAddress.IsLoopback(dstAddr))
            return PacketAction.Forward;

        // Already-classified flow: keep sending it the same way. The destination is re-checked
        // because one UDP socket can legitimately send to several peers, and only the datagrams
        // matching the recorded peer belong to this NAT entry.
        var hasExistingNat = _natTable.TryGet(ProtocolUdp, srcPort, out var tracked);
        if (hasExistingNat && tracked.OriginalDestPort == dstPort &&
            tracked.OriginalDestAddress.Equals(dstAddr))
        {
            _natTable.Touch(ProtocolUdp, srcPort);
            RewriteUdpToRelay(ipv4Hdr, udpHdr, ref addr, tracked.ProxyPort);
            debugTag = "Udp-established";
            return PacketAction.Rewrite;
        }

        if (!_flowTracker.TryGetOwner(ProtocolUdp, srcPort, out var owner)
            || owner.ProcessId == _flowTracker.SelfProcessId
            || _excludedExecutableNames.Contains(Path.GetFileName(owner.ExecutablePath)))
            return PacketAction.Forward;

        if (dstPort == 0)
            return PacketAction.Forward;

        var decision = ResolveRoute(owner, dstAddr, dstPort, ProtocolUdp);
        if (decision.Kind == RouteDecisionKind.Block)
        {
            debugTag = $"UDP blocked by {(decision.PolicyId?.ToString() ?? "legacy adapter rule")} to {dstAddr}:{dstPort}";
            return PacketAction.Drop;
        }
        if (decision.Kind != RouteDecisionKind.Route)
            return PacketAction.Forward;

        // The existing transparent UDP protocol uses the app's source port as its NAT key.
        // It cannot simultaneously relay two different destinations from one source port.
        // Do not let a second routed destination leak out directly or corrupt that NAT entry.
        if (hasExistingNat)
        {
            debugTag = $"UDP multiple destinations on port {srcPort}: blocked to protect NAT mapping";
            return PacketAction.Drop;
        }

        if (_proxyManager.GetUdpPortForAdapter(decision.AdapterId!) is not int relayPort)
        {
            debugTag = $"UDP route to {decision.AdapterId} unavailable, fail-closed";
            return PacketAction.Drop;
        }

        DebugLog.Write($"Udp new: {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} owner={Path.GetFileName(owner.ExecutablePath)} => relay 127.0.0.1:{relayPort}");
        _natTable.Track(ProtocolUdp, srcPort, dstAddr, dstPort, srcAddr, (ushort)relayPort);
        RewriteUdpToRelay(ipv4Hdr, udpHdr, ref addr, (ushort)relayPort);
        debugTag = "Udp-new";
        return PacketAction.Rewrite;
    }

    private static unsafe void RewriteUdpToRelay(
        WinDivertIPv4Hdr* ipv4Hdr, WinDivertUDPHdr* udpHdr, ref WinDivertAddress addr, ushort relayPort)
    {
        // Same loopback rules as the TCP path — see RewriteToProxy for why both addresses and the
        // interface metadata have to be rewritten together.
        ipv4Hdr->SrcAddr = ToIPv4Addr(IPAddress.Loopback);
        ipv4Hdr->DstAddr = ToIPv4Addr(IPAddress.Loopback);
        udpHdr->DstPort = relayPort;

        addr.Network.IfIdx = 1;
        addr.Network.SubIfIdx = 0;
        addr.Loopback = true;
    }

    /// <summary>
    /// Rewrites an app's outbound packet into a loopback packet aimed at the local proxy.
    /// Both addresses become loopback, not just the destination: a packet with dst=127.0.0.1 but a
    /// real, non-loopback source is silently dropped by Windows rather than delivered to a listener
    /// bound to 127.0.0.1 (confirmed by testing — SYNs kept retransmitting and never arrived).
    /// </summary>
    private static unsafe void RewriteToProxy(WinDivertIPv4Hdr* ipv4Hdr, WinDivertTCPHdr* tcpHdr, ref WinDivertAddress addr, ushort proxyPort)
    {
        ipv4Hdr->SrcAddr = ToIPv4Addr(IPAddress.Loopback);
        ipv4Hdr->DstAddr = ToIPv4Addr(IPAddress.Loopback);
        tcpHdr->DstPort = proxyPort;

        // The addresses now say loopback, but the packet's WinDivert interface metadata still
        // points at whatever real adapter it was originally headed out of. That mismatch can make
        // Windows try to actually transmit it on that interface instead of delivering it locally.
        // Genuine loopback packets on this machine consistently report IfIdx=1 (seen in Case B's
        // untouched captures), so stamp the same values to make it unambiguously loopback.
        addr.Network.IfIdx = 1;
        addr.Network.SubIfIdx = 0;
        addr.Loopback = true;
    }

    /// <summary>Diagnostic: when non-zero, every TCP packet touching this port is traced. Set by the first Case A match.</summary>
    private static volatile ushort TraceFlowPort;

    private static string DescribeTcpFlags(byte flags)
    {
        var names = new List<string>();
        if ((flags & 0x02) != 0) names.Add("SYN");
        if ((flags & 0x10) != 0) names.Add("ACK");
        if ((flags & 0x08) != 0) names.Add("PSH");
        if ((flags & 0x01) != 0) names.Add("FIN");
        if ((flags & 0x04) != 0) names.Add("RST");
        return names.Count == 0 ? $"0x{flags:X2}" : string.Join("|", names);
    }

    // Never inherit a rule down from these. They parent large parts of the session — Explorer
    // launches nearly everything the user opens, and the service hosts launch the rest — so
    // treating a rule on one of them as covering its children would quietly capture the whole
    // machine off a single click. A rule on Explorer means Explorer's own traffic, nothing more.
    private static readonly HashSet<string> NonInheritableParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
        "winlogon.exe", "userinit.exe", "taskeng.exe", "taskhostw.exe", "runtimebroker.exe",
    };

    /// <summary>
    /// Finds the rule that governs a flow, falling back to the app's ancestors so helper processes
    /// are covered by the rule set on the app that launched them — Steam downloads through
    /// steam.exe while its interface runs as a separate steamwebhelper.exe, and a user setting a
    /// rule on one reasonably expects it to hold for the other.
    ///
    /// An app that has its own entry is never overridden by an ancestor's, even when that entry is
    /// "Automatic": choosing Automatic is a deliberate instruction to leave this app on the default
    /// route, and inheriting over it would make that choice impossible to express.
    /// </summary>
    private AppRule? ResolveEffectiveRule(FlowOwner owner)
    {
        var own = _ruleStore.Get(owner.ExecutablePath);
        if (own is not null)
            return own is { Enabled: true, AdapterId: not null } ? own : null;

        foreach (var ancestorPath in _flowTracker.GetAncestorExecutables(owner.ProcessId))
        {
            if (NonInheritableParents.Contains(Path.GetFileName(ancestorPath)))
                return null;

            var inherited = _ruleStore.Get(ancestorPath);
            if (inherited is null)
                continue;

            return inherited is { Enabled: true, AdapterId: not null } ? inherited : null;
        }

        return null;
    }

    /// <summary>
    /// Specific destination policies take precedence over legacy per-application defaults.
    /// The adapter snapshot is populated only for listeners that started successfully.
    /// </summary>
    private RouteDecision ResolveRoute(FlowOwner owner, IPAddress destination, ushort port, byte protocol)
    {
        var connection = new ConnectionDestination(
            Path.GetFileName(owner.ExecutablePath), owner.ExecutablePath, destination, port,
            protocol == ProtocolTcp ? TransportProtocol.Tcp : TransportProtocol.Udp);
        var policy = _policyEngine.Evaluate(connection, _proxyManager.GetAvailability(), _domainIndex);
        if (policy.Kind != RouteDecisionKind.Unmatched)
            return policy;

        var legacy = ResolveEffectiveRule(owner);
        if (legacy?.AdapterId is not string adapterId)
            return RouteDecision.Unmatched;

        if (destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return new RouteDecision(RouteDecisionKind.Block, null, null, "Legacy app rule cannot route IPv6");

        if (!_proxyManager.GetAvailability().Any(a => a.IsUp && a.Id.Equals(adapterId,
                StringComparison.OrdinalIgnoreCase) && a.SupportsIpv4))
            return new RouteDecision(RouteDecisionKind.Block, null, null, "Legacy app adapter unavailable");

        return new RouteDecision(RouteDecisionKind.Route, null, adapterId, "Legacy per-app adapter");
    }

    private bool IsKnownProxyPort(ushort port) => _proxyPortsCache.Contains(port);

    private static IPv4Addr ToIPv4Addr(IPAddress address) => IPv4Addr.Parse(address.ToString());

    public void Dispose()
    {
        _cts.Cancel();
        _proxyManager.PortsChanged -= OnProxyPortsChanged;
        _proxyPortCacheTimer.Dispose();
        _handle.Dispose();
        try { Task.WaitAll(_loops, TimeSpan.FromSeconds(2)); } catch { /* ignore */ }
        _cts.Dispose();
    }
}
