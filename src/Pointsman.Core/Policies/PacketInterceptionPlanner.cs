using System.Net.Sockets;
using Pointsman.Core.Models;

namespace Pointsman.Core.Policies;

/// <summary>
/// Generates the narrowest safe WinDivert NETWORK-layer filter supported by Pointsman.
/// Windows system routes work in the OS network stack and must not activate WinDivert.
/// The NETWORK layer cannot select a process ID, so per-application routing still
/// requires inspecting all non-loopback outbound connections.
/// </summary>
public static class PacketInterceptionPlanner
{
    public sealed record Plan(bool Required, string Filter, string Reason)
    {
        public static Plan Disabled { get; } = new(false, string.Empty, "No packet interception rules");
    }

    public static Plan Build(
        IEnumerable<DestinationPolicy> destinationPolicies,
        IEnumerable<AppRule> applicationRules,
        IEnumerable<int>? tcpRelayPorts = null,
        IEnumerable<int>? udpRelayPorts = null)
    {
        ArgumentNullException.ThrowIfNull(destinationPolicies);
        ArgumentNullException.ThrowIfNull(applicationRules);

        // Automatic or disabled legacy entries do not need packet interception.
        var hasApplicationRouting = applicationRules.Any(rule =>
            rule.Enabled && !string.IsNullOrWhiteSpace(rule.AdapterId));

        // 'Direct' alone is a no-op; it only needs evaluation if an application
        // route or another packet rule could otherwise redirect that connection.
        var packetPolicies = destinationPolicies
            .Where(rule => rule.Enabled && !rule.UseSystemRoute &&
                (hasApplicationRouting || rule.Action != PolicyAction.Direct))
            .ToArray();

        if (!hasApplicationRouting && packetPolicies.Length == 0)
            return Plan.Disabled;

        // Return traffic from local TCP/UDP relays must be rewritten to appear to
        // originate at the app's real destination. Capture ONLY the local relays'
        // reply ports, not every loopback connection (including the debugger's).
        var relayReplies = new List<string>();
        if (tcpRelayPorts is not null)
            relayReplies.AddRange(tcpRelayPorts.Where(ValidPort).Distinct().OrderBy(port => port)
                .Select(port => $"tcp.SrcPort == {port}"));
        if (udpRelayPorts is not null)
            relayReplies.AddRange(udpRelayPorts.Where(ValidPort).Distinct().OrderBy(port => port)
                .Select(port => $"udp.SrcPort == {port}"));
        var loopbackReplies = relayReplies.Count == 0 ? string.Empty :
            $" or (loopback and ({string.Join(" or ", relayReplies)}))";

        // With per-process rules the network layer has no PID. Domain, Any, CIDR
        // and IPv6 selectors likewise cannot use the limited exact-IPv4 filter.
        if (hasApplicationRouting || packetPolicies.Any(p =>
                p.DestinationKind != DestinationKind.Ip ||
                !IpAddressLiteral.TryParse(p.Destination, out var address) ||
                address is null || address.AddressFamily != AddressFamily.InterNetwork))
        {
            return new Plan(true,
                $"outbound and (tcp or udp) and (not loopback{loopbackReplies})",
                hasApplicationRouting ? "Per-application routing" : "Dynamic or non-IPv4 destination selectors");
        }

        // Exact IPv4 selectors can leave ALL other internet packets in Windows.
        // Huge filters risk exceeding WinDivert's filter parser limit; for now
        // those uncommon configurations use the generic non-loopback filter.
        var addresses = packetPolicies.Select(rule => rule.Destination!)
            .Distinct(StringComparer.Ordinal).OrderBy(ip => ip, StringComparer.Ordinal).ToArray();
        if (addresses.Length > 32)
            return new Plan(true,
                $"outbound and (tcp or udp) and (not loopback{loopbackReplies})",
                "Too many exact-IP selectors for the short filter");

        var remote = string.Join(" or ", addresses.Select(ip => $"ip.DstAddr == {ip}"));
        return new Plan(true,
            $"outbound and (tcp or udp) and ((ip and ({remote})){loopbackReplies})",
            "Exact IPv4 destinations and relay replies only");
    }

    private static bool ValidPort(int port) => port is >= 1 and <= 65535;
}
