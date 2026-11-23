using System.Net;
using System.IO;

namespace Pointsman.Core.Policies;

/// <summary>
/// Stateless connection decision path backed by an atomically replaced, precompiled ruleset.
/// The actual packet interception, redirects and blocking MUST be implemented at the
/// WinDivert caller; returning Block alone does not block traffic.
/// </summary>
public sealed class PolicyEngine
{
    private sealed class CompiledPolicy
    {
        public required DestinationPolicy Definition { get; init; }
        public required string ProcessName { get; init; }
        public required string? ProcessPath { get; init; }
        public required IPAddress? Ip { get; init; }
        public required IpNetwork Network { get; init; }
        public required string? Host { get; init; }
        public required string[] AlternativeAdapterIds { get; init; }
        public required int DestinationSpecificity { get; init; }
        public required int ProcessSpecificity { get; init; }
        public required int PortSpecificity { get; init; }
        public required int ProtocolSpecificity { get; init; }

        public bool Matches(ConnectionDestination connection, DomainAddressIndex? domains, DateTimeOffset now)
        {
            var process = Path.GetFileName(connection.ProcessName);
            if (!ProcessName.Equals("*", StringComparison.Ordinal) &&
                !ProcessName.Equals(process, StringComparison.OrdinalIgnoreCase) &&
                !ProcessName.Equals(process + ".exe", StringComparison.OrdinalIgnoreCase)) return false;

            if (ProcessPath is not null &&
                !ProcessPath.Equals(connection.ProcessPath, StringComparison.OrdinalIgnoreCase)) return false;
            if (Definition.Protocol != TransportProtocol.Any && Definition.Protocol != connection.Protocol) return false;
            if (Definition.FromPort is int from && connection.DestinationPort < from) return false;
            if (Definition.ToPort is int to && connection.DestinationPort > to) return false;

            var address = Normalize(connection.DestinationAddress);
            switch (Definition.DestinationKind)
            {
                case DestinationKind.Any: return true;
                case DestinationKind.Ip: return Ip!.Equals(address);
                case DestinationKind.Cidr: return Network.Contains(address);
                case DestinationKind.Domain:
                    if (connection.VerifiedHostName is not null &&
                        PolicyValidation.TryNormalizeHost(connection.VerifiedHostName, out var host, out var wildcard) &&
                        !wildcard)
                        return host.Equals(Host, StringComparison.OrdinalIgnoreCase);
                    return domains is not null &&
                        domains.Contains(Definition.Id, address, now);
                default: return false;
            }
        }
    }

    private CompiledPolicy[] _compiled = [];


    /// <summary>All replacements are validated completely before the active rules change.</summary>
    public void ReplaceRules(IEnumerable<DestinationPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var values = policies.ToArray();
        PolicyValidation.ThrowIfInvalid(values);
        var compiled = values.Where(p => p.Enabled).Select(Compile)
            .OrderByDescending(p => p.Definition.Priority)
            .ThenByDescending(p => p.DestinationSpecificity)
            .ThenByDescending(p => p.ProcessSpecificity)
            .ThenByDescending(p => p.PortSpecificity)
            .ThenByDescending(p => p.ProtocolSpecificity)
            .ThenBy(p => p.Definition.Id)
            .ToArray();
        Volatile.Write(ref _compiled, compiled);
    }

    /// <summary>
    /// Evaluate at connection creation, not per packet. The caller should retain the route
    /// for the lifetime of the flow and terminate the flow if a required adapter fails.
    /// </summary>
    public RouteDecision Evaluate(
        ConnectionDestination connection,
        IReadOnlyCollection<AdapterAvailability> adapters,
        DomainAddressIndex? domains = null,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(connection.DestinationAddress);
        if (connection.DestinationPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(connection), "Invalid destination port");

        var snapshot = Volatile.Read(ref _compiled);
        var instant = now ?? DateTimeOffset.UtcNow;
        foreach (var rule in snapshot)
        {
            if (!rule.Matches(connection, domains, instant)) continue;
            var policy = rule.Definition;
            if (policy.Action == PolicyAction.Block)
                return new RouteDecision(RouteDecisionKind.Block, policy.Id, null, "Policy blocks connection");
            if (policy.Action == PolicyAction.Direct)
                return new RouteDecision(RouteDecisionKind.Direct, policy.Id, null, "Policy explicitly uses the system default route");

            // An explicit OS route was installed for this global IP/CIDR rule.
            // Do NOT transparently relay it again: Windows must choose the selected
            // interface for all protocols (including traffic with unknown PID).
            if (policy.UseSystemRoute)
                return new RouteDecision(RouteDecisionKind.Direct, policy.Id, null,
                    "Windows system route handles this destination (all protocols)");

            if (Normalize(connection.DestinationAddress).AddressFamily ==
                    System.Net.Sockets.AddressFamily.InterNetworkV6)
                return new RouteDecision(RouteDecisionKind.Block, policy.Id, null,
                    "IPv6 redirector support is not available; blocked rather than leaked");

            if (IsAvailable(policy.AdapterId!, connection.DestinationAddress, adapters))
                return new RouteDecision(RouteDecisionKind.Route, policy.Id, policy.AdapterId,
                    "Primary adapter available");

            switch (policy.WhenUnavailable)
            {
                case UnavailableAdapterAction.Direct:
                    return new RouteDecision(RouteDecisionKind.Direct, policy.Id, null,
                        "Explicit direct fallback (may expose traffic outside the VPN)");
                case UnavailableAdapterAction.TryAlternatives:
                    foreach (var alternative in rule.AlternativeAdapterIds)
                        if (IsAvailable(alternative, connection.DestinationAddress, adapters))
                            return new RouteDecision(RouteDecisionKind.Route, policy.Id, alternative,
                                "Alternative adapter selected");
                    break;
            }
            return new RouteDecision(RouteDecisionKind.Block, policy.Id, null,
                "Required adapter unavailable; fail closed");
        }
        return RouteDecision.Unmatched;
    }

    private static bool IsAvailable(string adapterId, IPAddress address,
        IReadOnlyCollection<AdapterAvailability> adapters)
    {
        var ipv4 = Normalize(address).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        return adapters.Any(adapter =>
            adapter.IsUp && adapter.Id.Equals(adapterId, StringComparison.OrdinalIgnoreCase) &&
            (ipv4 ? adapter.SupportsIpv4 : adapter.SupportsIpv6));
    }

    private static CompiledPolicy Compile(DestinationPolicy policy)
    {
        IPAddress? ip = null;
        IpNetwork network = default;
        string? host = null;
        var specificity = 0;
        switch (policy.DestinationKind)
        {
            case DestinationKind.Ip:
                _ = IpAddressLiteral.TryParse(policy.Destination, out ip);
                specificity = 3000;
                break;
            case DestinationKind.Cidr:
                _ = IpNetwork.TryParse(policy.Destination, out network);
                specificity = 1000 + network.PrefixLength;
                break;
            case DestinationKind.Domain:
                host = PolicyValidation.NormalizeHost(policy.Destination!);
                specificity = 2000;
                break;
        }
        return new CompiledPolicy
        {
            Definition = policy,
            ProcessName = policy.ProcessName.Trim(),
            ProcessPath = string.IsNullOrWhiteSpace(policy.ProcessPath) ? null : policy.ProcessPath.Trim(),
            Ip = ip,
            Network = network,
            Host = host,
            AlternativeAdapterIds = (string[])policy.AlternativeAdapterIds.Clone(),
            DestinationSpecificity = specificity,
            ProcessSpecificity = (string.IsNullOrWhiteSpace(policy.ProcessPath) ? 0 : 2) +
                                 (policy.ProcessName.Trim() == "*" ? 0 : 1),
            PortSpecificity = policy.FromPort is null ? 0 : 1,
            ProtocolSpecificity = policy.Protocol == TransportProtocol.Any ? 0 : 1
        };
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
