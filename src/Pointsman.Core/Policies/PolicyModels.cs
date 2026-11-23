using System.Net;

namespace Pointsman.Core.Policies;

/// <summary>The protocol used by the originating connection.</summary>
public enum TransportProtocol { Any, Tcp, Udp }

/// <summary>How a destination is matched before a connection is redirected.</summary>
public enum DestinationKind { Any, Ip, Cidr, Domain }

/// <summary>Action to perform when a rule matches.</summary>
public enum PolicyAction { Route, Direct, Block }

/// <summary>What to do if the chosen outbound adapter is unavailable.</summary>
public enum UnavailableAdapterAction { Block, Direct, TryAlternatives }

/// <summary>
/// Named policies are independent of the legacy per-application rules.json file.
/// Higher Priority values win; stable specificity and Id tie-breakers apply.
/// </summary>
public sealed record DestinationPolicy
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; init; } = string.Empty;
    public bool Enabled { get; init; } = true;
    public int Priority { get; init; }
    public string ProcessName { get; init; } = "*";
    public string? ProcessPath { get; init; }
    public DestinationKind DestinationKind { get; init; } = DestinationKind.Any;
    public string? Destination { get; init; }
    public TransportProtocol Protocol { get; init; } = TransportProtocol.Any;
    public int? FromPort { get; init; }
    public int? ToPort { get; init; }
    public PolicyAction Action { get; init; } = PolicyAction.Route;
    public string? AdapterId { get; init; }
    /// <summary>
    /// Explicit opt-in: installs an ephemeral Windows IPv4 route for ALL processes and
    /// protocols, including ICMP. Only valid for a global IPv4 IP/CIDR Route policy.
    /// Not a firewall rule, not a kill switch.
    /// </summary>
    public bool UseSystemRoute { get; init; }
    /// <summary>Optional IPv4 next hop. Blank means on-link or the selected adapter's gateway.</summary>
    public string? SystemNextHop { get; init; }
    public UnavailableAdapterAction WhenUnavailable { get; init; } = UnavailableAdapterAction.Block;
    public string[] AlternativeAdapterIds { get; init; } = [];
}

/// <summary>Metadata from the originating connection. Hostname must be verified by the caller if provided.</summary>
public sealed record ConnectionDestination(
    string ProcessName,
    string? ProcessPath,
    IPAddress DestinationAddress,
    int DestinationPort,
    TransportProtocol Protocol,
    string? VerifiedHostName = null);

/// <summary>
/// An adapter is available only if it is up and has an outbound address of the required family.
/// The redirector must still verify actual socket binding and routing, and block on failure.
/// </summary>
public sealed record AdapterAvailability(
    string Id,
    bool IsUp,
    bool SupportsIpv4,
    bool SupportsIpv6);

public enum RouteDecisionKind { Unmatched, Route, Direct, Block }

public sealed record RouteDecision(
    RouteDecisionKind Kind,
    Guid? PolicyId,
    string? AdapterId,
    string Explanation)
{
    public static RouteDecision Unmatched { get; } = new(
        RouteDecisionKind.Unmatched, null, null, "No destination policy matched");
}
