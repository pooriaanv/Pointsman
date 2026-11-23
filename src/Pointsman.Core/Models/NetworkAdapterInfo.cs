namespace Pointsman.Core.Models;

public enum AdapterKind
{
    Ethernet,
    WiFi,
    Vpn,
    Other,
}

public sealed class NetworkAdapterInfo
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required AdapterKind Kind { get; init; }
    public required bool IsUp { get; init; }
    public string? IPv4Address { get; init; }
    /// <summary>Windows IPv4 interface index used by IP_UNICAST_IF.</summary>
    public int? IPv4InterfaceIndex { get; init; }
    /// <summary>Prefix length of the IPv4 unicast address used for on-link route selection.</summary>
    public int? IPv4PrefixLength { get; init; }
    /// <summary>First IPv4 default gateway associated with this interface, if any.</summary>
    public string? IPv4DefaultGateway { get; init; }
    public long SpeedBitsPerSecond { get; init; }

    public string DisplayLabel => IsUp && IPv4Address is not null
        ? $"{Name} ({IPv4Address})"
        : $"{Name} (disconnected)";
}
