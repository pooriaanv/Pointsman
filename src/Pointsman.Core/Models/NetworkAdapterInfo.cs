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
    public long SpeedBitsPerSecond { get; init; }

    public string DisplayLabel => IsUp && IPv4Address is not null
        ? $"{Name} ({IPv4Address})"
        : $"{Name} (disconnected)";
}
