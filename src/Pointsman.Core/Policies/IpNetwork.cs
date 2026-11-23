using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Pointsman.Core.Policies;

/// <summary>A strict IPv4/IPv6 CIDR value type. It is immutable and contains no network I/O.</summary>
public readonly struct IpNetwork
{
    private readonly byte[]? _network;
    public AddressFamily Family { get; }
    public int PrefixLength { get; }

    private IpNetwork(byte[] network, AddressFamily family, int prefixLength)
    {
        _network = network;
        Family = family;
        PrefixLength = prefixLength;
    }

    public static bool TryParse(string? value, out IpNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var pieces = value.Split('/');
        if (pieces.Length != 2 || !IpAddressLiteral.TryParse(pieces[0].Trim(), out var address) || address is null) return false;
        var bytes = address.GetAddressBytes();
        if (!int.TryParse(pieces[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) ||
            prefix < 0 || prefix > bytes.Length * 8) return false;

        ApplyMask(bytes, prefix);
        network = new IpNetwork(bytes, address.AddressFamily, prefix);
        return true;
    }

    public override string ToString() => _network is null ? string.Empty :
        $"{new IPAddress(_network)}/{PrefixLength}";

    public bool Contains(IPAddress address)
    {
        if (_network is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != Family) return false;
        var bytes = address.GetAddressBytes();
        ApplyMask(bytes, PrefixLength);
        return bytes.AsSpan().SequenceEqual(_network);
    }

    private static void ApplyMask(Span<byte> bytes, int bits)
    {
        var fullBytes = bits / 8;
        var partialBits = bits % 8;
        if (partialBits != 0 && fullBytes < bytes.Length)
        {
            bytes[fullBytes] &= (byte)(0xFF << (8 - partialBits));
            fullBytes++;
        }
        bytes[fullBytes..].Clear();
    }
}
