using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Pointsman.Core.Policies;

/// <summary>
/// Rejects abbreviated IPv4 literals (e.g. 127.1) and IPv6 zone IDs, avoiding
/// surprising rules caused by IPAddress.TryParse's permissive legacy syntax.
/// </summary>
public static class IpAddressLiteral
{
    public static bool TryParse(string? value, out IPAddress? address)
    {
        address = null;
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim() || value.Contains('%')) return false;
        if (value.Contains(':'))
        {
            if (!IPAddress.TryParse(value, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
                return false;
            address = v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;
            return true;
        }
        var segments = value.Split('.');
        if (segments.Length != 4) return false;
        var octets = new byte[4];
        for (var i = 0; i < segments.Length; i++)
        {
            var item = segments[i];
            if (item.Length is < 1 or > 3 || (item.Length > 1 && item[0] == '0') ||
                !item.All(char.IsAsciiDigit) ||
                !byte.TryParse(item, NumberStyles.None, CultureInfo.InvariantCulture, out octets[i]))
                return false;
        }
        address = new IPAddress(octets);
        return true;
    }
}
