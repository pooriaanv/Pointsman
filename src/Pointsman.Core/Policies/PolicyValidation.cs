using System.Globalization;
using System.Net;

namespace Pointsman.Core.Policies;

public static class PolicyValidation
{
    public static IReadOnlyList<string> Validate(DestinationPolicy? policy)
    {
        if (policy is null) return ["Policy cannot be null"];
        var errors = new List<string>();
        if (policy.Id == Guid.Empty) errors.Add("Policy Id cannot be empty");
        if (string.IsNullOrWhiteSpace(policy.Name) || policy.Name.Length > 128)
            errors.Add("Name must contain 1 to 128 characters");
        if (policy.Priority is < -10000 or > 10000)
            errors.Add("Priority must be between -10000 and 10000");

        if (string.IsNullOrWhiteSpace(policy.ProcessName) ||
            (policy.ProcessName.Trim() != "*" && !IsProcessName(policy.ProcessName)))
            errors.Add("ProcessName must be * or an executable file name (for example chrome.exe)");
        if (policy.ProcessPath is { Length: > 0 } path &&
            (!Path.IsPathFullyQualified(path) || path.Length > 1024))
            errors.Add("ProcessPath must be an absolute path shorter than 1025 characters");
        if (policy.FromPort is not null && policy.FromPort is < 1 or > 65535)
            errors.Add("FromPort must be between 1 and 65535");
        if (policy.ToPort is not null && policy.ToPort is < 1 or > 65535)
            errors.Add("ToPort must be between 1 and 65535");
        if (policy.FromPort is null ^ policy.ToPort is null)
            errors.Add("FromPort and ToPort must be supplied together");
        if (policy.FromPort > policy.ToPort)
            errors.Add("FromPort cannot exceed ToPort");

        switch (policy.DestinationKind)
        {
            case DestinationKind.Any:
                if (!string.IsNullOrWhiteSpace(policy.Destination)) errors.Add("Any destination must not have a value");
                break;
            case DestinationKind.Ip:
                if (!IpAddressLiteral.TryParse(policy.Destination, out _))
                    errors.Add("Invalid destination IP address");
                break;
            case DestinationKind.Cidr:
                if (!IpNetwork.TryParse(policy.Destination, out _)) errors.Add("Invalid IPv4/IPv6 CIDR");
                break;
            case DestinationKind.Domain:
                if (!TryNormalizeHost(policy.Destination, out _, out var wildcard) || wildcard)
                    errors.Add("Domain matching requires a specific hostname; wildcard DNS rules are not supported");
                break;
            default: errors.Add("Unknown destination kind"); break;
        }

        if (!Enum.IsDefined(policy.Protocol)) errors.Add("Unknown transport protocol");
        if (!Enum.IsDefined(policy.Action)) errors.Add("Unknown policy action");
        if (!Enum.IsDefined(policy.WhenUnavailable)) errors.Add("Unknown unavailable-adapter action");
        if (policy.Action == PolicyAction.Route)
        {
            if (string.IsNullOrWhiteSpace(policy.AdapterId)) errors.Add("A Route policy must specify AdapterId");
        }
        else if (!string.IsNullOrWhiteSpace(policy.AdapterId) ||
                 policy.WhenUnavailable != UnavailableAdapterAction.Block ||
                 (policy.AlternativeAdapterIds?.Length ?? 0) != 0)
        {
            errors.Add("Non-route policies cannot specify adapter or fallback settings");
        }

        if (policy.UseSystemRoute)
        {
            if (policy.Action != PolicyAction.Route ||
                !string.Equals(policy.ProcessName?.Trim(), "*", StringComparison.Ordinal) || !string.IsNullOrWhiteSpace(policy.ProcessPath) ||
                policy.Protocol != TransportProtocol.Any || policy.FromPort is not null || policy.ToPort is not null ||
                policy.WhenUnavailable != UnavailableAdapterAction.Block ||
                policy.AlternativeAdapterIds is not { Length: 0 })
                errors.Add("System routes require global scope (*), Route action, Any protocol, no ports and no adapter fallbacks");

            if (policy.DestinationKind == DestinationKind.Ip)
            {
                if (!IpAddressLiteral.TryParse(policy.Destination, out var address) ||
                    address?.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    errors.Add("System routes support IPv4 destination addresses only");
            }
            else if (policy.DestinationKind == DestinationKind.Cidr)
            {
                if (!IpNetwork.TryParse(policy.Destination, out var network) ||
                    network.Family != System.Net.Sockets.AddressFamily.InterNetwork || network.PrefixLength < 24)
                    errors.Add("System route CIDRs must be IPv4 /24 or narrower to protect the default route");
            }
            else errors.Add("System routes support only exact IPv4 IP or IPv4 CIDR");
        }
        if (!string.IsNullOrWhiteSpace(policy.SystemNextHop))
        {
            if (!policy.UseSystemRoute || !IpAddressLiteral.TryParse(policy.SystemNextHop, out var gateway) ||
                gateway is null || gateway.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                gateway.Equals(IPAddress.Any) || IPAddress.IsLoopback(gateway) || gateway.IsIPv6Multicast)
                errors.Add("SystemNextHop must be a non-loopback IPv4 gateway and requires UseSystemRoute");
        }
        if (policy.AlternativeAdapterIds is null) errors.Add("AlternativeAdapterIds cannot be null");
        else
        {
            if (policy.AlternativeAdapterIds.Length > 16) errors.Add("At most 16 fallback adapters are allowed");
            if (policy.AlternativeAdapterIds.Any(string.IsNullOrWhiteSpace))
                errors.Add("Fallback adapter IDs cannot be blank");
            if (policy.AlternativeAdapterIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != policy.AlternativeAdapterIds.Length ||
                policy.AlternativeAdapterIds.Contains(policy.AdapterId ?? "", StringComparer.OrdinalIgnoreCase))
                errors.Add("Fallback adapter IDs must be unique and distinct from the primary adapter");
            if (policy.WhenUnavailable != UnavailableAdapterAction.TryAlternatives && policy.AlternativeAdapterIds.Length > 0)
                errors.Add("AlternativeAdapterIds may only be set when TryAlternatives is selected");
            if (policy.WhenUnavailable == UnavailableAdapterAction.TryAlternatives && policy.AlternativeAdapterIds.Length == 0)
                errors.Add("TryAlternatives requires at least one fallback adapter");
        }
        return errors;
    }

    public static string NormalizeHost(string host)
    {
        if (!TryNormalizeHost(host, out var normalized, out _))
            throw new ArgumentException("Invalid hostname", nameof(host));
        return normalized;
    }

    public static bool TryNormalizeHost(string? input, out string normalized, out bool wildcard)
    {
        normalized = string.Empty;
        wildcard = false;
        if (string.IsNullOrWhiteSpace(input) || input.Contains(' ') || input.Contains(':') || input.Contains('/') || input.Contains('\\')) return false;
        var hostname = input.Trim().TrimEnd('.');
        if (hostname.StartsWith("*.", StringComparison.Ordinal))
        {
            wildcard = true;
            hostname = hostname[2..];
        }
        if (hostname.Contains('*')) return false;
        try
        {
            hostname = new IdnMapping().GetAscii(hostname).ToLowerInvariant();
        }
        catch (ArgumentException) { return false; }
        var labels = hostname.Split('.');
        if (hostname.Length > 253 || labels.Length < 2 ||
            labels.Any(label => label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' ||
                                label.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch == '-')))) return false;
        normalized = hostname;
        return true;
    }

    private static bool IsProcessName(string name)
    {
        var text = name.Trim();
        return text.Length is > 4 and <= 255 &&
               text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
               text.IndexOfAny(['/', '\\', '*', '?', ':']) < 0 &&
               !text.Any(char.IsControl);
    }

    public static void ThrowIfInvalid(IEnumerable<DestinationPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var ids = new HashSet<Guid>();
        var selectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        foreach (var policy in policies)
        {
            if (++count > 10000) throw new ArgumentException("Too many destination policies");
            var errors = Validate(policy);
            if (errors.Count != 0) throw new ArgumentException($"Policy '{policy?.Name}': {string.Join("; ", errors)}");
            if (!ids.Add(policy!.Id)) throw new ArgumentException($"Duplicate policy ID: {policy.Id}");
            // Equal-priority identical selectors would be dependent on an arbitrary GUID tie-breaker.
            // Treat them as an error instead of silently choosing one of two contradictory actions.
            var destination = policy.DestinationKind switch
            {
                DestinationKind.Ip when IpAddressLiteral.TryParse(policy.Destination, out var ip) => ip!.ToString(),
                DestinationKind.Cidr when IpNetwork.TryParse(policy.Destination, out var network) => network.ToString(),
                DestinationKind.Domain => NormalizeHost(policy.Destination!),
                _ => "",
            };
            var selector = string.Join("|", policy.Priority, policy.ProcessName.Trim(),
                policy.ProcessPath?.Trim() ?? "", policy.DestinationKind,
                destination, policy.Protocol, policy.FromPort, policy.ToPort);
            if (policy.Enabled && !selectors.Add(selector))
                throw new ArgumentException($"Duplicate active policy selector at priority {policy.Priority}: {policy.Name}");
        }
    }
}
