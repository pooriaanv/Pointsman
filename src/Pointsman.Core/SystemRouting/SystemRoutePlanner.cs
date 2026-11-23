using System.Net;
using System.Net.Sockets;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.Core.SystemRouting;

/// <summary>Exact Windows ActiveStore IPv4 route identity.</summary>
public sealed record WindowsRoute(string DestinationPrefix, int InterfaceIndex, string NextHop);

/// <summary>
/// Pure route planner, independent of Windows. System routing is deliberately limited to
/// explicit global IPv4 policies so a process-specific rule never changes another app's route.
/// </summary>
public static class SystemRoutePlanner
{
    public static IReadOnlyList<WindowsRoute> Build(
        IEnumerable<DestinationPolicy> policies,
        IEnumerable<NetworkAdapterInfo> adapters,
        bool requireAvailableAdapters)
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(adapters);

        var byId = adapters.ToDictionary(a => a.Id, StringComparer.OrdinalIgnoreCase);
        var byPrefix = new Dictionary<string, WindowsRoute>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in policies.Where(p => p.Enabled && p.UseSystemRoute))
        {
            var validation = PolicyValidation.Validate(policy);
            if (validation.Count != 0)
                throw new ArgumentException($"System route '{policy.Name}': {string.Join("; ", validation)}");

            if (!byId.TryGetValue(policy.AdapterId!, out var adapter) ||
                !adapter.IsUp || adapter.IPv4InterfaceIndex is not > 0 ||
                !IpAddressLiteral.TryParse(adapter.IPv4Address, out var source) ||
                source?.AddressFamily != AddressFamily.InterNetwork)
            {
                if (requireAvailableAdapters)
                    throw new InvalidOperationException(
                        $"System route '{policy.Name}' cannot be installed: the selected adapter is offline or has no IPv4 address");
                continue;
            }

            var prefix = policy.DestinationKind == DestinationKind.Ip
                ? $"{IPAddress.Parse(policy.Destination!)}/32"
                : IpNetwork.TryParse(policy.Destination, out var network)
                    ? network.ToString()
                    : throw new ArgumentException("Invalid IPv4 route prefix");
            if (!IpNetwork.TryParse(prefix, out var destinationNetwork))
                throw new ArgumentException("Invalid route destination");

            var networkAddress = IPAddress.Parse(prefix[..prefix.IndexOf('/')]);
            var isOnLink = adapter.IPv4PrefixLength is >= 0 and <= 32 &&
                IpNetwork.TryParse($"{source}/{adapter.IPv4PrefixLength}", out var nicSubnet) &&
                nicSubnet.PrefixLength <= destinationNetwork.PrefixLength &&
                nicSubnet.Contains(networkAddress);

            var nextHop = !string.IsNullOrWhiteSpace(policy.SystemNextHop)
                ? policy.SystemNextHop!
                : isOnLink ? IPAddress.Any.ToString() : adapter.IPv4DefaultGateway;
            if (string.IsNullOrWhiteSpace(nextHop) ||
                !IpAddressLiteral.TryParse(nextHop, out var gateway) ||
                gateway is null || gateway.AddressFamily != AddressFamily.InterNetwork)
            {
                if (requireAvailableAdapters)
                    throw new InvalidOperationException(
                        $"System route '{policy.Name}' needs a reachable IPv4 gateway on '{adapter.Name}'. " +
                        "Specify a next hop in the editor or configure a gateway for the selected adapter.");
                continue;
            }

            var route = new WindowsRoute(prefix, adapter.IPv4InterfaceIndex.Value, gateway.ToString());
            if (byPrefix.TryGetValue(prefix, out var existing) && existing != route)
                throw new ArgumentException(
                    $"Conflicting Windows system routes for {prefix}: two rules select different interfaces or next hops");
            byPrefix[prefix] = route;
            if (byPrefix.Count > 64)
                throw new ArgumentException("At most 64 active Windows system routes are allowed");
        }
        return byPrefix.Values.OrderBy(r => r.DestinationPrefix, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}

public interface ISystemRouteApplier
{
    /// <summary>Load persisted policies without altering Windows routes until adapter discovery completes.</summary>
    void SetLoadedRules(IReadOnlyList<DestinationPolicy> rules);

    /// <summary>Install the required Windows routes before a policy is persisted and activated.</summary>
    Task ApplyAsync(IReadOnlyList<DestinationPolicy> rules, CancellationToken cancellationToken = default);
}
