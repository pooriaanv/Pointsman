using System.Management;
using System.Net.NetworkInformation;
using Pointsman.Core.Models;

namespace Pointsman.Core.Adapters;

/// <summary>
/// Enumerates network adapters (Wi-Fi / Ethernet / VPN) worth showing to the user, and raises
/// an event whenever the set of adapters or their up/down state or IP changes.
/// </summary>
public sealed class AdapterMonitor : IDisposable
{
    public event EventHandler? AdaptersChanged;

    public AdapterMonitor()
    {
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
    }

    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
        => AdaptersChanged?.Invoke(this, EventArgs.Empty);

    private void OnNetworkChanged(object? sender, EventArgs e)
        => AdaptersChanged?.Invoke(this, EventArgs.Empty);

    public IReadOnlyList<NetworkAdapterInfo> GetAdapters()
    {
        var visibleAdapters = GetVisibleAdapterGuids();
        var result = new List<NetworkAdapterInfo>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            AdapterKind? kind;

            if (visibleAdapters.Count > 0)
            {
                // NetworkInterface.GetAllNetworkInterfaces() also returns hidden pseudo-adapters
                // Windows creates for NDIS filter/protocol bindings (e.g. "NDIS 6.0 LightWeight
                // Filter-0000", "QoS Packet Scheduler-0000", or per-binding clones that inherit a
                // VPN adapter's name/description). Win32_NetworkAdapter.NetConnectionID is only
                // populated for adapters that actually show up in Windows' "Network Connections"
                // list — exactly the set a user would recognize and want to pick from — so it
                // reliably excludes those hidden bindings without relying on fragile name matching.
                if (!visibleAdapters.TryGetValue(nic.Id, out var isPhysical))
                    continue;

                kind = isPhysical ? ClassifyPhysicalKind(nic) : ClassifyNonPhysicalKind(nic);
            }
            else
            {
                // WMI unavailable — degrade to type/name heuristics only.
                kind = ClassifyPhysicalKind(nic) ?? ClassifyNonPhysicalKind(nic);
            }

            if (kind is null)
                continue;

            var ipProps = nic.GetIPProperties();
            var ipv4 = ipProps.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?.Address.ToString();

            result.Add(new NetworkAdapterInfo
            {
                Id = nic.Id,
                Name = nic.Name,
                Description = nic.Description,
                Kind = kind.Value,
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                IPv4Address = ipv4,
                SpeedBitsPerSecond = SafeSpeed(nic),
            });
        }

        return result
            .OrderByDescending(a => a.IsUp)
            .ThenBy(a => a.Kind)
            .ThenBy(a => a.Name)
            .ToList();
    }

    /// <summary>Maps adapter GUID -> PhysicalAdapter flag, for every adapter visible in Windows' Network Connections list.</summary>
    private static Dictionary<string, bool> GetVisibleAdapterGuids()
    {
        var map = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT GUID, PhysicalAdapter FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                using (obj)
                {
                    if (obj["GUID"] is string guid && !string.IsNullOrEmpty(guid))
                        map[guid] = obj["PhysicalAdapter"] is true;
                }
            }
        }
        catch
        {
            // WMI unavailable — caller falls back to type/name-based filtering only.
        }

        return map;
    }

    private static long SafeSpeed(NetworkInterface nic)
    {
        try { return nic.Speed; } catch { return 0; }
    }

    private static AdapterKind? ClassifyPhysicalKind(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback
            or NetworkInterfaceType.Tunnel
            or NetworkInterfaceType.Unknown)
            return null;

        // Skip virtual adapters (Hyper-V, VMware, WSL, Bluetooth PAN) that WMI still reports
        // as "physical" on some driver stacks but aren't real uplinks a user would route
        // app traffic through.
        var name = (nic.Name + " " + nic.Description).ToLowerInvariant();
        if (name.Contains("virtual") || name.Contains("vmware") || name.Contains("hyper-v")
            || name.Contains("loopback") || name.Contains("bluetooth") || name.Contains("wsl"))
            return null;

        return nic.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => AdapterKind.WiFi,
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet
                or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx
                => AdapterKind.Ethernet,
            // Some VPN vendors' NDIS miniport/DCO drivers (WireSock, FortiClient, OpenVPN DCO, ...)
            // report PhysicalAdapter=True in WMI despite being virtual, and use a media type other
            // than Ethernet/Wireless80211. Anything reaching here is realistically a VPN adapter,
            // not literal unknown hardware.
            _ => AdapterKind.Vpn,
        };
    }

    private static readonly string[] NonVpnVirtualNoise =
    [
        "teredo", "isatap", "6to4", "kernel debug", "wi-fi direct", "multiplexor",
        "loopback", "bluetooth", "hyper-v", "vmware", "wsl",
    ];

    private static AdapterKind? ClassifyNonPhysicalKind(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Unknown)
            return null;

        var name = (nic.Name + " " + nic.Description).ToLowerInvariant();
        if (NonVpnVirtualNoise.Any(name.Contains))
            return null;

        // Anything left that Windows itself lists as a real "Network Connection" but isn't
        // physical hardware is, in practice, a VPN tunnel adapter (TAP/WinTun/PPP dial-up VPN).
        return AdapterKind.Vpn;
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
    }
}
