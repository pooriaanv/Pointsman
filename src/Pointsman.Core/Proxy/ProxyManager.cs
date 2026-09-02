using System.Net;
using Pointsman.Core.Models;
using Pointsman.Core.Redirect;

namespace Pointsman.Core.Proxy;

/// <summary>
/// Keeps one TCP proxy and one UDP relay running per connected adapter that has an IPv4 address,
/// rebuilding them when the adapter set changes (adapter connects/disconnects/gets a new IP).
/// Exposes the local ports the redirector steers each protocol's traffic to.
/// </summary>
public sealed class ProxyManager(NatTable? natTable = null) : IAsyncDisposable
{
    private sealed record AdapterEndpoints(Socks5Server Tcp, UdpRelay? Udp)
    {
        public async ValueTask DisposeAsync()
        {
            await Tcp.DisposeAsync().ConfigureAwait(false);
            if (Udp is not null)
                await Udp.DisposeAsync().ConfigureAwait(false);
        }
    }

    private readonly Dictionary<string, AdapterEndpoints> _byAdapter = new();
    private readonly Lock _lock = new();

    public int? GetPortForAdapter(string adapterId)
    {
        lock (_lock)
        {
            return _byAdapter.TryGetValue(adapterId, out var e) ? e.Tcp.Port : null;
        }
    }

    public int? GetUdpPortForAdapter(string adapterId)
    {
        lock (_lock)
        {
            return _byAdapter.TryGetValue(adapterId, out var e) ? e.Udp?.Port : null;
        }
    }

    public IReadOnlyDictionary<string, int> GetAllPorts()
    {
        lock (_lock)
        {
            return _byAdapter.ToDictionary(kv => kv.Key, kv => kv.Value.Tcp.Port);
        }
    }

    public IReadOnlyCollection<int> GetAllUdpPorts()
    {
        lock (_lock)
        {
            return _byAdapter.Values
                .Where(e => e.Udp is not null)
                .Select(e => e.Udp!.Port)
                .ToList();
        }
    }

    public async Task SyncAsync(IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        var eligible = adapters
            .Where(a => a.IsUp && a.IPv4Address is not null)
            .ToDictionary(a => a.Id);

        List<AdapterEndpoints> toStop = [];
        List<NetworkAdapterInfo> toStart = [];

        lock (_lock)
        {
            foreach (var staleId in _byAdapter.Keys.Where(id => !eligible.ContainsKey(id)).ToList())
            {
                toStop.Add(_byAdapter[staleId]);
                _byAdapter.Remove(staleId);
            }

            foreach (var adapter in eligible.Values)
            {
                if (_byAdapter.TryGetValue(adapter.Id, out var existing) &&
                    existing.Tcp.AdapterAddress.ToString() == adapter.IPv4Address)
                    continue; // already running with the right IP

                if (_byAdapter.Remove(adapter.Id, out var stale))
                    toStop.Add(stale);

                toStart.Add(adapter);
            }
        }

        foreach (var endpoints in toStop)
            await endpoints.DisposeAsync().ConfigureAwait(false);

        foreach (var adapter in toStart)
        {
            var address = IPAddress.Parse(adapter.IPv4Address!);

            var tcp = new Socks5Server(address, natTable);
            tcp.Start();

            // The UDP relay needs the NAT table to recover each datagram's real destination, so
            // without one there is nothing to relay through and TCP-only redirection stands.
            UdpRelay? udp = null;
            if (natTable is not null)
            {
                udp = new UdpRelay(address, natTable);
                udp.Start();
            }

            lock (_lock)
            {
                _byAdapter[adapter.Id] = new AdapterEndpoints(tcp, udp);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        List<AdapterEndpoints> endpoints;
        lock (_lock)
        {
            endpoints = _byAdapter.Values.ToList();
            _byAdapter.Clear();
        }

        foreach (var e in endpoints)
            await e.DisposeAsync().ConfigureAwait(false);
    }
}
