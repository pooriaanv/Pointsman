using System.Net;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;
using Pointsman.Core.Redirect;

namespace Pointsman.Core.Proxy;

/// <summary>
/// Owns the per-adapter relay listeners. A serialized refresh prevents network-change events
/// from racing each other. An adapter is published as available only after its relays start.
/// </summary>
public sealed class ProxyManager(NatTable? natTable = null) : IAsyncDisposable
{
    private sealed record AdapterEndpoints(Socks5Server Tcp, UdpRelay? Udp, int InterfaceIndex)
    {
        public async ValueTask DisposeAsync()
        {
            await Tcp.DisposeAsync().ConfigureAwait(false);
            if (Udp is not null)
                await Udp.DisposeAsync().ConfigureAwait(false);
        }
    }

    private readonly Dictionary<string, AdapterEndpoints> _byAdapter = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private readonly SemaphoreSlim _syncGate = new(1, 1);
    private AdapterAvailability[] _availability = [];

    public event EventHandler? PortsChanged;

    public int? GetPortForAdapter(string adapterId)
    {
        lock (_lock)
            return _byAdapter.TryGetValue(adapterId, out var e) ? e.Tcp.Port : null;
    }

    public int? GetUdpPortForAdapter(string adapterId)
    {
        lock (_lock)
            return _byAdapter.TryGetValue(adapterId, out var e) ? e.Udp?.Port : null;
    }

    public IReadOnlyCollection<AdapterAvailability> GetAvailability() => Volatile.Read(ref _availability);

    public IReadOnlyDictionary<string, int> GetAllPorts()
    {
        lock (_lock)
            return _byAdapter.ToDictionary(kv => kv.Key, kv => kv.Value.Tcp.Port);
    }

    public IReadOnlyCollection<int> GetAllUdpPorts()
    {
        lock (_lock)
            return _byAdapter.Values.Where(e => e.Udp is not null).Select(e => e.Udp!.Port).ToArray();
    }

    public async Task SyncAsync(IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        await _syncGate.WaitAsync().ConfigureAwait(false);
        try
        {
            var eligible = adapters
                .Where(a => a.IsUp && a.IPv4Address is not null && a.IPv4InterfaceIndex is > 0)
                .ToDictionary(a => a.Id, StringComparer.OrdinalIgnoreCase);

            List<AdapterEndpoints> toStop = [];
            List<NetworkAdapterInfo> toStart = [];
            bool changed = false;

            lock (_lock)
            {
                foreach (var staleId in _byAdapter.Keys.Where(id => !eligible.ContainsKey(id)).ToArray())
                {
                    toStop.Add(_byAdapter[staleId]);
                    _byAdapter.Remove(staleId);
                    changed = true;
                }

                foreach (var adapter in eligible.Values)
                {
                    if (_byAdapter.TryGetValue(adapter.Id, out var existing) &&
                        existing.Tcp.AdapterAddress.ToString() == adapter.IPv4Address &&
                        existing.InterfaceIndex == adapter.IPv4InterfaceIndex)
                        continue;

                    if (_byAdapter.Remove(adapter.Id, out var stale))
                        toStop.Add(stale);
                    toStart.Add(adapter);
                    changed = true;
                }

                // Network-change bursts with an identical adapter snapshot must NOT briefly
                // publish an empty availability list. That used to block matching new flows.
                if (changed)
                    PublishAvailabilityLocked();
            }

            if (!changed) return;

            foreach (var endpoints in toStop)
                await endpoints.DisposeAsync().ConfigureAwait(false);

            foreach (var adapter in toStart)
            {
                Socks5Server? tcp = null;
                UdpRelay? udp = null;
                try
                {
                    var address = IPAddress.Parse(adapter.IPv4Address!);
                    var index = adapter.IPv4InterfaceIndex!.Value;
                    tcp = new Socks5Server(address, index, natTable);
                    tcp.Start();
                    if (natTable is not null)
                    {
                        udp = new UdpRelay(address, index, natTable);
                        udp.Start();
                    }

                    lock (_lock)
                        _byAdapter.Add(adapter.Id, new AdapterEndpoints(tcp, udp, index));
                }
                catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException)
                {
                    DebugLog.Write($"Adapter relay could not start for '{adapter.Name}': {ex.Message}");
                    if (udp is not null) await udp.DisposeAsync().ConfigureAwait(false);
                    if (tcp is not null) await tcp.DisposeAsync().ConfigureAwait(false);
                    // Unavailable adapters must not appear routable or fall back silently.
                }
            }

            lock (_lock)
                PublishAvailabilityLocked();
            PortsChanged?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            _syncGate.Release();
        }
    }

    // Caller holds _lock; snapshots are published atomically for the packet hot path.
    private void PublishAvailabilityLocked() =>
        Volatile.Write(ref _availability, _byAdapter.Keys.Select(id =>
            new AdapterAvailability(id, true, true, false)).ToArray());

    public async ValueTask DisposeAsync()
    {
        await _syncGate.WaitAsync().ConfigureAwait(false);
        try
        {
            List<AdapterEndpoints> endpoints;
            lock (_lock)
            {
                Volatile.Write(ref _availability, []);
                endpoints = _byAdapter.Values.ToList();
                _byAdapter.Clear();
            }
            PortsChanged?.Invoke(this, EventArgs.Empty);
            foreach (var endpoint in endpoints)
                await endpoint.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _syncGate.Release();
            _syncGate.Dispose();
        }
    }
}
