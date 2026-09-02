using System.Collections.Concurrent;
using System.Net;

namespace Pointsman.Core.Redirect;

public readonly record struct NatEntry(
    IPAddress OriginalDestAddress,
    ushort OriginalDestPort,
    IPAddress OriginalSrcAddress,
    ushort ProxyPort,
    DateTime LastSeenUtc);

/// <summary>
/// Remembers, for each locally-redirected flow, what the real destination was before
/// <see cref="TransparentRedirector"/> rewrote it to point at a local proxy — so replies can be
/// rewritten back to look like they came from that destination, and so the proxy can reach it.
///
/// Keyed by protocol as well as port: a TCP and a UDP flow can legitimately hold the same local
/// port number at the same time while being completely unrelated. Entries expire on a TTL sweep,
/// since the OS reuses ephemeral ports soon after a flow ends.
/// </summary>
public sealed class NatTable : IDisposable
{
    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;

    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<(byte Protocol, ushort Port), NatEntry> _entries = new();
    private readonly Timer _sweepTimer;

    public NatTable()
    {
        _sweepTimer = new Timer(_ => Sweep(), null, MaxAge, MaxAge);
    }

    public void Track(
        byte protocol,
        ushort localPort,
        IPAddress originalDestAddress,
        ushort originalDestPort,
        IPAddress originalSrcAddress,
        ushort proxyPort)
    {
        _entries[(protocol, localPort)] =
            new NatEntry(originalDestAddress, originalDestPort, originalSrcAddress, proxyPort, DateTime.UtcNow);
    }

    public bool TryGet(byte protocol, ushort localPort, out NatEntry entry)
        => _entries.TryGetValue((protocol, localPort), out entry);

    /// <summary>
    /// Refreshes a UDP flow's timestamp. UDP has no close to observe, so an entry that is still
    /// carrying traffic has to be kept alive explicitly or the sweep would drop a live flow.
    /// </summary>
    public void Touch(byte protocol, ushort localPort)
    {
        var key = (protocol, localPort);
        if (_entries.TryGetValue(key, out var entry))
            _entries[key] = entry with { LastSeenUtc = DateTime.UtcNow };
    }

    private void Sweep()
    {
        var cutoff = DateTime.UtcNow - MaxAge;
        foreach (var (key, entry) in _entries)
        {
            if (entry.LastSeenUtc < cutoff)
                _entries.TryRemove(key, out _);
        }
    }

    public void Dispose() => _sweepTimer.Dispose();
}
