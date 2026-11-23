using System.Net;
using System.Net.Sockets;

namespace Pointsman.Core.Policies;

/// <summary>
/// OPTIONAL best-effort IP-to-domain evidence. DNS lookups cannot identify the application
/// which initiated a connection, and an IP can host many domains. Never treat this as
/// equivalent to a verified hostname or as a domain-aware kill switch.
/// </summary>
public sealed class DomainAddressIndex
{
    private sealed record Snapshot(DateTimeOffset ExpiresAt, Dictionary<Guid, HashSet<IPAddress>> Addresses);
    private Snapshot _snapshot = new(DateTimeOffset.MinValue, []);

    public bool Contains(Guid policyId, IPAddress destination, DateTimeOffset now)
    {
        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.ExpiresAt <= now || !snapshot.Addresses.TryGetValue(policyId, out var addresses))
            return false;
        return addresses.Contains(Normalize(destination));
    }

    /// <summary>
    /// Resolve exact domain rules only. Wildcard rules require verified hostname evidence.
    /// Uses the SYSTEM DNS resolver; this does not route the DNS lookup through the rule's adapter.
    /// Failed lookups are not retained past the current refresh.
    /// </summary>
    public async Task RefreshAsync(
        IEnumerable<DestinationPolicy> policies,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policies);
        if (ttl <= TimeSpan.Zero || ttl > TimeSpan.FromMinutes(30))
            throw new ArgumentOutOfRangeException(nameof(ttl), "TTL must be between 1 tick and 30 minutes");

        var exactDomains = policies.Where(p => p.Enabled && p.DestinationKind == DestinationKind.Domain)
            .Select(p => (p.Id, Host: PolicyValidation.NormalizeHost(p.Destination!)))
            .ToArray();

        // A bounded number of DNS requests prevents hundreds of rules from creating a burst.
        using var limiter = new SemaphoreSlim(8);
        var results = new Dictionary<Guid, HashSet<IPAddress>>();
        var tasks = exactDomains.Select(async item =>
        {
            await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(item.Host, cancellationToken)
                        .ConfigureAwait(false);
                    return (item.Id, Addresses: addresses.Where(a => a.AddressFamily is
                            AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        .Select(Normalize).ToHashSet());
                }
                catch (SocketException) { return (item.Id, Addresses: new HashSet<IPAddress>()); }
            }
            finally { limiter.Release(); }
        }).ToArray();
        var fetched = await Task.WhenAll(tasks).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var entry in fetched) results[entry.Id] = entry.Addresses;
        Volatile.Write(ref _snapshot, new Snapshot(DateTimeOffset.UtcNow.Add(ttl), results));
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
