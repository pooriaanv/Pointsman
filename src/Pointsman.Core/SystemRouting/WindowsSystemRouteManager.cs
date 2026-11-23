using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.Core.SystemRouting;

/// <summary>
/// Manages only routes that Pointsman created. Every route is ephemeral (ActiveStore), and
/// an ownership journal allows clean-up after a crash when the app next starts. Routes that
/// existed before Pointsman are never added to the journal or removed by this manager.
/// Not a Windows firewall and not a VPN kill switch.
/// </summary>
public sealed class WindowsSystemRouteManager : ISystemRouteApplier, IAsyncDisposable
{
    public static string DefaultJournalPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Pointsman", "owned-system-routes.json");

    private sealed record Journal
    {
        public int SchemaVersion { get; init; } = 1;
        public WindowsRoute[] Routes { get; init; } = [];
    }

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IWindowsRouteCommands _commands;
    private readonly string _journalPath;
    private readonly HashSet<WindowsRoute> _owned = [];
    private NetworkAdapterInfo[] _adapters = [];
    private DestinationPolicy[] _policies = [];
    private bool _journalLoaded;
    private bool _disposed;

    public WindowsSystemRouteManager(IWindowsRouteCommands? commands = null, string? journalPath = null)
    {
        _commands = commands ?? new WindowsPowerShellRouteCommands();
        _journalPath = journalPath ?? DefaultJournalPath;
    }

    /// <summary>
    /// Used only during initial policy load, before NICs have been enumerated. Does not
    /// create or remove routes; the first UpdateAdaptersAsync applies the saved configuration.
    /// </summary>
    public void SetLoadedRules(IReadOnlyList<DestinationPolicy> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _policies = rules.ToArray();
    }

    public async Task UpdateAdaptersAsync(
        IReadOnlyList<NetworkAdapterInfo> adapters, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            _adapters = adapters.ToArray();
            // Missing/offline adapters cause any previously owned route to be withdrawn.
            // The OS might then choose a VPN route. This is not a fail-closed firewall.
            await ReconcileAsync(requireAvailableAdapters: false, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    public async Task ApplyAsync(
        IReadOnlyList<DestinationPolicy> rules, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var previous = _policies;
            _policies = rules.ToArray();
            try
            {
                // An explicit Save must never claim success with a selected NIC unavailable.
                await ReconcileAsync(requireAvailableAdapters: true, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _policies = previous;
                try { await ReconcileAsync(requireAvailableAdapters: false, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception restoreError)
                {
                    System.Diagnostics.Trace.TraceError("Restoring Windows routes failed: {0}", restoreError);
                }
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    private async Task ReconcileAsync(bool requireAvailableAdapters, CancellationToken token)
    {
        await LoadJournalAsync(token).ConfigureAwait(false);
        var desired = SystemRoutePlanner.Build(_policies, _adapters, requireAvailableAdapters).ToHashSet();

        // Install new destinations before withdrawing old ones to minimize network disruption.
        foreach (var route in desired)
        {
            token.ThrowIfCancellationRequested();
            var outcome = await _commands.EnsureAsync(route, token).ConfigureAwait(false);
            if (outcome != RouteInstallResult.Created || _owned.Contains(route)) continue;

            _owned.Add(route);
            try { await SaveJournalAsync(token).ConfigureAwait(false); }
            catch
            {
                // Never leave a newly-created route untracked after a failed journal write.
                try { await _commands.RemoveAsync(route, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception removeError)
                {
                    System.Diagnostics.Trace.TraceError("Removing untracked route failed: {0}", removeError);
                }
                _owned.Remove(route);
                throw;
            }
        }

        foreach (var obsolete in _owned.Except(desired).ToArray())
        {
            token.ThrowIfCancellationRequested();
            await _commands.RemoveAsync(obsolete, token).ConfigureAwait(false);
            _owned.Remove(obsolete);
            await SaveJournalAsync(token).ConfigureAwait(false);
        }
    }

    private async Task LoadJournalAsync(CancellationToken token)
    {
        if (_journalLoaded) return;
        if (File.Exists(_journalPath))
        {
            var info = new FileInfo(_journalPath);
            if (info.Length > 64 * 1024)
                throw new InvalidDataException("System route ownership file is unexpectedly large");
            await using var stream = new FileStream(_journalPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous);
            var document = await JsonSerializer.DeserializeAsync<Journal>(stream, cancellationToken: token)
                .ConfigureAwait(false);
            if (document is null || document.SchemaVersion != 1 || document.Routes is null || document.Routes.Length > 64)
                throw new InvalidDataException("Invalid system route ownership journal");
            foreach (var route in document.Routes)
            {
                ValidateOwnedRoute(route);
                if (!_owned.Add(route))
                    throw new InvalidDataException("Duplicate route in ownership journal");
            }
        }
        _journalLoaded = true;
    }

    private static void ValidateOwnedRoute(WindowsRoute route)
    {
        if (route is null || route.InterfaceIndex <= 0 ||
            !IpNetwork.TryParse(route.DestinationPrefix, out var network) ||
            network.Family != AddressFamily.InterNetwork || network.PrefixLength < 24 ||
            !IpAddressLiteral.TryParse(route.NextHop, out var nextHop) ||
            nextHop?.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidDataException("Invalid owned Windows route in the journal");
    }

    private async Task SaveJournalAsync(CancellationToken token)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(_journalPath))!;
        Directory.CreateDirectory(directory);
        var temporary = _journalPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, new Journal { Routes = _owned.ToArray() },
                    cancellationToken: token).ConfigureAwait(false);
                await stream.FlushAsync(token).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, _journalPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                try { File.Delete(temporary); }
                catch (IOException) { /* best-effort temporary cleanup */ }
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                await LoadJournalAsync(CancellationToken.None).ConfigureAwait(false);
                foreach (var route in _owned.ToArray())
                {
                    try
                    {
                        await _commands.RemoveAsync(route, CancellationToken.None).ConfigureAwait(false);
                        _owned.Remove(route);
                        await SaveJournalAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.TraceError("Windows route cleanup failed: {0}", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError("System route ownership recovery failed: {0}", ex);
            }
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}
