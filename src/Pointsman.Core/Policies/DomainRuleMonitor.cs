namespace Pointsman.Core.Policies;

/// <summary>
/// Resolves exact-hostname rules outside the packet hot path. DNS-to-IP attribution is a
/// best-effort heuristic: shared IPs and Windows DNS caching mean hostname rules are not a
/// security boundary. IP/CIDR rules should be used for strict routing or blocking.
/// </summary>
public sealed class DomainRuleMonitor : IAsyncDisposable
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(2);

    private readonly PolicyManager _manager;
    private readonly DomainAddressIndex _index;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _refreshRequested = new(1, 1);
    private readonly Task _background;

    public DomainRuleMonitor(PolicyManager manager, DomainAddressIndex index)
    {
        _manager = manager;
        _index = index;
        _manager.RulesChanged += OnRulesChanged;
        _background = Task.Run(RunAsync);
    }

    private void OnRulesChanged(object? sender, EventArgs e)
    {
        try { _refreshRequested.Release(); }
        catch (SemaphoreFullException) { /* Multiple changes coalesce into one refresh. */ }
        catch (ObjectDisposedException) { /* Shutdown raced a policy notification. */ }
    }

    private async Task RunAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await _index.RefreshAsync(_manager.Current, CacheLifetime, _cts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                // A broken resolver must not crash interception or delete the previous rules.
                System.Diagnostics.Trace.TraceWarning("Domain refresh failed: {0}", ex.Message);
            }

            try
            {
                await _refreshRequested.WaitAsync(RefreshInterval, _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested) { break; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _manager.RulesChanged -= OnRulesChanged;
        await _cts.CancelAsync().ConfigureAwait(false);
        try { await _background.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        _refreshRequested.Dispose();
        _cts.Dispose();
    }
}
