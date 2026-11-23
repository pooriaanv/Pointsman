using Pointsman.Core.SystemRouting;

namespace Pointsman.Core.Policies;

/// <summary>
/// Single owner for persistence and activation. A failed validation, read or write leaves
/// the previous active rule snapshot unchanged. The UI should call SaveAsync on edits.
/// </summary>
public sealed class PolicyManager
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly PolicyStore _store;
    private readonly PolicyEngine _engine;
    private readonly ISystemRouteApplier? _systemRoutes;
    private DestinationPolicy[] _rules = [];

    public event EventHandler? RulesChanged;

    public PolicyManager(PolicyStore store, PolicyEngine engine, ISystemRouteApplier? systemRoutes = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _systemRoutes = systemRoutes;
    }

    public IReadOnlyList<DestinationPolicy> Current => Clone(Volatile.Read(ref _rules));

    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = Clone(await _store.LoadAsync(cancellationToken).ConfigureAwait(false));
            _engine.ReplaceRules(loaded);
            Volatile.Write(ref _rules, loaded);
            // Adapter discovery and route reconciliation happen after the UI starts.
            _systemRoutes?.SetLoadedRules(loaded);
        }
        finally { _gate.Release(); }
        NotifyRulesChanged();
    }

    public async Task SaveAsync(IEnumerable<DestinationPolicy> rules, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var proposed = Clone(rules);
        PolicyValidation.ThrowIfInvalid(proposed);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previous = Clone(Volatile.Read(ref _rules));
            var routeChangeAttempted = false;
            var savedOnDisk = false;
            try
            {
                if (_systemRoutes is not null)
                {
                    routeChangeAttempted = true;
                    // A system route affects all applications. The OS operation must
                    // succeed before the editor can display a successful save.
                    await _systemRoutes.ApplyAsync(proposed, cancellationToken).ConfigureAwait(false);
                }
                await _store.SaveAsync(proposed, cancellationToken).ConfigureAwait(false);
                savedOnDisk = true;
                var persisted = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
                if (persisted.Count != proposed.Length ||
                    !proposed.Zip(persisted).All(pair => SamePolicy(pair.First, pair.Second)))
                    throw new IOException("Saved routing policies differ from the file read back from disk");
                _engine.ReplaceRules(proposed);
                Volatile.Write(ref _rules, proposed);
            }
            catch (Exception error)
            {
                // Reconcile OS routes back to the active snapshot if persistence failed.
                // Do not hide rollback failures: the user needs the exact error.
                Exception? rollbackFailure = null;
                if (routeChangeAttempted)
                {
                    try { await _systemRoutes!.ApplyAsync(previous, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception ex) { rollbackFailure = ex; }
                }
                if (savedOnDisk)
                {
                    try { await _store.SaveAsync(previous, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception ex) { rollbackFailure = rollbackFailure is null ? ex :
                        new AggregateException(rollbackFailure, ex); }
                }
                if (rollbackFailure is not null)
                    throw new AggregateException("Policy save failed and its rollback also failed", error, rollbackFailure);
                throw;
            }
        }
        finally { _gate.Release(); }
        NotifyRulesChanged();
    }

    private void NotifyRulesChanged()
    {
        // Persistence/activation succeeded already. An observer failure must not report
        // "save failed" when the JSON and active snapshot were actually committed.
        try { RulesChanged?.Invoke(this, EventArgs.Empty); }
        catch (Exception ex) { System.Diagnostics.Trace.TraceError("Policy change notification: {0}", ex); }
    }

    private static bool SamePolicy(DestinationPolicy a, DestinationPolicy b) =>
        a.Id == b.Id &&
        string.Equals(a.Name, b.Name, StringComparison.Ordinal) &&
        a.Enabled == b.Enabled &&
        a.Priority == b.Priority &&
        string.Equals(a.ProcessName, b.ProcessName, StringComparison.Ordinal) &&
        string.Equals(a.ProcessPath, b.ProcessPath, StringComparison.Ordinal) &&
        a.DestinationKind == b.DestinationKind &&
        string.Equals(a.Destination, b.Destination, StringComparison.Ordinal) &&
        a.Protocol == b.Protocol &&
        a.FromPort == b.FromPort &&
        a.ToPort == b.ToPort &&
        a.Action == b.Action &&
        string.Equals(a.AdapterId, b.AdapterId, StringComparison.Ordinal) &&
        a.WhenUnavailable == b.WhenUnavailable &&
        a.UseSystemRoute == b.UseSystemRoute &&
        string.Equals(a.SystemNextHop, b.SystemNextHop, StringComparison.Ordinal) &&
        a.AlternativeAdapterIds.SequenceEqual(b.AlternativeAdapterIds, StringComparer.Ordinal);

    private static DestinationPolicy[] Clone(IEnumerable<DestinationPolicy> rules) =>
        rules.Select(policy => policy with
        {
            AlternativeAdapterIds = policy.AlternativeAdapterIds?.ToArray() ?? []
        }).ToArray();
}
