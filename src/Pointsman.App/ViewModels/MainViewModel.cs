using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Threading;
using Pointsman.Core.Diagnostics;
using System.Windows.Data;
using Pointsman.App.Views;
using Pointsman.Core.Adapters;
using Pointsman.Core.Apps;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;
using Pointsman.Core.Proxy;
using Pointsman.Core.Redirect;
using Pointsman.Core.Rules;
using Pointsman.Core.Settings;
using Pointsman.Core.SystemRouting;

namespace Pointsman.App.ViewModels;

public sealed class MainViewModel : ViewModelBase, IAsyncDisposable
{
    // Never redirect the VPN client itself — its own encrypted traffic to the VPN server must
    // always go direct, or it would be sent right back into our redirected path and loop.
    private static readonly string[] VpnClientExeNames =
    [
        "openvpnconnect.exe", "openvpn.exe", "openvpngui.exe",
    ];

    private readonly AdapterMonitor _adapterMonitor = new();
    private readonly NatTable _natTable = new();
    private readonly ProxyManager _proxyManager;
    // Socket-layer process discovery is also a WinDivert handle. Keep it closed when
    // only Windows system routing is configured.
    private FlowTracker? _flowTracker;
    // WinDivert must only be open while there are rules that actually need packet interception.
    // Machine-wide IPv4 system routes are handled by Windows and require no packet capture.
    private TransparentRedirector? _redirector;
    private string? _activeCaptureFilter;
    private bool _interceptionFaulted;
    private readonly RuleStore _ruleStore = new();
    private readonly PolicyEngine _policyEngine = new();
    private readonly WindowsSystemRouteManager _systemRoutes = new();
    private readonly DomainAddressIndex _domainIndex = new();
    private readonly PolicyManager _policyManager;
    private readonly DomainRuleMonitor _domainMonitor;
    private readonly SettingsStore _settings = new();
    private readonly Dictionary<string, AppRowViewModel> _rowsByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _manuallyAddedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Windows.Threading.Dispatcher _dispatcher;

    private string _searchText = "";
    private bool _isBusy;
    private bool _isRefreshing;
    private bool _refreshQueued;
    private volatile bool _shuttingDown;
    private bool _refreshErrorShown;
    private bool _systemRouteErrorShown;
    private TaskCompletionSource? _refreshFinished;
    private bool _openingRules;
    private readonly DispatcherTimer _refreshDebounce;
    private readonly EventHandler _adapterChangedHandler;
    private readonly EventHandler _ruleReloadedHandler;
    private readonly EventHandler _policyChangedHandler;

    public ObservableCollection<AdapterViewModel> Adapters { get; } = [];
    public ObservableCollection<AppRowViewModel> Apps { get; } = [];
    public ICollectionView AppsView { get; }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
                AppsView.Refresh();
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetField(ref _isBusy, value);
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand BrowseForAppCommand { get; }
    public RelayCommand OpenSettingsCommand { get; }
    public RelayCommand OpenRoutingRulesCommand { get; }

    public SettingsStore Settings => _settings;
    public UpdateViewModel Updates { get; }

    public MainViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        _refreshDebounce = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
        {
            Interval = TimeSpan.FromMilliseconds(450)
        };
        _refreshDebounce.Tick += (_, _) =>
        {
            _refreshDebounce.Stop();
            _ = RefreshAsync();
        };
        _adapterChangedHandler = (_, _) => QueueRefreshFromAnyThread();
        _ruleReloadedHandler = (_, _) => QueueRefreshFromAnyThread();
        _policyChangedHandler = (_, _) => QueueRefreshFromAnyThread();
        AppsView = CollectionViewSource.GetDefaultView(Apps);
        AppsView.Filter = FilterApp;
        AppsView.SortDescriptions.Add(new SortDescription(nameof(AppRowViewModel.SortGroup), ListSortDirection.Ascending));
        AppsView.SortDescriptions.Add(new SortDescription(nameof(AppRowViewModel.DisplayName), ListSortDirection.Ascending));

        _proxyManager = new ProxyManager(_natTable);
        _policyManager = new PolicyManager(new PolicyStore(), _policyEngine, _systemRoutes);
        // Do not activate interception with an empty rule set if saved policy JSON is invalid.
        // Startup is refused until the configuration is repaired (fail closed at startup).
        _policyManager.LoadAsync().GetAwaiter().GetResult();
        _domainMonitor = new DomainRuleMonitor(_policyManager, _domainIndex);
        // Do NOT start a catch-all network-layer WinDivert handle here. The adapters
        // and relays have not even been discovered yet, and a system-route-only policy
        // must never capture unrelated internet traffic.

        Updates = new UpdateViewModel(_settings);

        RefreshCommand = new RelayCommand(_ => _ = RefreshAsync());
        BrowseForAppCommand = new RelayCommand(_ => BrowseForApp());
        OpenSettingsCommand = new RelayCommand(_ =>
            new SettingsWindow(_settings) { Owner = System.Windows.Application.Current.MainWindow }.ShowDialog());
        // Always get a fresh adapter list off the UI thread before opening the editor.
        OpenRoutingRulesCommand = new RelayCommand(_ => _ = OpenRoutingRulesAsync());

        _adapterMonitor.AdaptersChanged += _adapterChangedHandler;

        // Source-of-truth changes, including those from the routing editor, are reconciled
        // on the UI dispatcher after adapter sync has finished.
        _ruleStore.RulesReloaded += _ruleReloadedHandler;
        _policyManager.RulesChanged += _policyChangedHandler;
    }

    private bool FilterApp(object obj)
    {
        if (string.IsNullOrWhiteSpace(SearchText))
            return true;

        var row = (AppRowViewModel)obj;
        return row.DisplayName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase)
            || row.ExecutablePath.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase);
    }

    private async Task OpenRoutingRulesAsync()
    {
        if (_shuttingDown || _openingRules) return;
        _openingRules = true;
        try
        {
            var adapters = await Task.Run(_adapterMonitor.GetAdapters);
            // Load the latest NICs before editing. If Windows route reconciliation fails,
            // keep the editor accessible so the user can correct the adapter or gateway.
            try { await _systemRoutes.UpdateAdaptersAsync(adapters); }
            catch (Exception routeError)
            {
                DiagnosticsLog.Error("Refresh Windows routes before editing", routeError);
                if (!_shuttingDown)
                    System.Windows.MessageBox.Show(
                        $"The Windows route could not be verified. You can still edit the rule.\n\n{routeError.Message}\n\nLog: {DiagnosticsLog.FilePath}",
                        "Windows route unavailable", System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Warning);
            }
            if (!_shuttingDown)
                new RoutingRulesWindow(_policyManager, adapters)
                    { Owner = System.Windows.Application.Current.MainWindow }.ShowDialog();
        }
        catch (Exception ex)
        {
            DiagnosticsLog.Error("Open destination routing editor", ex);
            if (!_shuttingDown)
                System.Windows.MessageBox.Show(
                    $"Unable to open routing rules.\n\n{ex.Message}\n\nLog: {DiagnosticsLog.FilePath}",
                    "Pointsman", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
        finally { _openingRules = false; }
    }

    private void QueueRefreshFromAnyThread()
    {
        if (_shuttingDown || _dispatcher.HasShutdownStarted) return;
        try { _ = _dispatcher.BeginInvoke((Action)ScheduleRefresh, DispatcherPriority.Background); }
        catch (InvalidOperationException) { /* Dispatcher is shutting down. */ }
    }

    private void ScheduleRefresh()
    {
        if (_shuttingDown || _dispatcher.HasShutdownStarted) return;
        _refreshDebounce.Stop();
        _refreshDebounce.Start();
    }

    private void OnRedirectorFaulted(object? sender, Exception error)
    {
        DiagnosticsLog.Error("WinDivert interception stopped", error);
        if (_shuttingDown || _dispatcher.HasShutdownStarted) return;
        _ = _dispatcher.BeginInvoke((Action)(() =>
        {
            // Reopening a failing global capture handle after every adapter notification
            // could repeatedly disrupt networking. Stay passive until the next restart.
            _interceptionFaulted = true;
            StopInterception();
            System.Windows.MessageBox.Show(
                $"Packet interception stopped after an error. Ordinary Windows networking is restored, " +
                $"but process-level and packet-level rules are NOT enforced until Pointsman restarts.\n\n" +
                $"{error.Message}\n\nDetails: {DiagnosticsLog.FilePath}",
                "Pointsman network interception stopped",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }));
    }

    private void StopInterception()
    {
        var redirector = _redirector;
        var tracker = _flowTracker;
        _redirector = null;
        _flowTracker = null;
        _activeCaptureFilter = null;

        if (redirector is not null)
        {
            redirector.Faulted -= OnRedirectorFaulted;
            try { redirector.Dispose(); }
            catch (Exception ex) { DiagnosticsLog.Error("Stop packet interception", ex); }
        }
        if (tracker is not null)
        {
            try { tracker.Dispose(); }
            catch (Exception ex) { DiagnosticsLog.Error("Stop process ownership capture", ex); }
        }
        if (redirector is not null || tracker is not null)
        {
            _natTable.Clear();
            DiagnosticsLog.Write("Packet and process interception stopped; Windows owns all traffic again");
        }
    }

    private void ReconcileInterception()
    {
        var plan = PacketInterceptionPlanner.Build(_policyManager.Current, _ruleStore.GetAll(),
            _proxyManager.GetAllPorts().Values, _proxyManager.GetAllUdpPorts());
        if (!plan.Required)
        {
            StopInterception();
            return;
        }

        if (_interceptionFaulted)
            return; // Explicit user restart required after a driver failure.

        if (_redirector is not null && string.Equals(_activeCaptureFilter, plan.Filter, StringComparison.Ordinal))
            return;

        // Keep WinDivert open only when needed. Never open it just for an IPv4
        // system-route policy: Windows applies that route without packet capture.
        StopInterception();
        try
        {
            _flowTracker = new FlowTracker();
            var redirector = new TransparentRedirector(_flowTracker, _natTable, _ruleStore,
                _policyEngine, _domainIndex, _proxyManager, VpnClientExeNames, plan.Filter);
            redirector.Faulted += OnRedirectorFaulted;
            _redirector = redirector;
            _activeCaptureFilter = plan.Filter;
            DiagnosticsLog.Write($"Packet interception enabled: {plan.Reason}");
        }
        catch (Exception ex)
        {
            // Never spin on a failing capture driver after every VPN/NIC change.
            _interceptionFaulted = true;
            StopInterception();
            DiagnosticsLog.Error("Start packet interception", ex);
            throw new InvalidOperationException(
                "WinDivert could not start. Packet-routing policies are inactive until Pointsman restarts. " +
                "Windows networking remains available without this capture handle.", ex);
        }
    }

    public async Task RefreshAsync()
    {
        if (_shuttingDown) return;
        if (_isRefreshing)
        {
            _refreshQueued = true;
            return;
        }

        _isRefreshing = true;
        _refreshFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        IsBusy = true;
        try
        {
            // A refresh can trigger another adapter-change notification. Run at most one
            // pass now; a pending pass is debounced instead of looping indefinitely on UI.
            _refreshQueued = false;
            await RefreshCoreAsync();
        }
        catch (Exception ex)
        {
            if (!_shuttingDown)
            {
                DiagnosticsLog.Error("Refresh adapters and applications", ex);
                if (!_refreshErrorShown)
                {
                    _refreshErrorShown = true;
                    System.Windows.MessageBox.Show(
                        $"Could not refresh network adapters.\n\n{ex.Message}\n\nDetails: {DiagnosticsLog.FilePath}",
                        "Pointsman refresh", System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Warning);
                }
            }
        }
        finally
        {
            _isRefreshing = false;
            IsBusy = false;
            _refreshFinished?.TrySetResult();
            if (_refreshQueued && !_shuttingDown)
                ScheduleRefresh();
        }
    }

    private async Task RefreshCoreAsync()
    {
        // WMI adapter enumeration and the process/network tables are too expensive to
        // execute on the WPF dispatcher. Only ObservableCollection changes stay on UI.
        var adapters = await Task.Run(_adapterMonitor.GetAdapters);
        if (_shuttingDown) return;
        await _proxyManager.SyncAsync(adapters);
        if (_shuttingDown) return;
        ReconcileInterception();
        try
        {
            // Refresh can be triggered when the VPN connects or drops. Re-install
            // active ephemeral routes using the NIC's latest interface index/gateway.
            await _systemRoutes.UpdateAdaptersAsync(adapters);
            _systemRouteErrorShown = false;
        }
        catch (Exception ex)
        {
            // A saved system-route rule can be present on disk while its Windows route
            // failed to install. The user must not be told it is active in that case.
            DiagnosticsLog.Error("Reconcile Windows system routes", ex);
            if (!_systemRouteErrorShown && !_shuttingDown &&
                _policyManager.Current.Any(rule => rule.Enabled && rule.UseSystemRoute))
            {
                _systemRouteErrorShown = true;
                System.Windows.MessageBox.Show(
                    $"A saved Windows system route could not be installed or verified. " +
                    $"It may NOT bypass your VPN until this is fixed. Other traffic will keep " +
                    $"using Windows normal routing.\n\n{ex.Message}\n\nLog: {DiagnosticsLog.FilePath}",
                    "Pointsman system route not active", System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
            }
        }

        var adapterVms = adapters
            .Select(a => new AdapterViewModel(a, _proxyManager.GetPortForAdapter(a.Id)))
            .ToList();

        Adapters.Clear();
        foreach (var vm in adapterVms)
            Adapters.Add(vm);

        var choices = new List<AdapterChoiceViewModel> { AdapterChoiceViewModel.Automatic };
        choices.AddRange(adapterVms.Select(a =>
            new AdapterChoiceViewModel(a.Id, $"{a.KindIcon} {a.Name}", a.ProxyPort)));

        var running = await Task.Run(AppDiscovery.GetRunningApps);
        if (_shuttingDown) return;
        var rulePaths = _ruleStore.GetAll().Select(r => r.ExecutablePath);
        var allPaths = running.Select(a => a.ExecutablePath)
            .Union(rulePaths, StringComparer.OrdinalIgnoreCase)
            .Union(_manuallyAddedPaths, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var runningByPath = running.ToDictionary(a => a.ExecutablePath, StringComparer.OrdinalIgnoreCase);
        foreach (var path in allPaths)
        {
            var info = runningByPath.TryGetValue(path, out var runningInfo)
                ? runningInfo
                : AppDiscovery.FromPath(path);
            UpsertRow(info, choices);
        }

        var staleKeys = _rowsByPath.Keys.Except(allPaths, StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var key in staleKeys)
        {
            if (_rowsByPath.Remove(key, out var row))
                Apps.Remove(row);
        }
        AppsView.Refresh();
    }

    private void UpsertRow(AppInfo info, List<AdapterChoiceViewModel> choices)
    {
        var rule = _ruleStore.Get(info.ExecutablePath);
        var (selected, rowChoices) = ResolveSelection(rule, choices);

        if (_rowsByPath.TryGetValue(info.ExecutablePath, out var existingRow))
        {
            existingRow.ApplyRefresh(info, rowChoices, selected);
            return;
        }

        var icon = File.Exists(info.ExecutablePath) ? IconHelper.ExtractIcon(info.ExecutablePath) : null;
        var row = new AppRowViewModel(info, icon, rowChoices, selected);
        row.OnAdapterChanged += OnRowAdapterChanged;
        _rowsByPath[info.ExecutablePath] = row;
        Apps.Add(row);
    }

    /// <summary>
    /// Works out which dropdown entry a row should show for its saved rule.
    ///
    /// If the adapter that rule names is gone entirely — unplugged, or a VPN that isn't running —
    /// it isn't among the live choices, and simply falling back to "Automatic" would show the user
    /// a rule they never set while the real one sits unchanged on disk. A placeholder entry is
    /// added for that row instead, so the saved rule stays visible and is flagged as not in effect.
    /// </summary>
    private static (AdapterChoiceViewModel Selected, List<AdapterChoiceViewModel> Choices) ResolveSelection(
        Core.Models.AppRule? rule, List<AdapterChoiceViewModel> choices)
    {
        if (rule?.AdapterId is not string adapterId)
            return (AdapterChoiceViewModel.Automatic, choices);

        var match = choices.FirstOrDefault(c => c.AdapterId == adapterId);
        if (match is not null)
            return (match, choices);

        var placeholder = new AdapterChoiceViewModel(adapterId, "⚠ Adapter not present", null);
        return (placeholder, [.. choices, placeholder]);
    }

    private void OnRowAdapterChanged(object? sender, AdapterChoiceViewModel choice)
    {
        var row = (AppRowViewModel)sender!;
        try
        {
            _ruleStore.Set(new Core.Models.AppRule
            {
                ExecutablePath = row.ExecutablePath,
                AdapterId = choice.AdapterId,
                Enabled = choice.AdapterId is not null,
            });
            ScheduleRefresh(); // A new per-app rule may require starting packet interception.
        }
        catch (Exception ex)
        {
            DiagnosticsLog.Error("Save application adapter choice", ex);
            System.Windows.MessageBox.Show(
                $"The adapter choice was not saved.\n\n{ex.Message}\n\nDetails: {DiagnosticsLog.FilePath}",
                "Pointsman rule save failed", System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
            // Reload the actual persisted selection rather than leaving a misleading UI state.
            ScheduleRefresh();
        }
    }

    private void BrowseForApp()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select an application",
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
        };

        if (dialog.ShowDialog() == true)
        {
            var choices = new List<AdapterChoiceViewModel> { AdapterChoiceViewModel.Automatic };
            choices.AddRange(Adapters.Select(a =>
                new AdapterChoiceViewModel(a.Id, $"{a.KindIcon} {a.Name}", a.ProxyPort)));

            _manuallyAddedPaths.Add(dialog.FileName);
            UpsertRow(AppDiscovery.FromPath(dialog.FileName), choices);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_shuttingDown) return;
        _shuttingDown = true;
        _refreshDebounce.Stop();
        _adapterMonitor.AdaptersChanged -= _adapterChangedHandler;
        _ruleStore.RulesReloaded -= _ruleReloadedHandler;
        _policyManager.RulesChanged -= _policyChangedHandler;
        if (_refreshFinished is not null)
            await _refreshFinished.Task;
        Updates.Dispose();
        _adapterMonitor.Dispose();
        StopInterception();
        await _systemRoutes.DisposeAsync().ConfigureAwait(false);
        await _domainMonitor.DisposeAsync().ConfigureAwait(false);
        // Relay tasks can still consult the NAT table until all listeners stop.
        await _proxyManager.DisposeAsync().ConfigureAwait(false);
        _natTable.Dispose();
        _ruleStore.Dispose();
    }
}
