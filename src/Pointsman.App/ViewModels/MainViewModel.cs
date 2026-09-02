using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using Pointsman.App.Views;
using Pointsman.Core.Adapters;
using Pointsman.Core.Apps;
using Pointsman.Core.Models;
using Pointsman.Core.Proxy;
using Pointsman.Core.Redirect;
using Pointsman.Core.Rules;

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
    private readonly FlowTracker _flowTracker = new();
    private readonly TransparentRedirector _redirector;
    private readonly RuleStore _ruleStore = new();
    private readonly Dictionary<string, AppRowViewModel> _rowsByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _manuallyAddedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Windows.Threading.Dispatcher _dispatcher;

    private string _searchText = "";
    private bool _isBusy;

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

    public MainViewModel()
    {
        _dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
        AppsView = CollectionViewSource.GetDefaultView(Apps);
        AppsView.Filter = FilterApp;
        AppsView.SortDescriptions.Add(new SortDescription(nameof(AppRowViewModel.SortGroup), ListSortDirection.Ascending));
        AppsView.SortDescriptions.Add(new SortDescription(nameof(AppRowViewModel.DisplayName), ListSortDirection.Ascending));

        _proxyManager = new ProxyManager(_natTable);
        _redirector = new TransparentRedirector(_flowTracker, _natTable, _ruleStore, _proxyManager, VpnClientExeNames);

        RefreshCommand = new RelayCommand(_ => _ = RefreshAsync());
        BrowseForAppCommand = new RelayCommand(_ => BrowseForApp());

        _adapterMonitor.AdaptersChanged += (_, _) => _dispatcher.InvokeAsync(() => _ = RefreshAsync());

        // The engine picks up an externally edited rules file on its own; without this the list
        // would keep showing the previous state and look like the edit hadn't taken.
        _ruleStore.RulesReloaded += (_, _) => _dispatcher.InvokeAsync(() => _ = RefreshAsync());
    }

    private bool FilterApp(object obj)
    {
        if (string.IsNullOrWhiteSpace(SearchText))
            return true;

        var row = (AppRowViewModel)obj;
        return row.DisplayName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase)
            || row.ExecutablePath.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase);
    }

    public async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var adapters = _adapterMonitor.GetAdapters();
            await _proxyManager.SyncAsync(adapters).ConfigureAwait(true);

            var adapterVms = adapters
                .Select(a => new AdapterViewModel(a, _proxyManager.GetPortForAdapter(a.Id)))
                .ToList();

            Adapters.Clear();
            foreach (var vm in adapterVms)
                Adapters.Add(vm);

            var choices = new List<AdapterChoiceViewModel> { AdapterChoiceViewModel.Automatic };
            choices.AddRange(adapterVms.Select(a =>
                new AdapterChoiceViewModel(a.Id, $"{a.KindIcon} {a.Name}", a.ProxyPort)));

            var running = AppDiscovery.GetRunningApps();
            var rulePaths = _ruleStore.GetAll().Select(r => r.ExecutablePath);
            var allPaths = running.Select(a => a.ExecutablePath)
                .Union(rulePaths, StringComparer.OrdinalIgnoreCase)
                // An app the user picked via "Add app" has no rule until they choose an adapter
                // for it, and may not be running — without this it would vanish from the list on
                // the next refresh, before they ever got to set one.
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

            // Remove rows for apps that are neither running nor have a saved rule anymore.
            var staleKeys = _rowsByPath.Keys.Except(allPaths, StringComparer.OrdinalIgnoreCase).ToList();
            foreach (var key in staleKeys)
            {
                if (_rowsByPath.Remove(key, out var row))
                    Apps.Remove(row);
            }
        }
        finally
        {
            IsBusy = false;
        }
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
        _ruleStore.Set(new Core.Models.AppRule
        {
            ExecutablePath = row.ExecutablePath,
            AdapterId = choice.AdapterId,
            Enabled = choice.AdapterId is not null,
        });
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
        _adapterMonitor.Dispose();
        _redirector.Dispose();
        _flowTracker.Dispose();
        _natTable.Dispose();
        _ruleStore.Dispose();
        await _proxyManager.DisposeAsync().ConfigureAwait(false);
    }
}
