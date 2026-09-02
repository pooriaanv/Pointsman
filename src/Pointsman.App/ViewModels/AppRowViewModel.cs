using System.Windows.Media.Imaging;
using Pointsman.Core.Models;

namespace Pointsman.App.ViewModels;

public sealed class AppRowViewModel : ViewModelBase
{
    private AdapterChoiceViewModel _selectedAdapter;
    private AppInfo _info;
    private IReadOnlyList<AdapterChoiceViewModel> _availableAdapters;

    /// <summary>
    /// Set while a refresh is writing new state into this row, so the dropdown's own binding
    /// echoing that value back isn't mistaken for the user choosing it.
    /// </summary>
    private bool _applyingRefresh;

    public AppInfo Info => _info;
    public BitmapSource? Icon { get; init; }

    public string DisplayName => Info.DisplayName;
    public string ExecutablePath => Info.ExecutablePath;
    public bool IsRunning => Info.IsRunning;

    public string RunningStateText => IsRunning ? "Running" : "Not running";

    /// <summary>
    /// Orders the list so it stays usable now that every process holding a socket is listed:
    /// apps you've already assigned first, then apps with a window, then the background services
    /// that are only worth showing when you go looking for one.
    /// </summary>
    public int SortGroup => SelectedAdapter.AdapterId is not null ? 0
        : Info.HasWindow ? 1
        : 2;

    /// <summary>
    /// True when an adapter is chosen but cannot currently carry traffic — it is disconnected, has
    /// no IPv4 address, or has disappeared. Without this the rule would just stop applying and the
    /// app would quietly fall back to the default route, which for a tool whose whole job is
    /// deciding where traffic goes is the worst way to fail.
    /// </summary>
    public bool IsRuleInactive => SelectedAdapter.AdapterId is not null && SelectedAdapter.ProxyPort is null;

    public string RuleInactiveText =>
        "⚠️ This adapter isn't available right now, so the rule is not in effect — the app is using the system's default route.";

    public IReadOnlyList<AdapterChoiceViewModel> AvailableAdapters => _availableAdapters;

    public AdapterChoiceViewModel SelectedAdapter
    {
        get => _selectedAdapter;
        set
        {
            // WPF writes null through this binding while a dropdown's items are being rebuilt and
            // the current selection is briefly absent from them. Nobody chose that — "Automatic"
            // is a real entry — and acting on it would throw partway through a binding write,
            // which detaches the binding for good.
            if (value is null)
                return;

            if (!SetField(ref _selectedAdapter, value))
                return;

            // Reads off the selection, so the warning would otherwise keep showing the previous
            // adapter's state until something else redrew the row.
            OnPropertyChanged(nameof(IsRuleInactive));

            if (!_applyingRefresh)
                OnAdapterChanged?.Invoke(this, value);
        }
    }

    public event EventHandler<AdapterChoiceViewModel>? OnAdapterChanged;

    /// <summary>
    /// Records a choice the user made in the dropdown. Called from the control's own event rather
    /// than relying on the binding to write back — see the handler in MainWindow for why.
    /// Selections replayed by a refresh are ignored, so a redraw never looks like a user edit.
    /// </summary>
    public void CommitUserSelection(AdapterChoiceViewModel choice)
    {
        if (_applyingRefresh || choice is null)
            return;

        var changed = !Equals(_selectedAdapter, choice);
        _selectedAdapter = choice;

        if (!changed)
            return;

        OnPropertyChanged(nameof(SelectedAdapter));
        OnPropertyChanged(nameof(IsRuleInactive));
        OnAdapterChanged?.Invoke(this, choice);
    }

    public AppRowViewModel(
        AppInfo info,
        BitmapSource? icon,
        IReadOnlyList<AdapterChoiceViewModel> availableAdapters,
        AdapterChoiceViewModel initialSelection)
    {
        _info = info;
        Icon = icon;
        _availableAdapters = availableAdapters;
        _selectedAdapter = initialSelection;
    }

    /// <summary>
    /// Refreshes this row's contents without replacing the row itself.
    ///
    /// Rows used to be swapped for new instances on every refresh, and refreshes fire on any
    /// network change, not just the Refresh button. WPF's own binding trace showed the result:
    /// the dropdown's source object being replaced again and again, bindings re-pointed and
    /// sometimes detached outright. A selection made in that window was written to an object that
    /// had already been discarded, so the rule never changed — no error, nothing in any log, and
    /// only sometimes, depending on whether a refresh happened to land mid-click.
    /// </summary>
    public void ApplyRefresh(
        AppInfo info,
        IReadOnlyList<AdapterChoiceViewModel> availableAdapters,
        AdapterChoiceViewModel selection)
    {
        _applyingRefresh = true;
        try
        {
            _info = info;
            OnPropertyChanged(nameof(Info));
            OnPropertyChanged(nameof(DisplayName));
            OnPropertyChanged(nameof(IsRunning));
            OnPropertyChanged(nameof(RunningStateText));

            // Only swap the list when it genuinely differs: handing the dropdown a new collection
            // makes it rebuild its items and momentarily lose the selection.
            if (!_availableAdapters.SequenceEqual(availableAdapters))
            {
                _availableAdapters = availableAdapters;
                OnPropertyChanged(nameof(AvailableAdapters));
            }

            SelectedAdapter = selection;
            OnPropertyChanged(nameof(SortGroup));
        }
        finally
        {
            _applyingRefresh = false;
        }
    }
}
