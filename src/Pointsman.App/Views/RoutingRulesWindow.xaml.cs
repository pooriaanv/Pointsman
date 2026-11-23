using System.Collections.ObjectModel;
using System.Windows;
using Pointsman.App.ViewModels;
using Pointsman.Core.Diagnostics;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.App.Views;

public partial class RoutingRulesWindow : Window
{
    private readonly PolicyManager _manager;
    private readonly IReadOnlyList<NetworkAdapterInfo> _adapters;
    private RoutingRuleRowViewModel? _selectedRule;
    private bool _saving;

    public ObservableCollection<RoutingRuleRowViewModel> Rules { get; } = [];

    public RoutingRuleRowViewModel? SelectedRule
    {
        get => _selectedRule;
        set => _selectedRule = value;
    }

    public RoutingRulesWindow(PolicyManager manager, IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        InitializeComponent();
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        _adapters = adapters ?? throw new ArgumentNullException(nameof(adapters));
        DataContext = this;
        RefreshList();
    }

    private void RefreshList()
    {
        Rules.Clear();
        foreach (var policy in _manager.Current.OrderByDescending(p => p.Priority).ThenBy(p => p.Name))
            Rules.Add(new RoutingRuleRowViewModel(policy, _adapters));
    }

    private async void Add_Click(object sender, RoutedEventArgs e)
    {
        if (_saving) return;
        try
        {
            var editor = new RoutingRuleEditorWindow(new DestinationPolicy
            {
                Name = "New route", DestinationKind = DestinationKind.Ip, Action = PolicyAction.Route,
                ProcessName = "*", Priority = 100
            }, _adapters) { Owner = this };
            if (editor.ShowDialog() != true) return;
            await ApplyAsync([.. _manager.Current, editor.Result]);
        }
        catch (Exception ex) { ReportFailure("Add rule", ex); }
    }

    private async void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (_saving || SelectedRule is null) return;
        try
        {
            var original = SelectedRule.Policy;
            var editor = new RoutingRuleEditorWindow(original, _adapters) { Owner = this };
            if (editor.ShowDialog() != true) return;
            await ApplyAsync(_manager.Current.Select(p => p.Id == original.Id ? editor.Result : p).ToArray());
        }
        catch (Exception ex) { ReportFailure("Edit rule", ex); }
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_saving || SelectedRule is null) return;
        try
        {
            var selected = SelectedRule.Policy;
            if (System.Windows.MessageBox.Show(this, $"Delete routing rule '{selected.Name}'?",
                    "Confirm deletion", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            await ApplyAsync(_manager.Current.Where(p => p.Id != selected.Id).ToArray());
        }
        catch (Exception ex) { ReportFailure("Delete rule", ex); }
    }

    private async Task ApplyAsync(IEnumerable<DestinationPolicy> proposed)
    {
        if (_saving) return;
        _saving = true;
        IsEnabled = false;
        SaveStatus.Text = "Saving and verifying destination policies...";
        try
        {
            // PolicyManager validates, atomically persists, reads back and only then activates.
            await _manager.SaveAsync(proposed);
            RefreshList();
            var globalCount = _manager.Current.Count(p => p.Enabled && p.UseSystemRoute);
            SaveStatus.Text = $"Saved {Rules.Count} rule(s) to {PolicyStore.DefaultPath}" +
                (globalCount > 0 ? $". {globalCount} Windows system route(s) verified in ActiveStore." : string.Empty);
        }
        catch (Exception ex)
        {
            ReportFailure("Save routing rules", ex);
        }
        finally
        {
            _saving = false;
            IsEnabled = true;
        }
    }

    private void ReportFailure(string operation, Exception error)
    {
        DiagnosticsLog.Error(operation, error);
        SaveStatus.Text = "Changes were not activated. See the error message and diagnostics log.";
        var message = string.Join(Environment.NewLine,
            $"{operation} failed. The previous active rules have been kept.",
            string.Empty,
            error.Message,
            string.Empty,
            $"Log: {DiagnosticsLog.FilePath}");

        System.Windows.MessageBox.Show(this, message,
            "Pointsman routing rules", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
