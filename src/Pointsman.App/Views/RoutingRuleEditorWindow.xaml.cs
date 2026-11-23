using System.Windows;
using Pointsman.Core.Diagnostics;
using Pointsman.App.ViewModels;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.App.Views;

public partial class RoutingRuleEditorWindow : Window
{
    private readonly RoutingRuleEditorViewModel _model;

    public DestinationPolicy Result { get; private set; }

    public RoutingRuleEditorWindow(DestinationPolicy initial, IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        InitializeComponent();
        Result = initial;
        _model = new RoutingRuleEditorViewModel(initial, adapters);
        DataContext = _model;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Result = _model.Build();
            DialogResult = true;
        }
        catch (ArgumentException ex)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Invalid routing rule",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            DiagnosticsLog.Error("Build routing rule", ex);
            System.Windows.MessageBox.Show(this, ex.Message, "Unable to prepare rule",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
