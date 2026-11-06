using System.Diagnostics;
using System.Windows;
using Pointsman.Core.Settings;
using Pointsman.Core.Updates;

namespace Pointsman.App.Views;

public partial class SettingsWindow : Window
{
    private readonly SettingsStore _store;

    public SettingsWindow(SettingsStore store)
    {
        InitializeComponent();
        _store = store;

        AutoInstallBox.IsChecked = store.Current.AutoInstallUpdates;

        var version = AppVersion.Current();
        VersionRun.Text = version.ToString();
        if (version.IsDevelopmentBuild)
        {
            VersionNote.Text = "Development build: does not check for updates.";
            VersionNote.Visibility = Visibility.Visible;
        }
    }

    private void Link_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var autoInstall = AutoInstallBox.IsChecked == true;
        _store.Update(s => s with { AutoInstallUpdates = autoInstall });
        DialogResult = true;
    }
}
