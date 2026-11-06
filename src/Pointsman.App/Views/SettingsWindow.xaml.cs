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
        VersionText.Text = version.IsDevelopmentBuild
            ? $"Version {version} (development build: does not check for updates)"
            : $"Version {version}";
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var autoInstall = AutoInstallBox.IsChecked == true;
        _store.Update(s => s with { AutoInstallUpdates = autoInstall });
        DialogResult = true;
    }
}
