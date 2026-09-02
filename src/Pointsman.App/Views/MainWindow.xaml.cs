using System.Drawing;
using System.Windows;
using Pointsman.App.ViewModels;
using Application = System.Windows.Application;

namespace Pointsman.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private bool _isExiting;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;

        SetupTrayIcon();
        Loaded += async (_, _) => await _viewModel.RefreshAsync();
    }

    private void SetupTrayIcon()
    {
        System.Drawing.Icon? icon = null;
        try
        {
            icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "");
        }
        catch
        {
            // fall back to default below
        }

        _trayIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = icon ?? SystemIcons.Application,
            Visible = true,
            Text = "Pointsman",
        };

        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => ShowWindow());
        menu.Items.Add("Refresh", null, async (_, _) => await _viewModel.RefreshAsync());
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApplication());
        _trayIcon.ContextMenuStrip = menu;

        _trayIcon.DoubleClick += (_, _) => ShowWindow();
    }

    private void ShowWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _isExiting = true;
        Close();
    }

    /// <summary>
    /// Commits an adapter choice straight from the control that made it.
    ///
    /// The two-way binding alone proved unreliable here: these dropdowns live inside DataGrid
    /// cells, and the grid's editing machinery sits between the control and the source. WPF's own
    /// binding trace recorded no write at all when a selection was made by hand — the dropdown
    /// showed the new adapter while the rule behind it never changed. Handling the event directly
    /// takes that machinery out of the path entirely.
    /// </summary>
    private void AdapterComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox { DataContext: AppRowViewModel row })
            return;

        if (e.AddedItems.Count == 0 || e.AddedItems[0] is not AdapterChoiceViewModel choice)
            return;

        row.CommitUserSelection(choice);
    }

    private void Window_StateChanged(object sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
            Hide();
    }

    private async void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_isExiting)
        {
            // Minimize to tray instead of exiting, so background proxy servers keep running.
            e.Cancel = true;
            Hide();
            return;
        }

        _trayIcon?.Dispose();
        await _viewModel.DisposeAsync();
        Application.Current.Shutdown();
    }
}
