using System.Diagnostics;
using System.IO;
using System.Windows;
using Pointsman.Core.Diagnostics;

namespace Pointsman.App;

public partial class App : System.Windows.Application
{
    // Two WinDivert capture instances can reinject the same traffic into each other.
    // Enforce one instance per Windows logon session, even when the second was started
    // outside Rider (e.g. elevated from PowerShell or from the system tray).
    private Mutex? _instanceMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _instanceMutex = new Mutex(initiallyOwned: true,
            name: @"Local\Pointsman.PacketCapture.SingleInstance", createdNew: out var firstInstance);
        if (!firstInstance)
        {
            _instanceMutex.Dispose();
            _instanceMutex = null;
            System.Windows.MessageBox.Show(
                "Pointsman is already running. Open the existing window from the system tray " +
                "or exit the old instance before starting another one.",
                "Pointsman is already running", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        // Older Pointsman builds do not own the mutex, so also detect their
        // processes before opening a second WinDivert interception handle.
        try
        {
            using var current = Process.GetCurrentProcess();
            var others = Process.GetProcessesByName(current.ProcessName);
            try
            {
                if (others.Any(other => other.Id != current.Id))
                {
                    System.Windows.MessageBox.Show(
                        "Another Pointsman process is running (possibly an older build). " +
                        "Exit it from the system tray or Task Manager before starting this copy.",
                        "Another Pointsman instance", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Shutdown();
                    return;
                }
            }
            finally
            {
                foreach (var other in others) other.Dispose();
            }
        }
        catch (Exception ex)
        {
            DiagnosticsLog.Error("Check for an older Pointsman instance", ex);
            // The named mutex still prevents multiple instances of this build.
        }

        DispatcherUnhandledException += (_, args) =>
        {
            DiagnosticsLog.Error("Unhandled WPF dispatcher exception", args.Exception);
            try
            {
                System.Windows.MessageBox.Show(
                    $"Pointsman encountered an unexpected error:\n\n{args.Exception.Message}\n\nDetails: {DiagnosticsLog.FilePath}",
                    "Pointsman error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch { /* The dispatcher may already be shutting down. */ }
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
                DiagnosticsLog.Error("Unhandled process exception", exception);
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            DiagnosticsLog.Error("Unobserved background task", args.Exception);
            args.SetObserved();
        };

        base.OnStartup(e);

        // WPF reports binding problems through its own trace source and nowhere else — a binding
        // that silently fails to write looks identical to one that was never touched. Routing that
        // to a file is the only way to tell those apart in a windowed app with no console.
        if (Environment.GetEnvironmentVariable("POINTSMAN_BINDINGTRACE") is not (null or "" or "0"))
        {
            try
            {
                var path = Path.Combine(Path.GetDirectoryName(DiagnosticsLog.FilePath)!, "debug-binding.log");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var listener = new TextWriterTraceListener(path) { TraceOutputOptions = TraceOptions.None };
                PresentationTraceSources.Refresh();
                PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
                PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.All;
                Trace.AutoFlush = true;
            }
            catch (Exception ex)
            {
                DiagnosticsLog.Error("Enable WPF binding trace", ex);
            }
        }

    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_instanceMutex is not null)
        {
            try { _instanceMutex.ReleaseMutex(); }
            catch (ApplicationException) { /* Mutex ownership was lost during shutdown. */ }
            _instanceMutex.Dispose();
            _instanceMutex = null;
        }
        base.OnExit(e);
    }
}
