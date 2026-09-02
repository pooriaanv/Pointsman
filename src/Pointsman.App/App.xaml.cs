using System.Diagnostics;
using System.IO;
using System.Windows;

namespace Pointsman.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // WPF reports binding problems through its own trace source and nowhere else — a binding
        // that silently fails to write looks identical to one that was never touched. Routing that
        // to a file is the only way to tell those apart in a windowed app with no console.
        if (Environment.GetEnvironmentVariable("POINTSMAN_BINDINGTRACE") is not (null or "" or "0"))
        {
            var path = Path.Combine(AppContext.BaseDirectory, "debug-binding.log");
            var listener = new TextWriterTraceListener(path) { TraceOutputOptions = TraceOptions.None };
            PresentationTraceSources.Refresh();
            PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
            PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.All;
            Trace.AutoFlush = true;
        }
    }
}
