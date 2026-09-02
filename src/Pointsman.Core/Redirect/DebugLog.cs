namespace Pointsman.Core.Redirect;

/// <summary>
/// Diagnostic file logger for the redirect path, with an immediate flush per line — Console
/// output proved unreliable here (it buffers, and a redirected elevated process can exit with
/// the buffer unwritten, which silently hides exactly the traces you need).
///
/// Some of this runs per packet, so it is off unless <see cref="Enabled"/> is set. Turn it on by
/// setting the POINTSMAN_TRACE environment variable, or from code before starting the engine.
/// </summary>
internal static class DebugLog
{
    private static readonly object Lock = new();

    private static readonly string Path = System.IO.Path.Combine(
        AppContext.BaseDirectory, "debug-trace.log");

    /// <summary>Off by default: writing a line per packet to disk under a lock is far too slow to leave on.</summary>
    public static bool Enabled { get; set; } =
        Environment.GetEnvironmentVariable("POINTSMAN_TRACE") is not (null or "" or "0");

    public static void Write(string message)
    {
        if (!Enabled)
            return;

        lock (Lock)
        {
            File.AppendAllText(Path, $"{DateTime.Now:HH:mm:ss.fff} {message}{Environment.NewLine}");
        }
    }
}
