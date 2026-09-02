using System.Diagnostics;
using Pointsman.Core.Models;

namespace Pointsman.Core.Apps;

/// <summary>
/// Discovers the applications worth showing in the app list: running processes that either have
/// a visible window or currently hold a network connection. Callers merge this with executables
/// that already have a saved rule, so those stay listed even while not running.
/// </summary>
public static class AppDiscovery
{
    public static IReadOnlyList<AppInfo> GetRunningApps()
    {
        var seen = new Dictionary<string, AppInfo>(StringComparer.OrdinalIgnoreCase);
        var networkPids = ProcessNetworkTable.GetPidsWithConnections();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    // A process qualifies if it has a window (so the user recognizes it) or if it
                    // currently holds a network connection. The second half matters more than it
                    // looks: the process doing the networking is often not the one with the window
                    // — Steam downloads through windowless steam.exe while steamwebhelper.exe owns
                    // the UI, so a window-only filter hides the process a rule actually needs to
                    // target and makes the rule look broken.
                    var hasWindow = process.MainWindowHandle != IntPtr.Zero;
                    if (!hasWindow && !networkPids.Contains(process.Id))
                        continue;

                    // Not MainModule: service and protected processes deny the access it needs,
                    // which used to hide exactly the ones worth routing — a VPN's tunnel daemon,
                    // for instance, never appeared in this list at all.
                    var path = ProcessPathResolver.TryGetPath(process.Id);
                    if (string.IsNullOrEmpty(path))
                        continue;

                    // Prefer the window title, but never let a windowless entry overwrite a
                    // windowed one for the same executable.
                    if (seen.TryGetValue(path, out var existing) && !hasWindow && existing.IsRunning)
                        continue;

                    seen[path] = new AppInfo
                    {
                        ExecutablePath = path,
                        DisplayName = hasWindow && !string.IsNullOrWhiteSpace(process.MainWindowTitle)
                            ? process.MainWindowTitle
                            : Path.GetFileNameWithoutExtension(path),
                        IsRunning = true,
                        ProcessId = process.Id,
                        HasWindow = hasWindow,
                    };
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Access denied reading MainModule for elevated/system processes — skip.
                }
                catch (InvalidOperationException)
                {
                    // Process exited between enumeration and inspection — skip.
                }
            }
        }

        return seen.Values
            .OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public static AppInfo FromPath(string executablePath) => new()
    {
        ExecutablePath = executablePath,
        DisplayName = Path.GetFileNameWithoutExtension(executablePath),
        IsRunning = false,
    };
}
