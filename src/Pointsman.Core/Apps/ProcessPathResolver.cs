using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Pointsman.Core.Apps;

/// <summary>
/// Reads a process's executable path.
///
/// <see cref="Process.MainModule"/> is the obvious way and works for ordinary programs, but it
/// walks the target's module list, which needs PROCESS_VM_READ — a right Windows refuses for
/// service and protected processes even to an administrator. Those are exactly the processes that
/// matter here: a VPN client's tunnel is established by a SYSTEM daemon, not by the window the
/// user sees, and a flow whose owner can't be named gets no rule applied at all.
///
/// QueryFullProcessImageName only needs PROCESS_QUERY_LIMITED_INFORMATION, which such processes do
/// grant, so it is tried first.
/// </summary>
public static class ProcessPathResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static string? TryGetPath(int processId)
    {
        return QueryImageName(processId) ?? FromMainModule(processId);
    }

    private static string? QueryImageName(int processId)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
            return null;

        try
        {
            var capacity = 1024;
            var buffer = new StringBuilder(capacity);
            return QueryFullProcessImageName(handle, 0, buffer, ref capacity)
                ? buffer.ToString()
                : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string? FromMainModule(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.MainModule?.FileName;
        }
        catch (ArgumentException) { return null; }        // already exited
        catch (Win32Exception) { return null; }            // access denied
        catch (InvalidOperationException) { return null; } // exited mid-read
    }
}
