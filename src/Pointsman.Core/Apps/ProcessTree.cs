using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Pointsman.Core.Apps;

/// <summary>
/// Reads parent/child relationships between processes, so a rule set on an app can also cover the
/// helper processes it launches. One Toolhelp snapshot returns the whole table, which is far
/// cheaper than asking about processes one at a time, and the result is cached briefly because
/// this is consulted while a packet is being held.
/// </summary>
internal static class ProcessTree
{
    private const uint SnapProcess = 0x00000002;
    private static readonly TimeSpan SnapshotMaxAge = TimeSpan.FromSeconds(3);

    private static readonly Lock Lock = new();
    private static Dictionary<int, int> _parentByPid = new();
    private static DateTime _snapshotTakenUtc = DateTime.MinValue;

    // A process can outlive its parent, and Windows reuses PIDs — so an ancestor lookup can walk
    // into a completely unrelated process that happens to have inherited the number. Comparing
    // start times rejects that: a real parent cannot have started after its child.
    private static readonly ConcurrentDictionary<int, DateTime> StartTimeByPid = new();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    private static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>Walks up from <paramref name="pid"/>, yielding each ancestor PID nearest-first.</summary>
    public static IEnumerable<int> GetAncestors(int pid, int maxDepth = 8)
    {
        var parents = GetParentMap();
        var seen = new HashSet<int> { pid };
        var current = pid;

        for (var depth = 0; depth < maxDepth; depth++)
        {
            if (!parents.TryGetValue(current, out var parent) || parent == 0)
                yield break;

            // Guards against both a PID cycle and the idle process parenting itself.
            if (!seen.Add(parent))
                yield break;

            if (!IsPlausibleParent(parent, current))
                yield break;

            yield return parent;
            current = parent;
        }
    }

    private static bool IsPlausibleParent(int parentPid, int childPid)
    {
        var parentStart = GetStartTime(parentPid);
        var childStart = GetStartTime(childPid);

        // If either time is unavailable the relationship can't be disproved; accepting it keeps
        // inheritance working for processes we can't open, and a wrong guess here only ever means
        // a rule applies where the user didn't intend, never that traffic escapes unnoticed.
        if (parentStart is null || childStart is null)
            return true;

        return parentStart <= childStart;
    }

    private static DateTime? GetStartTime(int pid)
    {
        if (StartTimeByPid.TryGetValue(pid, out var cached))
            return cached;

        try
        {
            using var process = Process.GetProcessById(pid);
            var started = process.StartTime.ToUniversalTime();
            StartTimeByPid[pid] = started;
            return started;
        }
        catch (ArgumentException) { return null; }            // already exited
        catch (System.ComponentModel.Win32Exception) { return null; }  // access denied
        catch (InvalidOperationException) { return null; }    // exited mid-read
    }

    private static Dictionary<int, int> GetParentMap()
    {
        lock (Lock)
        {
            if (DateTime.UtcNow - _snapshotTakenUtc < SnapshotMaxAge)
                return _parentByPid;

            var map = TakeSnapshot();
            if (map is not null)
            {
                _parentByPid = map;
                _snapshotTakenUtc = DateTime.UtcNow;
            }

            return _parentByPid;
        }
    }

    private static Dictionary<int, int>? TakeSnapshot()
    {
        var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            return null;

        try
        {
            var map = new Dictionary<int, int>();
            var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };

            if (!Process32First(snapshot, ref entry))
                return null;

            do
            {
                map[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID;
            }
            while (Process32Next(snapshot, ref entry));

            return map;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }
}
