namespace Pointsman.Core.Models;

public sealed class AppInfo
{
    public required string ExecutablePath { get; init; }
    public required string DisplayName { get; init; }
    public bool IsRunning { get; set; }
    public int? ProcessId { get; set; }

    /// <summary>
    /// Whether the process shows a top-level window. Listing every process that holds a socket is
    /// what makes background workers like Steam's downloader targetable, but it also drags in a
    /// long tail of system services — so the UI uses this to float the apps a user recognizes to
    /// the top rather than hiding the rest.
    /// </summary>
    public bool HasWindow { get; init; }
}
