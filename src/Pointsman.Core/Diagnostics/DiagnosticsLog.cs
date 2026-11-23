using System.Text;

namespace Pointsman.Core.Diagnostics;

/// <summary>
/// Best-effort persistent diagnostics. An error while logging must never crash the
/// WPF dispatcher or stop the packet interception loop. No packet payload is logged.
/// </summary>
public static class DiagnosticsLog
{
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private static readonly object Gate = new();

    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Pointsman", "diagnostics.log");

    public static void Error(string operation, Exception error) =>
        Write($"{operation}{Environment.NewLine}{error}");

    public static void Write(string message)
    {
        try
        {
            lock (Gate)
            {
                var path = FilePath;
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                if (File.Exists(path) && new FileInfo(path).Length >= MaxFileBytes)
                    File.Move(path, path + ".old", overwrite: true);
                File.AppendAllText(path,
                    $"[{DateTimeOffset.Now:O}] {message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
                                   or NotSupportedException or System.Security.SecurityException)
        {
            // Diagnostics must never be allowed to take down the program.
        }
    }
}
