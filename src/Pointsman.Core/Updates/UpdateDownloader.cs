using System.Security.Cryptography;

namespace Pointsman.Core.Updates;

/// <summary>
/// Downloads a release's installer and checks it against the release's <c>SHA256SUMS.txt</c>
/// before anything runs it.
///
/// Nothing Pointsman ships is code-signed, so the checksum is the only thing tying the file on
/// disk to the file CI produced. An installer that cannot be verified — no checksum file, no line
/// for it, or a mismatch — is deleted and never started, since it runs as administrator.
/// </summary>
public sealed class UpdateDownloader
{
    private readonly HttpClient _http;

    public UpdateDownloader(HttpClient http) => _http = http;

    public static string DownloadDirectory => Path.Combine(Path.GetTempPath(), "Pointsman-update");

    /// <returns>Path of the verified installer.</returns>
    public async Task<string> DownloadAsync(
        ReleaseInfo release,
        IProgress<double>? progress = null,
        CancellationToken cancel = default)
    {
        if (release.Installer is null)
            throw new InvalidOperationException($"Release {release.TagName} has no installer attached.");
        if (release.Checksums is null)
            throw new InvalidOperationException(
                $"Release {release.TagName} has no SHA256SUMS.txt, so its installer cannot be verified.");

        // Only the file name is taken from the release, and only after checking it is just a name.
        var fileName = Path.GetFileName(release.Installer.Name);
        if (fileName.Length == 0 || fileName != release.Installer.Name)
            throw new InvalidOperationException($"Unexpected installer name '{release.Installer.Name}'.");

        var expected = await GetExpectedHashAsync(release.Checksums, fileName, cancel).ConfigureAwait(false);

        // Start clean: a leftover from an interrupted download must never be mistaken for this one.
        var dir = DownloadDirectory;
        if (Directory.Exists(dir))
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        Directory.CreateDirectory(dir);

        var target = Path.Combine(dir, fileName);
        var partial = target + ".partial";

        using (var response = await _http.GetAsync(
                   release.Installer.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancel).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            var total = response.Content.Headers.ContentLength ?? release.Installer.Size;

            await using var source = await response.Content.ReadAsStreamAsync(cancel).ConfigureAwait(false);
            await using var file = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);

            var buffer = new byte[81920];
            long done = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, cancel).ConfigureAwait(false)) > 0)
            {
                await file.WriteAsync(buffer.AsMemory(0, read), cancel).ConfigureAwait(false);
                done += read;
                if (total > 0)
                    progress?.Report(Math.Min(1.0, (double)done / total));
            }
        }

        string actual;
        await using (var check = File.OpenRead(partial))
            actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancel).ConfigureAwait(false));

        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(partial);
            throw new InvalidDataException(
                $"The downloaded installer does not match its published checksum (expected {expected}, got {actual}). It was deleted and not run.");
        }

        File.Move(partial, target, overwrite: true);
        return target;
    }

    private async Task<string> GetExpectedHashAsync(ReleaseAsset sums, string fileName, CancellationToken cancel)
    {
        var text = await _http.GetStringAsync(sums.DownloadUrl, cancel).ConfigureAwait(false);
        return FindHash(text, fileName)
            ?? throw new InvalidDataException(
                $"SHA256SUMS.txt has no entry for {fileName}, so it cannot be verified.");
    }

    /// <summary>Lines are <c>&lt;hex&gt;  &lt;name&gt;</c>, as the release workflow writes them.</summary>
    public static string? FindHash(string sums, string fileName)
    {
        foreach (var line in sums.Split('\n'))
        {
            var parts = line.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 2
                && parts[0].Length == 64
                && parts[1].TrimStart('*').Equals(fileName, StringComparison.OrdinalIgnoreCase))
                return parts[0];
        }

        return null;
    }
}
