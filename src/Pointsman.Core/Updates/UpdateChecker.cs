using System.Net.Http.Headers;
using System.Text.Json;

namespace Pointsman.Core.Updates;

/// <summary>
/// Asks GitHub for the latest published release and reports it if it is newer than this build.
///
/// Uses the public, unauthenticated REST endpoint: no token ships with the app, and the 60
/// requests an hour GitHub allows per address is far more than a check every few hours needs.
/// <c>releases/latest</c> already skips drafts and pre-releases, so a beta tag never reaches
/// people on the stable line.
/// </summary>
public sealed class UpdateChecker
{
    public const string Repository = "pooriaanv/Pointsman";

    /// <summary>
    /// Put this anywhere in a release's notes to mark it critical. An HTML comment, so it does not
    /// show on the release page. Critical releases are installed without asking; the release
    /// workflow adds the marker when the tag's message contains <c>[critical]</c>.
    /// </summary>
    public const string CriticalMarker = "<!-- pointsman:critical -->";

    private readonly HttpClient _http;

    public UpdateChecker(HttpClient http) => _http = http;

    public static HttpClient CreateHttpClient()
    {
        // No overall timeout: the same client downloads the installer, which can legitimately
        // take minutes on a slow link. Callers pass a cancellation token instead.
        var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        // GitHub rejects API requests without a User-Agent.
        http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("Pointsman-Updater", AppVersion.Current().ToString()));
        return http;
    }

    /// <summary>
    /// Returns the latest release when it is newer than <paramref name="current"/>, otherwise null.
    /// Network and parse failures throw; the caller decides whether that is worth showing.
    /// </summary>
    public async Task<ReleaseInfo?> CheckAsync(AppVersion current, CancellationToken cancel = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.github.com/repos/{Repository}/releases/latest");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));

        using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);

        // No release published yet.
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token).ConfigureAwait(false);

        var release = Parse(doc.RootElement);
        if (release is null || !(release.Version > current))
            return null;

        return release;
    }

    public static ReleaseInfo? Parse(JsonElement root)
    {
        var tag = root.GetProperty("tag_name").GetString();
        if (!AppVersion.TryParse(tag, out var version))
            return null;

        var notes = root.TryGetProperty("body", out var body) ? body.GetString() ?? "" : "";
        var page = root.TryGetProperty("html_url", out var html) ? html.GetString() ?? "" : "";

        ReleaseAsset? installer = null, checksums = null;
        if (root.TryGetProperty("assets", out var assets))
        {
            foreach (var a in assets.EnumerateArray())
            {
                var name = a.GetProperty("name").GetString() ?? "";
                var asset = new ReleaseAsset(
                    name,
                    a.GetProperty("browser_download_url").GetString() ?? "",
                    a.TryGetProperty("size", out var size) ? size.GetInt64() : 0);

                if (name.EndsWith("-setup.exe", StringComparison.OrdinalIgnoreCase))
                    installer = asset;
                else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
                    checksums = asset;
            }
        }

        return new ReleaseInfo(
            version,
            tag!,
            page,
            notes.Replace(CriticalMarker, "", StringComparison.OrdinalIgnoreCase).Trim(),
            notes.Contains(CriticalMarker, StringComparison.OrdinalIgnoreCase),
            installer,
            checksums);
    }
}
