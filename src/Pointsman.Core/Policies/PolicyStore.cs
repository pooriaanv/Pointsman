using System.Text.Json;
using System.Text.Json.Serialization;

namespace Pointsman.Core.Policies;

/// <summary>
/// Versioned, separately stored destination policies. Does not modify Pointsman's
/// existing rules.json and will never silently reset malformed policies.
/// </summary>
public sealed class PolicyStore
{
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Pointsman", "destination-policies.json");

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private sealed record Document
    {
        public int SchemaVersion { get; init; } = 1;
        public DestinationPolicy[] Rules { get; init; } = [];
    }

    public PolicyStore(string? path = null)
    {
        _path = path ?? DefaultPath;
        if (string.IsNullOrWhiteSpace(_path)) throw new ArgumentException("Invalid policy path", nameof(path));
    }

    public async Task<IReadOnlyList<DestinationPolicy>> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_path)) return [];
            await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length > 16 * 1024 * 1024)
                throw new InvalidDataException("Destination policy file exceeds the supported 16 MB limit");
            using var parsed = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var root = parsed.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var version) ||
                version.ValueKind != JsonValueKind.Number || version.GetInt32() != 1 ||
                !root.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Invalid destination policies: schemaVersion=1 and rules array are required");
            var document = root.Deserialize<Document>(JsonOptions)
                ?? throw new InvalidDataException("Empty destination policies document");
            if (document.Rules is null) throw new InvalidDataException("Rules cannot be null");
            PolicyValidation.ThrowIfInvalid(document.Rules);
            return document.Rules;
        }
        finally { _gate.Release(); }
    }

    public async Task SaveAsync(IEnumerable<DestinationPolicy> rules, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var snapshot = rules.ToArray();
        PolicyValidation.ThrowIfInvalid(snapshot);
        var directory = Path.GetDirectoryName(Path.GetFullPath(_path))!;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? temporary = null;
        try
        {
            Directory.CreateDirectory(directory);
            temporary = Path.Combine(directory, Path.GetFileName(_path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, new Document { Rules = snapshot }, JsonOptions, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, _path, overwrite: true);
            temporary = null;
        }
        finally
        {
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best effort */ }
            }
            _gate.Release();
        }
    }
}
