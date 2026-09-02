using System.Text.Json;
using Pointsman.Core.Models;

namespace Pointsman.Core.Rules;

/// <summary>
/// Persists per-app adapter rules as JSON under %AppData%\Pointsman\rules.json, keyed by
/// normalized executable path (case-insensitive), and keeps them in step with the file on disk.
///
/// The rule set is held as an immutable dictionary swapped in on each change. Lookups happen once
/// per new flow, on the thread holding a captured packet, so they read the current reference with
/// no lock at all; only writers serialize, and they build a fresh dictionary rather than mutate
/// the one readers may be walking.
/// </summary>
public sealed class RuleStore : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private static readonly TimeSpan ReloadDebounce = TimeSpan.FromMilliseconds(250);

    private readonly string _filePath;
    private readonly Lock _writeLock = new();
    private readonly FileSystemWatcher? _watcher;
    private readonly Timer _reloadDebounce;

    private volatile Dictionary<string, AppRule> _rules;

    /// <summary>Raised after the file changed underneath us and the new rules have been adopted.</summary>
    public event EventHandler? RulesReloaded;

    public RuleStore(string? filePath = null)
    {
        _filePath = filePath ?? GetDefaultPath();
        _rules = Load() ?? new Dictionary<string, AppRule>();
        _reloadDebounce = new Timer(_ => ReloadFromDisk(), null, Timeout.Infinite, Timeout.Infinite);

        try
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (directory is not null)
            {
                _watcher = new FileSystemWatcher(directory, Path.GetFileName(_filePath))
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    EnableRaisingEvents = true,
                };
                _watcher.Changed += OnFileChanged;
                _watcher.Created += OnFileChanged;
                _watcher.Renamed += OnFileChanged;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Watching is a convenience; without it edits simply need a restart, as before.
            _watcher = null;
        }
    }

    private static string GetDefaultPath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var dir = Path.Combine(appData, "Pointsman");
        Directory.CreateDirectory(dir);

        var path = Path.Combine(dir, "rules.json");
        MigrateFromFormerName(appData, path);
        return path;
    }

    /// <summary>
    /// The program was called NetChooser before, and stored rules under that name. Renaming it
    /// must not silently throw away the assignments an existing user built up, so their file is
    /// carried across the first time the new location is asked for.
    ///
    /// Copied rather than moved, and only when nothing is at the new path yet: if this build is
    /// abandoned and the old one run again, its rules are still where it left them.
    /// </summary>
    private static void MigrateFromFormerName(string appData, string newPath)
    {
        if (File.Exists(newPath))
            return;

        var legacyPath = Path.Combine(appData, "NetChooser", "rules.json");
        if (!File.Exists(legacyPath))
            return;

        try
        {
            File.Copy(legacyPath, newPath);
        }
        catch (IOException)
        {
            // Nothing to do but start empty — losing the old rules is a worse outcome than
            // failing loudly, but not one worth refusing to start over.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    public IReadOnlyList<AppRule> GetAll() => _rules.Values.ToList();

    public AppRule? Get(string executablePath) => _rules.GetValueOrDefault(Normalize(executablePath));

    public void Set(AppRule rule)
    {
        lock (_writeLock)
        {
            var updated = new Dictionary<string, AppRule>(_rules) { [Normalize(rule.ExecutablePath)] = rule };
            _rules = updated;
            Save(updated);
        }
    }

    public void Remove(string executablePath)
    {
        lock (_writeLock)
        {
            var updated = new Dictionary<string, AppRule>(_rules);
            if (!updated.Remove(Normalize(executablePath)))
                return;

            _rules = updated;
            Save(updated);
        }
    }

    private static string Normalize(string path) => path.Trim().ToLowerInvariant();

    // An editor saving a file typically produces several events; collapsing them avoids reparsing
    // once per event, and gives whoever is writing a moment to finish.
    private void OnFileChanged(object sender, FileSystemEventArgs e)
        => _reloadDebounce.Change(ReloadDebounce, Timeout.InfiniteTimeSpan);

    private void ReloadFromDisk()
    {
        var loaded = Load();
        if (loaded is null)
            return; // unreadable or malformed — keep what's already in effect

        lock (_writeLock)
        {
            // Our own Save() trips the watcher too. Rather than juggle a suppression flag against
            // an event that arrives whenever the OS feels like it, just compare: if what's on disk
            // already matches what's in memory, there is nothing to adopt and nobody to notify.
            if (SameRules(_rules, loaded))
                return;

            _rules = loaded;
        }

        RulesReloaded?.Invoke(this, EventArgs.Empty);
    }

    private static bool SameRules(Dictionary<string, AppRule> a, Dictionary<string, AppRule> b)
    {
        if (a.Count != b.Count)
            return false;

        foreach (var (key, left) in a)
        {
            if (!b.TryGetValue(key, out var right)
                || left.AdapterId != right.AdapterId
                || left.Enabled != right.Enabled)
                return false;
        }

        return true;
    }

    /// <summary>Returns null when the file can't be read or parsed, so callers can keep the rules already loaded.</summary>
    private Dictionary<string, AppRule>? Load()
    {
        if (!File.Exists(_filePath))
            return new Dictionary<string, AppRule>();

        // A write in progress briefly locks the file, and a half-written file won't parse; both
        // resolve within milliseconds, so a couple of retries beats discarding the user's rules.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                var json = File.ReadAllText(_filePath);
                var list = JsonSerializer.Deserialize<List<AppRule>>(json, JsonOptions) ?? [];
                return list
                    .Where(r => !string.IsNullOrWhiteSpace(r.ExecutablePath))
                    .GroupBy(r => Normalize(r.ExecutablePath))
                    .ToDictionary(g => g.Key, g => g.Last());
            }
            catch (Exception ex) when (ex is IOException or JsonException)
            {
                Thread.Sleep(40);
            }
        }

        return null;
    }

    private void Save(Dictionary<string, AppRule> rules)
    {
        var json = JsonSerializer.Serialize(rules.Values.ToList(), JsonOptions);
        File.WriteAllText(_filePath, json);
    }

    public void Dispose()
    {
        _watcher?.Dispose();
        _reloadDebounce.Dispose();
    }
}
