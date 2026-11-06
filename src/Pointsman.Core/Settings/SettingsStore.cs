using System.Text.Json;

namespace Pointsman.Core.Settings;

/// <summary>
/// Program preferences, kept apart from the rules: rules are the user's routing data and are
/// asked about on uninstall, while these are just how the program behaves.
/// </summary>
public sealed record AppSettings
{
    /// <summary>
    /// Download and install every new release without asking. Off by default: an update restarts
    /// Pointsman, which briefly interrupts every routed connection, so it should be the user's
    /// choice. Critical releases are installed regardless; see docs/RELEASING.md.
    /// </summary>
    public bool AutoInstallUpdates { get; init; }
}

/// <summary>
/// Reads and writes <see cref="AppSettings"/> as <c>%AppData%\Pointsman\settings.json</c>.
///
/// Unlike the rules file this is not watched: nothing but the settings window changes it, and a
/// missing or unreadable file just means the defaults, never a reason to refuse to start.
/// </summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _filePath;
    private readonly Lock _lock = new();
    private AppSettings _current;

    public event EventHandler<AppSettings>? Changed;

    public SettingsStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Pointsman", "settings.json");
        _current = Load();
    }

    public AppSettings Current => _current;

    public void Update(Func<AppSettings, AppSettings> change)
    {
        AppSettings updated;
        lock (_lock)
        {
            updated = change(_current);
            if (updated == _current)
                return;

            _current = updated;
            Save(updated);
        }

        Changed?.Invoke(this, updated);
    }

    private AppSettings Load()
    {
        try
        {
            if (File.Exists(_filePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_filePath), JsonOptions) ?? new();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
        }

        return new AppSettings();
    }

    private void Save(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            File.WriteAllText(_filePath, JsonSerializer.Serialize(settings, JsonOptions));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The change still holds for this session; it just won't survive a restart.
        }
    }
}
