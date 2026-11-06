using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Windows.Threading;
using Pointsman.Core.Settings;
using Pointsman.Core.Updates;

namespace Pointsman.App.ViewModels;

/// <summary>
/// Looks for a newer release on GitHub and drives the banner that offers it.
///
/// Checks shortly after startup and then every few hours, since Pointsman mostly lives in the
/// tray and may run for weeks. A failed check is silent: an offline machine or a GitHub hiccup is
/// not something the user can act on, and the next check will try again.
///
/// A release is installed without being asked for when the user turned on automatic updates, or
/// when the release is marked critical (docs/RELEASING.md). Either way the installer is
/// downloaded and verified first, then a countdown gives warning before Pointsman restarts:
/// restarting drops every routed connection, and someone mid-call deserves a minute's notice.
/// Only an automatic update can be postponed from the countdown; a critical one can only be
/// brought forward.
/// </summary>
public sealed class UpdateViewModel : ViewModelBase, IDisposable
{
    private static readonly TimeSpan FirstCheckDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private const int CountdownLength = 60;

    private readonly SettingsStore _settings;
    private readonly HttpClient _http = UpdateChecker.CreateHttpClient();
    private readonly UpdateChecker _checker;
    private readonly UpdateDownloader _downloader;
    private readonly DispatcherTimer _checkTimer;
    private readonly DispatcherTimer _countdownTimer;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly AppVersion _current = AppVersion.Current();

    private ReleaseInfo? _release;
    private string? _installerPath;       // verified installer for _release, once downloaded
    private string? _announcedTag;        // release already shown to the user this session
    private string? _postponedTag;        // automatic install the user said "not now" to
    private bool _isBannerVisible;
    private bool _isDownloading;
    private bool _isCountingDown;
    private int _secondsLeft;
    private double _progress;
    private string? _errorText;

    /// <summary>A newer release was found that the user has not been told about yet this session.</summary>
    public event EventHandler<ReleaseInfo>? ReleaseFound;

    /// <summary>The installer is downloaded and Pointsman will restart when the countdown ends.</summary>
    public event EventHandler<ReleaseInfo>? CountdownStarted;

    /// <summary>
    /// The verified installer is on disk and the program should hand over to it: start it, then
    /// close down properly so the driver is released before setup replaces it.
    /// </summary>
    public event EventHandler<string>? InstallerReady;

    public UpdateViewModel(SettingsStore settings)
    {
        _settings = settings;
        _checker = new UpdateChecker(_http);
        _downloader = new UpdateDownloader(_http);

        UpdateCommand = new RelayCommand(_ => _ = InstallAsync(automatic: false),
            _ => _release is not null && !_isDownloading);
        DismissCommand = new RelayCommand(_ => Dismiss(), _ => !_isDownloading && CanPostpone);
        ViewReleaseCommand = new RelayCommand(_ => OpenReleasePage());

        _checkTimer = new DispatcherTimer { Interval = FirstCheckDelay };
        _checkTimer.Tick += async (_, _) =>
        {
            _checkTimer.Interval = CheckInterval;
            await CheckAsync();
        };

        _countdownTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _countdownTimer.Tick += (_, _) =>
        {
            SecondsLeft--;
            if (SecondsLeft <= 0)
                HandOver();
        };

        // Turning automatic updates on while a release is waiting should act on it now, not in
        // six hours at the next check.
        _settings.Changed += (_, s) =>
        {
            if (s.AutoInstallUpdates && _release is not null)
                _ = MaybeInstallAutomaticallyAsync();
        };
    }

    /// <summary>
    /// Installed copies have the Inno Setup uninstaller beside them; the portable zip does not,
    /// and running the installer over it would create a second copy in Program Files rather than
    /// update the one in use. Portable users are sent to the release page instead.
    /// </summary>
    public static bool IsInstalledCopy =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, "unins000.exe"));

    public bool IsEnabled => !_current.IsDevelopmentBuild;

    public RelayCommand UpdateCommand { get; }
    public RelayCommand DismissCommand { get; }
    public RelayCommand ViewReleaseCommand { get; }

    public ReleaseInfo? Release => _release;

    public bool IsBannerVisible
    {
        get => _isBannerVisible;
        private set => SetField(ref _isBannerVisible, value);
    }

    public bool IsDownloading
    {
        get => _isDownloading;
        private set
        {
            if (SetField(ref _isDownloading, value))
                RaiseTextChanged();
        }
    }

    public bool IsCountingDown
    {
        get => _isCountingDown;
        private set
        {
            if (SetField(ref _isCountingDown, value))
                RaiseTextChanged();
        }
    }

    public int SecondsLeft
    {
        get => _secondsLeft;
        private set
        {
            if (SetField(ref _secondsLeft, value))
                OnPropertyChanged(nameof(Detail));
        }
    }

    /// <summary>A critical release can be installed early but not put off.</summary>
    public bool CanPostpone => _release is not { IsCritical: true } || !IsInstalledCopy;

    /// <summary>0–100.</summary>
    public double Progress
    {
        get => _progress;
        private set => SetField(ref _progress, value);
    }

    public string? ErrorText
    {
        get => _errorText;
        private set
        {
            if (SetField(ref _errorText, value))
                OnPropertyChanged(nameof(HasError));
        }
    }

    public bool HasError => _errorText is not null;

    public string Title => _release is null ? "" :
        _release.IsCritical
            ? $"Important update: Pointsman {_release.Version}"
            : $"Pointsman {_release.Version} is available";

    public string Detail
    {
        get
        {
            if (_release is null)
                return "";
            if (!IsInstalledCopy)
                return $"You have {_current}. This is a portable copy: download the new version and replace this folder.";
            if (IsCountingDown)
                return $"Pointsman will restart to install it in {SecondsLeft} s. Routed connections drop briefly while it does.";
            if (IsDownloading)
                return _release.IsCritical
                    ? "This update fixes a serious problem and is being installed automatically."
                    : "Downloading the update…";
            return $"You have {_current}. Updating restarts Pointsman, which briefly interrupts routed connections.";
        }
    }

    public string ActionText =>
        IsDownloading ? "Downloading…"
        : IsCountingDown ? "Restart now"
        : IsInstalledCopy ? "Update now"
        : "Download";

    public string DismissText => IsCountingDown ? "Not now" : "Later";

    public void Start()
    {
        if (IsEnabled)
            _checkTimer.Start();
    }

    /// <summary>Whether this release will install on its own, without the user choosing Update.</summary>
    public bool WillInstallAutomatically(ReleaseInfo release) =>
        IsInstalledCopy
        && (release.IsCritical || (_settings.Current.AutoInstallUpdates && _postponedTag != release.TagName));

    public async Task CheckAsync()
    {
        if (!IsEnabled || _isDownloading || _isCountingDown)
            return;

        ReleaseInfo? found;
        try
        {
            found = await _checker.CheckAsync(_current, _shutdown.Token);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                                       or System.Text.Json.JsonException or InvalidOperationException
                                       or KeyNotFoundException)
        {
            return;
        }

        if (found is null)
            return;

        // A newer release replaces the one we were holding, along with anything downloaded for it.
        // Comparing by record equality would also catch a release whose notes were edited to mark
        // it critical after it was first seen.
        if (_release != found)
        {
            if (_release?.TagName != found.TagName)
                _installerPath = null;
            _release = found;
            OnPropertyChanged(nameof(Release));
            OnPropertyChanged(nameof(CanPostpone));
            RaiseTextChanged();
        }

        // Announce each release once per session: the six-hourly check must not keep popping
        // up a notification the user already dismissed.
        if (_announcedTag != found.TagName)
        {
            _announcedTag = found.TagName;
            ErrorText = null;
            IsBannerVisible = true;
            ReleaseFound?.Invoke(this, found);
        }

        // Retried on every check, so a critical update that failed to download — offline, say —
        // still goes in once the network is back.
        await MaybeInstallAutomaticallyAsync();
    }

    private Task MaybeInstallAutomaticallyAsync()
    {
        if (_release is null || _isDownloading || _isCountingDown || !WillInstallAutomatically(_release))
            return Task.CompletedTask;

        return InstallAsync(automatic: true);
    }

    /// <param name="automatic">
    /// True when nobody asked for it: downloads, then counts down before restarting. False when the
    /// user chose Update (or Restart now during a countdown): restarts as soon as the file is ready.
    /// </param>
    public async Task InstallAsync(bool automatic)
    {
        if (_release is null || _isDownloading)
            return;

        if (!IsInstalledCopy)
        {
            OpenReleasePage();
            return;
        }

        if (IsCountingDown)
        {
            HandOver();
            return;
        }

        var release = _release;
        if (_installerPath is null || !File.Exists(_installerPath))
        {
            IsBannerVisible = true;
            IsDownloading = true;
            ErrorText = null;
            Progress = 0;
            try
            {
                var progress = new Progress<double>(p => Progress = p * 100);
                _installerPath = await _downloader.DownloadAsync(release, progress, _shutdown.Token);
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException
                                           or InvalidOperationException or TaskCanceledException
                                           or UnauthorizedAccessException)
            {
                ErrorText = automatic
                    ? $"Automatic update failed, will try again later: {ex.Message}"
                    : $"Update failed: {ex.Message}";
                IsBannerVisible = true;
                return;
            }
            finally
            {
                IsDownloading = false;
            }

            // A newer release may have turned up while this one was downloading.
            if (_release != release)
                return;
        }

        if (automatic)
            StartCountdown();
        else
            HandOver();
    }

    private void StartCountdown()
    {
        SecondsLeft = CountdownLength;
        IsCountingDown = true;
        IsBannerVisible = true;
        _countdownTimer.Start();
        CountdownStarted?.Invoke(this, _release!);
    }

    private void StopCountdown()
    {
        _countdownTimer.Stop();
        IsCountingDown = false;
    }

    private void HandOver()
    {
        StopCountdown();
        if (_installerPath is { } path && File.Exists(path))
            InstallerReady?.Invoke(this, path);
    }

    private void Dismiss()
    {
        if (IsCountingDown)
        {
            // Postpones this release for the rest of the session; Update still installs it.
            StopCountdown();
            _postponedTag = _release?.TagName;
        }

        IsBannerVisible = false;
    }

    private void RaiseTextChanged()
    {
        // RelayCommand re-evaluates CanExecute only when WPF suggests it, which it does on input.
        // State changed here by a download finishing would otherwise leave buttons greyed out
        // until the mouse next moved over the window.
        System.Windows.Input.CommandManager.InvalidateRequerySuggested();

        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Detail));
        OnPropertyChanged(nameof(ActionText));
        OnPropertyChanged(nameof(DismissText));
    }

    /// <summary>
    /// Starts the installer. Pointsman runs elevated, and the child inherits that, so there is no
    /// second UAC prompt. <c>/SILENT</c> shows setup's progress but skips the wizard pages;
    /// <c>/RELAUNCH</c> is our own switch, read by Pointsman.iss, to start the new version after.
    /// </summary>
    public static void LaunchInstaller(string installerPath)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = "/SILENT /SUPPRESSMSGBOXES /NORESTART /RELAUNCH",
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(installerPath),
        });
    }

    private void OpenReleasePage()
    {
        var url = _release?.PageUrl is { Length: > 0 } page
            ? page
            : $"https://github.com/{UpdateChecker.Repository}/releases/latest";
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    public void Dispose()
    {
        _checkTimer.Stop();
        _countdownTimer.Stop();
        _shutdown.Cancel();
        _http.Dispose();
        _shutdown.Dispose();
    }
}
