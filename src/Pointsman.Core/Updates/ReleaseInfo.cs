namespace Pointsman.Core.Updates;

/// <summary>A published GitHub release that is newer than the running program.</summary>
public sealed record ReleaseInfo(
    AppVersion Version,
    string TagName,
    string PageUrl,
    string Notes,
    bool IsCritical,
    ReleaseAsset? Installer,
    ReleaseAsset? Checksums);

public sealed record ReleaseAsset(string Name, string DownloadUrl, long Size);
