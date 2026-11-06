using System.Reflection;

namespace Pointsman.Core.Updates;

/// <summary>
/// A release version as Pointsman uses it: <c>major.minor.patch</c>, optionally followed by a
/// pre-release label (<c>0.2.0-beta.1</c>). Tags carry a leading <c>v</c>, which is accepted and
/// ignored. Anything after <c>+</c> is build metadata — the SDK appends the commit hash there —
/// and plays no part in ordering.
/// </summary>
public sealed record AppVersion(Version Number, string? Label) : IComparable<AppVersion>
{
    /// <summary>A build made without a version from CI, i.e. on a developer's machine.</summary>
    public bool IsDevelopmentBuild =>
        Label is not null && Label.StartsWith("dev", StringComparison.OrdinalIgnoreCase);

    public static bool TryParse(string? text, out AppVersion version)
    {
        version = null!;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var s = text.Trim();
        if (s.StartsWith('v') || s.StartsWith('V'))
            s = s[1..];

        var plus = s.IndexOf('+');
        if (plus >= 0)
            s = s[..plus];

        string? label = null;
        var dash = s.IndexOf('-');
        if (dash >= 0)
        {
            label = s[(dash + 1)..];
            s = s[..dash];
            if (label.Length == 0)
                label = null;
        }

        if (!Version.TryParse(s, out var number))
            return false;

        // Version treats "0.1" and "0.1.0" as different (Build -1 vs 0); normalise so a tag
        // written either way compares equal.
        number = new Version(number.Major, number.Minor, Math.Max(number.Build, 0));
        version = new AppVersion(number, label);
        return true;
    }

    /// <summary>
    /// The version of the running program, as stamped by <c>-p:Version=</c> at publish time.
    /// <c>POINTSMAN_UPDATE_TEST_VERSION</c> overrides it, so the updater can be exercised from a
    /// development build by pretending to be an older release.
    /// </summary>
    public static AppVersion Current()
    {
        var overridden = Environment.GetEnvironmentVariable("POINTSMAN_UPDATE_TEST_VERSION");
        if (TryParse(overridden, out var fake))
            return fake;

        var assembly = Assembly.GetEntryAssembly() ?? typeof(AppVersion).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (TryParse(informational, out var v))
            return v;

        return new AppVersion(new Version(0, 0, 0), "dev");
    }

    public int CompareTo(AppVersion? other)
    {
        if (other is null)
            return 1;

        var byNumber = Number.CompareTo(other.Number);
        if (byNumber != 0)
            return byNumber;

        // Same number: a release outranks any pre-release of it (0.2.0 > 0.2.0-beta).
        return (Label, other.Label) switch
        {
            (null, null) => 0,
            (null, _) => 1,
            (_, null) => -1,
            _ => string.Compare(Label, other.Label, StringComparison.OrdinalIgnoreCase),
        };
    }

    public static bool operator >(AppVersion a, AppVersion b) => a.CompareTo(b) > 0;
    public static bool operator <(AppVersion a, AppVersion b) => a.CompareTo(b) < 0;

    public override string ToString() =>
        Label is null ? Number.ToString(3) : $"{Number.ToString(3)}-{Label}";
}
