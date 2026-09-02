namespace Pointsman.Core.Models;

public sealed class AppRule
{
    public required string ExecutablePath { get; init; }

    /// <summary>Adapter Id (NetworkInterface.Id) the app should egress through. Null = system default / no rule.</summary>
    public string? AdapterId { get; set; }

    public bool Enabled { get; set; } = true;
}
