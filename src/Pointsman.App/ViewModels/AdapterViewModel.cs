using Pointsman.Core.Models;

namespace Pointsman.App.ViewModels;

public sealed class AdapterViewModel(NetworkAdapterInfo info, int? proxyPort) : ViewModelBase
{
    public NetworkAdapterInfo Info { get; } = info;

    public string Id => Info.Id;
    public string Name => Info.Name;
    public bool IsUp => Info.IsUp;
    public string? IPv4Address => Info.IPv4Address;
    public AdapterKind Kind => Info.Kind;

    public string KindIcon => Kind switch
    {
        AdapterKind.WiFi => "📶",
        AdapterKind.Ethernet => "🔌",
        AdapterKind.Vpn => "🛡️",
        _ => "❓",
    };

    public string StatusText => IsUp
        ? $"Connected — {IPv4Address}"
        : "Disconnected";

    public int? ProxyPort { get; } = proxyPort;

    /// <summary>
    /// The engine keeps one local endpoint per connected adapter and routes redirected apps
    /// through it. Nothing to configure — the port is shown because it doubles as a plain SOCKS5
    /// proxy, which is handy for pointing a single app at an adapter by hand or for debugging.
    /// </summary>
    public string ProxyText => ProxyPort is int port
        ? $"Routing active · SOCKS5 127.0.0.1:{port}"
        : "Not routable — no IPv4 address";
}

/// <summary>Represents a selectable choice in an app's adapter dropdown ("Automatic" or a real adapter).</summary>
public sealed class AdapterChoiceViewModel(string? adapterId, string label, int? proxyPort)
{
    public static readonly AdapterChoiceViewModel Automatic = new(null, "Automatic (System)", null);

    public string? AdapterId { get; } = adapterId;
    public string Label { get; } = label;
    public int? ProxyPort { get; } = proxyPort;

    public override string ToString() => Label;

    public override bool Equals(object? obj) =>
        obj is AdapterChoiceViewModel other && other.AdapterId == AdapterId;

    public override int GetHashCode() => AdapterId?.GetHashCode() ?? 0;
}
