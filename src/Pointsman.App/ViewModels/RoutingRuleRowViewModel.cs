using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.App.ViewModels;

/// <summary>Read-only presentation of a routing policy; editing keeps the original Id.</summary>
public sealed class RoutingRuleRowViewModel
{
    public DestinationPolicy Policy { get; }
    public string Name => Policy.Name;
    public bool Enabled => Policy.Enabled;
    public int Priority => Policy.Priority;
    public string Process => Policy.ProcessPath ?? Policy.ProcessName;
    public string Destination => Policy.DestinationKind switch
    {
        DestinationKind.Any => "All destinations",
        _ => $"{Policy.DestinationKind}: {Policy.Destination}",
    };
    public string Transport => Policy.Protocol.ToString();
    public string Ports => Policy.FromPort is int from ? $"{from}-{Policy.ToPort}" : "Any";
    public string Route { get; }
    public string Mode => Policy.UseSystemRoute ? "Windows (all apps)" : "Relay (TCP/UDP)";
    public string OnUnavailable => Policy.Action == PolicyAction.Route
        ? Policy.WhenUnavailable.ToString() : "-";

    public RoutingRuleRowViewModel(DestinationPolicy policy, IEnumerable<NetworkAdapterInfo> adapters)
    {
        Policy = policy;
        var byId = adapters.ToDictionary(a => a.Id, a => a.Name, StringComparer.OrdinalIgnoreCase);
        Route = policy.Action switch
        {
            PolicyAction.Block => "Block",
            PolicyAction.Direct => "System default",
            PolicyAction.Route when policy.AdapterId is string id =>
                byId.TryGetValue(id, out var name) ? name : $"Unavailable ({id})",
            _ => "Invalid",
        };
    }
}
