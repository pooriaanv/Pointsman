using System.Globalization;
using Pointsman.Core.Models;
using Pointsman.Core.Policies;

namespace Pointsman.App.ViewModels;

/// <summary>UI input only; validation and normalization live in the policy domain.</summary>
public sealed class RoutingRuleEditorViewModel
{
    private readonly Guid _id;

    public string Name { get; set; }
    public bool Enabled { get; set; }
    public string PriorityText { get; set; }
    public string ProcessName { get; set; }
    public string ProcessPath { get; set; }
    public DestinationKind DestinationKind { get; set; }
    public string Destination { get; set; }
    public TransportProtocol Protocol { get; set; }
    public string FromPortText { get; set; }
    public string ToPortText { get; set; }
    public PolicyAction Action { get; set; }
    public string? AdapterId { get; set; }
    public bool UseSystemRoute { get; set; }
    public string SystemNextHop { get; set; }
    public UnavailableAdapterAction WhenUnavailable { get; set; }
    public string? FirstFallbackAdapterId { get; set; }
    public string AlternativeAdapterIdsText { get; set; }

    public IReadOnlyList<AdapterChoiceViewModel> AdapterChoices { get; }
    public IReadOnlyList<DestinationKind> Destinations { get; } = Enum.GetValues<DestinationKind>();
    public IReadOnlyList<TransportProtocol> Protocols { get; } = Enum.GetValues<TransportProtocol>();
    public IReadOnlyList<PolicyAction> Actions { get; } = Enum.GetValues<PolicyAction>();
    public IReadOnlyList<UnavailableAdapterAction> FallbackActions { get; } =
        Enum.GetValues<UnavailableAdapterAction>();

    public RoutingRuleEditorViewModel(DestinationPolicy policy, IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        _id = policy.Id;
        Name = policy.Name;
        Enabled = policy.Enabled;
        PriorityText = policy.Priority.ToString(CultureInfo.InvariantCulture);
        ProcessName = policy.ProcessName;
        ProcessPath = policy.ProcessPath ?? "";
        DestinationKind = policy.DestinationKind;
        Destination = policy.Destination ?? "";
        Protocol = policy.Protocol;
        FromPortText = policy.FromPort?.ToString(CultureInfo.InvariantCulture) ?? "";
        ToPortText = policy.ToPort?.ToString(CultureInfo.InvariantCulture) ?? "";
        Action = policy.Action;
        AdapterId = policy.AdapterId;
        UseSystemRoute = policy.UseSystemRoute;
        SystemNextHop = policy.SystemNextHop ?? "";
        WhenUnavailable = policy.WhenUnavailable;
        FirstFallbackAdapterId = policy.AlternativeAdapterIds.FirstOrDefault();
        AlternativeAdapterIdsText = string.Join(", ", policy.AlternativeAdapterIds.Skip(1));

        var choices = adapters.Select(a => new AdapterChoiceViewModel(a.Id,
            $"{a.Kind}: {a.Name} ({(a.IsUp ? a.IPv4Address ?? "no IPv4" : "disconnected")}) — {a.Id}", null)).ToList();
        foreach (var missingId in policy.AlternativeAdapterIds.Prepend(policy.AdapterId)
            .Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id!))
        {
            if (!choices.Any(a => string.Equals(a.AdapterId, missingId, StringComparison.OrdinalIgnoreCase)))
                choices.Add(new AdapterChoiceViewModel(missingId, $"Missing adapter — {missingId}", null));
        }
        AdapterChoices = choices;
    }

    public DestinationPolicy Build()
    {
        if (!int.TryParse(PriorityText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var priority))
            throw new ArgumentException("Priority must be a whole number");

        static int? ParsePort(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
                throw new ArgumentException("Ports must be whole numbers from 1 to 65535");
            return port;
        }

        string[] fallback = [];
        if (Action == PolicyAction.Route && WhenUnavailable == UnavailableAdapterAction.TryAlternatives)
        {
            var selected = string.IsNullOrWhiteSpace(FirstFallbackAdapterId)
                ? Array.Empty<string>()
                : new[] { FirstFallbackAdapterId! };
            fallback = [.. selected, .. AlternativeAdapterIdsText.Split(',',
                StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)];
        }

        var candidate = new DestinationPolicy
        {
            Id = _id,
            Name = Name.Trim(),
            Enabled = Enabled,
            Priority = priority,
            ProcessName = ProcessName.Trim(),
            ProcessPath = string.IsNullOrWhiteSpace(ProcessPath) ? null : ProcessPath.Trim(),
            DestinationKind = DestinationKind,
            Destination = DestinationKind == DestinationKind.Any ? null : Destination.Trim(),
            Protocol = Protocol,
            FromPort = ParsePort(FromPortText),
            ToPort = ParsePort(ToPortText),
            Action = Action,
            AdapterId = Action == PolicyAction.Route ? AdapterId : null,
            UseSystemRoute = Action == PolicyAction.Route && UseSystemRoute,
            SystemNextHop = Action == PolicyAction.Route && UseSystemRoute &&
                !string.IsNullOrWhiteSpace(SystemNextHop) ? SystemNextHop.Trim() : null,
            WhenUnavailable = Action == PolicyAction.Route ? WhenUnavailable : UnavailableAdapterAction.Block,
            AlternativeAdapterIds = fallback,
        };

        var errors = PolicyValidation.Validate(candidate);
        if (errors.Count != 0)
            throw new ArgumentException(string.Join(Environment.NewLine, errors));
        return candidate;
    }
}
