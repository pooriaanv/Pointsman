using System.Net;
using Pointsman.Core.Policies;
using Pointsman.Core.Models;
using Pointsman.Core.SystemRouting;
using Pointsman.Core.Settings;
using System.Text.Json;

var checks = 0;
void Assert(bool condition, string name)
{
    checks++;
    if (!condition) throw new Exception($"FAILED: {name}");
}

static DestinationPolicy Route(string selector, DestinationKind kind, string adapterId = "vpn", int priority = 0) => new()
{
    Name = "Route destination", DestinationKind = kind, Destination = selector,
    AdapterId = adapterId, Priority = priority
};
static ConnectionDestination Conn(string ip, string process = "chrome.exe", string? host = null,
    TransportProtocol protocol = TransportProtocol.Tcp, int port = 443) =>
    new(process, null, IPAddress.Parse(ip), port, protocol, host);
var adapters = new[]
{
    new AdapterAvailability("vpn", true, true, false),
    new AdapterAvailability("ethernet", true, true, true),
    new AdapterAvailability("offline", false, true, true)
};

Assert(IpNetwork.TryParse("10.42.0.0/16", out var network), "valid CIDR");
Assert(network.Contains(IPAddress.Parse("10.42.255.254")), "CIDR contains inside address");
Assert(!network.Contains(IPAddress.Parse("10.43.0.1")), "CIDR excludes adjacent subnet");
Assert(IpNetwork.TryParse("2001:db8::/32", out var ipv6), "valid IPv6 CIDR");
Assert(ipv6.Contains(IPAddress.Parse("2001:db8::1234")), "IPv6 CIDR contains prefix");
Assert(!ipv6.Contains(IPAddress.Parse("2001:db9::1")), "IPv6 CIDR excludes other prefix");
Assert(!IpNetwork.TryParse("192.168.0.0/33", out _), "reject oversized prefix");
Assert(!IpNetwork.TryParse("192.168.0.0/-1", out _), "reject negative prefix");
Assert(IpNetwork.TryParse("192.168.9.101/24", out var masked) && masked.ToString() == "192.168.9.0/24",
    "CIDR canonical form");
Assert(!IpAddressLiteral.TryParse("127.1", out _), "reject ambiguous short IPv4");
Assert(!IpAddressLiteral.TryParse("010.0.0.1", out _), "reject ambiguous octal-looking IPv4");

var engine = new PolicyEngine();
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).Kind == RouteDecisionKind.Unmatched,
    "no policy preserves legacy behavior");

var broad = new DestinationPolicy { Name = "Direct", Action = PolicyAction.Direct };
var specific = Route("8.8.8.8", DestinationKind.Ip);
engine.ReplaceRules([broad, specific]);
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).Kind == RouteDecisionKind.Route,
    "exact IP wins over Any at same priority");
Assert(engine.Evaluate(Conn("1.1.1.1"), adapters).Kind == RouteDecisionKind.Direct,
    "Any matches other traffic");

var higher = broad with { Priority = 10 };
engine.ReplaceRules([specific, higher]);
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).Kind == RouteDecisionKind.Direct,
    "explicit higher priority wins over specificity");

var bySubnet = Route("172.16.0.0/12", DestinationKind.Cidr) with
{
    ProcessName = "chrome.exe", Protocol = TransportProtocol.Tcp, FromPort = 443, ToPort = 443
};
engine.ReplaceRules([bySubnet]);
Assert(engine.Evaluate(Conn("172.17.0.4", "chrome", port: 443), adapters).Kind == RouteDecisionKind.Route,
    "matched process executable without extension");
Assert(engine.Evaluate(Conn("172.17.0.4", "firefox.exe"), adapters).Kind == RouteDecisionKind.Unmatched,
    "process filtering");
Assert(engine.Evaluate(Conn("172.17.0.4", port: 80), adapters).Kind == RouteDecisionKind.Unmatched,
    "port filtering");
Assert(engine.Evaluate(Conn("172.17.0.4", protocol: TransportProtocol.Udp), adapters).Kind == RouteDecisionKind.Unmatched,
    "transport filtering");

var domain = Route("example.com", DestinationKind.Domain);
engine.ReplaceRules([domain]);
Assert(engine.Evaluate(Conn("203.0.113.5", host: "example.com"), adapters).Kind == RouteDecisionKind.Route,
    "verified exact hostname matches");
Assert(engine.Evaluate(Conn("203.0.113.5", host: "shop.example.com"), adapters).Kind == RouteDecisionKind.Unmatched,
    "exact hostname does not match subdomain");
Assert(engine.Evaluate(Conn("203.0.113.5"), adapters).Kind == RouteDecisionKind.Unmatched,
    "domain cannot be inferred from arbitrary IP");

var offline = Route("8.8.8.8", DestinationKind.Ip, "offline");
engine.ReplaceRules([offline]);
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).Kind == RouteDecisionKind.Block,
    "offline VPN blocks by default");
engine.ReplaceRules([offline with
{
    WhenUnavailable = UnavailableAdapterAction.TryAlternatives,
    AlternativeAdapterIds = ["ethernet"]
}]);
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).AdapterId == "ethernet",
    "explicit ordered alternatives");
engine.ReplaceRules([offline with { WhenUnavailable = UnavailableAdapterAction.Direct }]);
Assert(engine.Evaluate(Conn("8.8.8.8"), adapters).Kind == RouteDecisionKind.Direct,
    "direct fallback only with explicit policy");

engine.ReplaceRules([Route("2001:db8::1", DestinationKind.Ip, "ethernet")]);
Assert(engine.Evaluate(Conn("2001:db8::1"), adapters).Kind == RouteDecisionKind.Block,
    "IPv6 blocked until underlying driver route implemented");
Assert(PolicyValidation.Validate(Route("not-an-ip", DestinationKind.Ip)).Count > 0,
    "reject invalid IP");
Assert(PolicyValidation.Validate(Route("10.0.0.0/99", DestinationKind.Cidr)).Count > 0,
    "reject invalid subnet");
Assert(PolicyValidation.Validate(Route("*.example.com", DestinationKind.Domain)).Count > 0,
    "reject wildcard with no reliable destination attribution");
try
{
    PolicyValidation.ThrowIfInvalid([
        Route("192.168.9.101/24", DestinationKind.Cidr),
        Route("192.168.9.0/24", DestinationKind.Cidr) with { Action = PolicyAction.Block, AdapterId = null }
    ]);
    throw new Exception("FAILED: duplicate CIDR selectors should be rejected");
}
catch (ArgumentException) { checks++; }
try
{
    engine.ReplaceRules([specific, specific]);
    throw new Exception("FAILED: duplicate IDs should be rejected");
}
catch (ArgumentException) { checks++; }
Assert(engine.Evaluate(Conn("2001:db8::1"), adapters).Kind == RouteDecisionKind.Block,
    "failed rule replacement preserves previous active snapshot");

var directory = Path.Combine(Path.GetTempPath(), "pointsman-policy-test-" + Guid.NewGuid().ToString("N"));
try
{
    var path = Path.Combine(directory, "destination-policies.json");
    var store = new PolicyStore(path);
    var manager = new PolicyManager(store, new PolicyEngine());
    await manager.SaveAsync([specific]);
    Assert(File.Exists(path), "atomic store creates file");
    Assert((await store.LoadAsync()).Single().Destination == "8.8.8.8", "store round-trip");
    using (var json = JsonDocument.Parse(await File.ReadAllTextAsync(path)))
    {
        Assert(json.RootElement.GetProperty("schemaVersion").GetInt32() == 1,
            "versioned destination policies are written to disk");
        Assert(json.RootElement.GetProperty("rules").GetArrayLength() == 1,
            "exactly one rule is persisted to the expected JSON field");
    }
    var restarted = new PolicyManager(new PolicyStore(path), new PolicyEngine());
    await restarted.LoadAsync();
    Assert(restarted.Current.Single().Id == specific.Id, "saved policy survives restart");
    var persistedBeforeInvalid = await File.ReadAllTextAsync(path);
    try
    {
        await manager.SaveAsync([specific with { Destination = "not-an-address" }]);
        throw new Exception("FAILED: invalid policy should not save");
    }
    catch (ArgumentException) { checks++; }
    Assert(await File.ReadAllTextAsync(path) == persistedBeforeInvalid,
        "rejected policy does not overwrite previous JSON");
    Assert(manager.Current.Single().Id == specific.Id,
        "rejected policy does not replace active rules");

    var settingsPath = Path.Combine(directory, "settings.json");
    var settings = new SettingsStore(settingsPath);
    settings.Update(current => current with { AutoInstallUpdates = true });
    Assert(File.Exists(settingsPath), "application settings file exists after save");
    Assert(new SettingsStore(settingsPath).Current.AutoInstallUpdates,
        "application settings survive restart");
    await File.WriteAllTextAsync(path, "{\"schemaVersion\":1}");
    try { await store.LoadAsync(); throw new Exception("FAILED: missing rules must not load"); }
    catch (InvalidDataException) { checks++; }
    await File.WriteAllTextAsync(path, "{ broken json");
    try
    {
        await manager.LoadAsync();
        throw new Exception("FAILED: corrupt config must be rejected");
    }
    catch (System.Text.Json.JsonException) { checks++; }
    Assert(manager.Current.Single().Id == specific.Id, "corrupt load leaves active policy intact");
}
finally
{
    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
}

// Windows system routes are explicit, machine-wide, and require IPv4 global selectors.
var ethernetNic = new NetworkAdapterInfo
{
    Id = "ethernet", Name = "Ethernet", Description = "LAN", Kind = AdapterKind.Ethernet,
    IsUp = true, IPv4Address = "192.168.3.10", IPv4PrefixLength = 24,
    IPv4InterfaceIndex = 12, IPv4DefaultGateway = "192.168.3.1",
};
var lanPolicy = Route("192.168.3.2", DestinationKind.Ip, "ethernet", priority: 1000) with
{
    Name = "LAN bypass", UseSystemRoute = true
};
var localPlan = SystemRoutePlanner.Build([lanPolicy], [ethernetNic], true);
Assert(localPlan.Count == 1 && localPlan[0] == new WindowsRoute("192.168.3.2/32", 12, "0.0.0.0"),
    "global LAN IP is routed on-link through selected interface");
engine.ReplaceRules([lanPolicy]);
Assert(engine.Evaluate(Conn("192.168.3.2"), adapters).Kind == RouteDecisionKind.Direct,
    "global Windows route is not transparently proxied a second time");
// Packet interception is an opt-in implementation detail: a system-route-only
// configuration must never divert the rest of the machine's internet traffic.
Assert(!PacketInterceptionPlanner.Build([lanPolicy], []).Required,
    "system-route-only configuration never starts WinDivert packet interception");
Assert(!PacketInterceptionPlanner.Build([], []).Required,
    "empty policy configuration leaves all Windows traffic untouched");
Assert(!PacketInterceptionPlanner.Build([Route("192.168.3.2", DestinationKind.Ip) with { Enabled = false }], []).Required,
    "disabled packet rules do not open a network capture");
Assert(!PacketInterceptionPlanner.Build([new DestinationPolicy { Name = "Direct all", Action = PolicyAction.Direct }], []).Required,
    "Direct-only policy without per-app rules needs no packet capture");
var narrowed = PacketInterceptionPlanner.Build([lanPolicy with { UseSystemRoute = false }], []);
Assert(narrowed.Required && narrowed.Filter.Contains("ip.DstAddr == 192.168.3.2", StringComparison.Ordinal) &&
       !narrowed.Filter.Contains("not loopback", StringComparison.Ordinal),
    "exact-IP packet policy only captures its destination and relay loopback");
Assert(!narrowed.Filter.Contains("8.8.8.8", StringComparison.Ordinal),
    "unrelated internet destinations are not selected in exact-IP WinDivert filter");
var narrowedWithRelays = PacketInterceptionPlanner.Build(
    [lanPolicy with { UseSystemRoute = false }], [], [53121], [53122]);
Assert(narrowedWithRelays.Filter.Contains("tcp.SrcPort == 53121", StringComparison.Ordinal) &&
       narrowedWithRelays.Filter.Contains("udp.SrcPort == 53122", StringComparison.Ordinal),
    "only relay reply ports are captured on loopback");
Assert(!narrowedWithRelays.Filter.Contains("or loopback", StringComparison.Ordinal),
    "the debugger's unrelated loopback sockets are not intercepted");
var withOther = PacketInterceptionPlanner.Build([lanPolicy, Route("8.8.8.8", DestinationKind.Ip)], []);
Assert(withOther.Required && withOther.Filter.Contains("ip.DstAddr == 8.8.8.8", StringComparison.Ordinal) &&
       !withOther.Filter.Contains("192.168.3.2", StringComparison.Ordinal),
    "system routes are excluded from packet capture even alongside packet rules");
Assert(PacketInterceptionPlanner.Build([lanPolicy], [new AppRule {
        ExecutablePath = @"C:\Program Files\Browser\browser.exe", AdapterId = "vpn", Enabled = true
    }]).Filter.Contains("not loopback", StringComparison.Ordinal),
    "legacy per-app routing needs non-loopback capture because WinDivert has no network-layer PID");
Assert(!PacketInterceptionPlanner.Build([lanPolicy], [new AppRule {
        ExecutablePath = @"C:\Program Files\Browser\browser.exe", AdapterId = "vpn", Enabled = false
    }]).Required,
    "disabled legacy rules must not turn packet interception on");
var legacyWithRelays = PacketInterceptionPlanner.Build([lanPolicy], [new AppRule {
        ExecutablePath = @"C:\Tools\App.exe", AdapterId = "ethernet", Enabled = true
    }], [53121], [53122]);
Assert(legacyWithRelays.Filter.Contains("not loopback", StringComparison.Ordinal) &&
       legacyWithRelays.Filter.Contains("tcp.SrcPort == 53121", StringComparison.Ordinal) &&
       !legacyWithRelays.Filter.Contains("or loopback", StringComparison.Ordinal),
    "per-app filter avoids unrelated loopback debugger connections");
var cidrPlan = PacketInterceptionPlanner.Build([Route("10.1.0.0/16", DestinationKind.Cidr)], []);
Assert(cidrPlan.Required && cidrPlan.Filter.Contains("not loopback", StringComparison.Ordinal),
    "CIDR rules continue using the generic outbound filter");

var remotePolicy = lanPolicy with { Destination = "10.7.0.2" };
var remotePlan = SystemRoutePlanner.Build([remotePolicy], [ethernetNic], true);
Assert(remotePlan[0].NextHop == "192.168.3.1", "off-link route uses adapter gateway");
Assert(SystemRoutePlanner.Build([remotePolicy with { SystemNextHop = "192.168.3.254" }],
    [ethernetNic], true)[0].NextHop == "192.168.3.254", "explicit gateway overrides discovery");
Assert(PolicyValidation.Validate(lanPolicy with { ProcessName = "chrome.exe" }).Count > 0,
    "process-specific rules cannot change machine-wide routing");
Assert(PolicyValidation.Validate(lanPolicy with { DestinationKind = DestinationKind.Domain, Destination = "example.com" }).Count > 0,
    "a DNS rule cannot install a system route");
Assert(PolicyValidation.Validate(lanPolicy with { DestinationKind = DestinationKind.Cidr, Destination = "0.0.0.0/0" }).Count > 0,
    "system route rejects default gateway takeover");
Assert(PolicyValidation.Validate(lanPolicy with { FromPort = 443, ToPort = 443 }).Count > 0,
    "machine-wide route cannot masquerade as port-specific route");
Assert(PolicyValidation.Validate(lanPolicy with { SystemNextHop = "not an IP" }).Count > 0,
    "invalid manual gateway is rejected");
try
{
    SystemRoutePlanner.Build([lanPolicy, lanPolicy with { Id = Guid.NewGuid(), AdapterId = "vpn" }],
        [ethernetNic, new NetworkAdapterInfo
        {
            Id = "vpn", Name = "VPN", Description = "VPN", Kind = AdapterKind.Vpn,
            IsUp = true, IPv4Address = "10.0.0.5", IPv4PrefixLength = 24,
            IPv4InterfaceIndex = 20, IPv4DefaultGateway = "10.0.0.1"
        }], true);
    throw new Exception("FAILED: conflicting system prefixes should fail");
}
catch (ArgumentException) { checks++; }

var routesFolder = Path.Combine(Path.GetTempPath(), "pointsman-windows-route-test-" + Guid.NewGuid().ToString("N"));
try
{
    var journal = Path.Combine(routesFolder, "owned-routes.json");
    var fakeCommands = new FakeWindowsRouteCommands();
    var routeManager = new WindowsSystemRouteManager(fakeCommands, journal);
    routeManager.SetLoadedRules([lanPolicy]);
    await routeManager.UpdateAdaptersAsync([ethernetNic]);
    Assert(fakeCommands.Present.Contains(localPlan[0]), "manager installs requested route");
    Assert(File.Exists(journal), "owned system route is journaled");
    await routeManager.UpdateAdaptersAsync([ethernetNic]);
    Assert(fakeCommands.Created == 1, "repeated adapter refresh is idempotent");
    fakeCommands.FailForPrefix = remotePlan[0].DestinationPrefix;
    try
    {
        await routeManager.ApplyAsync([remotePolicy]);
        throw new Exception("FAILED: system route creation error must propagate");
    }
    catch (IOException) { checks++; }
    Assert(fakeCommands.Present.SetEquals(localPlan),
        "failed route installation keeps previously owned Windows route");
    fakeCommands.FailForPrefix = null;
    await routeManager.ApplyAsync([remotePolicy]);
    Assert(fakeCommands.Present.SetEquals(remotePlan), "edit replaces old system route");
    await routeManager.DisposeAsync();
    Assert(fakeCommands.Present.Count == 0, "owned routes are removed on normal exit");
    var afterRestart = new WindowsSystemRouteManager(fakeCommands, journal);
    afterRestart.SetLoadedRules([]);
    await afterRestart.UpdateAdaptersAsync([ethernetNic]);
    Assert(fakeCommands.Present.Count == 0, "empty route journal is safe after restart");
    await afterRestart.DisposeAsync();
}
finally
{
    if (Directory.Exists(routesFolder)) Directory.Delete(routesFolder, recursive: true);
}

Console.WriteLine($"PASS: {checks} policy self-tests");

sealed class FakeWindowsRouteCommands : IWindowsRouteCommands
{
    public HashSet<WindowsRoute> Present { get; } = [];
    public int Created { get; private set; }
    public string? FailForPrefix { get; set; }

    public Task<RouteInstallResult> EnsureAsync(WindowsRoute route, CancellationToken cancellationToken)
    {
        if (string.Equals(FailForPrefix, route.DestinationPrefix, StringComparison.Ordinal))
            throw new IOException("Simulated route command failure");
        if (Present.Add(route))
        {
            Created++;
            return Task.FromResult(RouteInstallResult.Created);
        }
        return Task.FromResult(RouteInstallResult.AlreadyPresent);
    }

    public Task RemoveAsync(WindowsRoute route, CancellationToken cancellationToken)
    {
        Present.Remove(route);
        return Task.CompletedTask;
    }
}

