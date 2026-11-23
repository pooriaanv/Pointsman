using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Pointsman.Core.SystemRouting;

public enum RouteInstallResult { Created, AlreadyPresent }

/// <summary>OS command boundary; injected in self-tests to avoid changing the test machine's routes.</summary>
public interface IWindowsRouteCommands
{
    Task<RouteInstallResult> EnsureAsync(WindowsRoute route, CancellationToken cancellationToken);
    Task RemoveAsync(WindowsRoute route, CancellationToken cancellationToken);
}

/// <summary>
/// Uses built-in Windows NetTCPIP commands, always ActiveStore (never persistent), and never
/// deletes a route without matching its full prefix, interface index, gateway and metric.
/// User input is validated by the planner and passed as encoded, individually quoted literals.
/// </summary>
public sealed class WindowsPowerShellRouteCommands : IWindowsRouteCommands
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(25);
    private const int Metric = 1;

    public async Task<RouteInstallResult> EnsureAsync(WindowsRoute route, CancellationToken cancellationToken)
    {
        var variables = RouteVariables(route);
        var output = await RunAsync(variables + """
            # Find-NetRoute returns both a local-address object and a route object.
            # The more-specific route must actually be the best route chosen by Windows.
            function Assert-SelectedRoute {
                $networkPart = $prefix.Split('/')[0]
                $prefixLength = [int]$prefix.Split('/')[1]
                if ($prefixLength -lt 32) {
                    $bytes = [Net.IPAddress]::Parse($networkPart).GetAddressBytes()
                    $bytes[3] = [byte]($bytes[3] + 1)
                    $networkPart = ([Net.IPAddress]::new([byte[]]$bytes)).ToString()
                }
                $best = @(Find-NetRoute -RemoteIPAddress $networkPart -ErrorAction Stop |
                    Where-Object { $_.PSObject.Properties['DestinationPrefix'] -ne $null })
                if ($best.Count -eq 0 -or [int]$best[0].InterfaceIndex -ne $ifIndex -or
                    $best[0].DestinationPrefix -ne $prefix -or $best[0].NextHop -ne $nextHop) {
                    throw "Windows does not select the requested route for $networkPart; inspect VPN routing, next hop and interface metrics"
                }
            }
            $entries = @(Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            $matching = @($entries | Where-Object { $_.NextHop -eq $nextHop -and $_.RouteMetric -eq $metric })
            if ($matching.Count -gt 0) {
                Assert-SelectedRoute
                'PRESENT'
            } elseif ($entries.Count -gt 0) {
                throw "An existing route for the same destination and adapter has a different gateway or metric; no route was modified"
            } else {
                New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -NextHop $nextHop -RouteMetric $metric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
                try {
                    $verified = @(Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -PolicyStore ActiveStore -ErrorAction Stop |
                        Where-Object { $_.NextHop -eq $nextHop -and $_.RouteMetric -eq $metric })
                    if ($verified.Count -eq 0) { throw "The Windows route could not be verified after creation" }
                    Assert-SelectedRoute
                } catch {
                    # Roll back a new route if Windows will not actually select it.
                    Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                        Where-Object { $_.NextHop -eq $nextHop -and $_.RouteMetric -eq $metric } |
                        Remove-NetRoute -Confirm:$false -ErrorAction Stop
                    throw
                }
                'CREATED'
            }
            """, cancellationToken).ConfigureAwait(false);
        return output.Trim() switch
        {
            "CREATED" => RouteInstallResult.Created,
            "PRESENT" => RouteInstallResult.AlreadyPresent,
            _ => throw new IOException($"Unexpected Windows routing response: {output}")
        };
    }

    public async Task RemoveAsync(WindowsRoute route, CancellationToken cancellationToken)
    {
        var variables = RouteVariables(route);
        var output = await RunAsync(variables + """
            $entries = @(Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $nextHop -and $_.RouteMetric -eq $metric })
            foreach ($entry in $entries) {
                $entry | Remove-NetRoute -Confirm:$false -ErrorAction Stop
            }
            'REMOVED'
            """, cancellationToken).ConfigureAwait(false);
        if (output.Trim() != "REMOVED")
            throw new IOException($"Unexpected Windows routing removal response: {output}");
    }

    private static string RouteVariables(WindowsRoute route)
    {
        // Strict literal quoting even though the policy planner has already validated IPv4/CIDR.
        static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        return $"$prefix = {Quote(route.DestinationPrefix)}\n" +
               $"$ifIndex = {route.InterfaceIndex.ToString(CultureInfo.InvariantCulture)}\n" +
               $"$nextHop = {Quote(route.NextHop)}\n$metric = {Metric}\n";
    }

    private static async Task<string> RunAsync(string script, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows system routes require Windows NetTCPIP");

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "$ErrorActionPreference = 'Stop'\n" + script));
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(encoded);

        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw new IOException("Unable to start Windows PowerShell");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(CommandTimeout);
        try
        {
            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0)
                throw new IOException("Windows routing command failed: " + stderr.Trim());
            return stdout;
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { /* child exited during cancellation */ }
            }
            if (!token.IsCancellationRequested)
                throw new TimeoutException("Windows routing command timed out");
            throw;
        }
    }
}
