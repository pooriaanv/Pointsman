# Reports why Pointsman is or is not listing a machine's network adapters.
#
# Pointsman builds its list from two sources and intersects them: the .NET
# network-interface list, and a WMI query for the adapters Windows shows in
# "Network Connections". If an adapter is missing from the app, it is missing
# from one of those two, or their GUIDs do not agree -- and this says which.
#
# Run it and send the output:
#   powershell -ExecutionPolicy Bypass -File diagnose-adapters.ps1 > adapters.txt

$ErrorActionPreference = 'Continue'

Write-Output "Pointsman adapter diagnostic"
Write-Output "OS       : $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)"
Write-Output "Build    : $([System.Environment]::OSVersion.Version)"
Write-Output "Culture  : $((Get-Culture).Name)"
Write-Output "Elevated : $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-Output ""

# --- Source 1: what .NET sees, the same call the app makes -------------------
Write-Output "=== [1] NetworkInterface.GetAllNetworkInterfaces() ==="
$nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
Write-Output "count: $($nics.Count)"
Write-Output ""
foreach ($n in $nics) {
    $ipv4 = $null
    try {
        $ipv4 = ($n.GetIPProperties().UnicastAddresses |
                 Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
                 Select-Object -First 1).Address.IPAddressToString
    } catch { }
    Write-Output "  Id     : $($n.Id)"
    Write-Output "  Name   : $($n.Name)"
    Write-Output "  Desc   : $($n.Description)"
    Write-Output "  Type   : $($n.NetworkInterfaceType)   Status: $($n.OperationalStatus)   IPv4: $ipv4"
    Write-Output ""
}

# --- Source 2: the WMI query the app uses to drop hidden pseudo-adapters -----
Write-Output "=== [2] WMI: Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL ==="
$wmi = @()
try {
    $wmi = @(Get-CimInstance -Query "SELECT GUID, PhysicalAdapter, NetConnectionID, Name FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL" -ErrorAction Stop)
    Write-Output "count: $($wmi.Count)"
    Write-Output ""
    foreach ($w in $wmi) {
        $g = if ([string]::IsNullOrEmpty($w.GUID)) { "<<NULL OR EMPTY>>" } else { $w.GUID }
        Write-Output "  GUID            : $g"
        Write-Output "  NetConnectionID : $($w.NetConnectionID)"
        Write-Output "  PhysicalAdapter : $($w.PhysicalAdapter)"
        Write-Output "  Name            : $($w.Name)"
        Write-Output ""
    }
} catch {
    Write-Output "WMI QUERY FAILED: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    Write-Output "(The app treats this as 'no WMI' and falls back to heuristics, which still lists adapters.)"
    Write-Output ""
}

# --- The intersection, which is what actually decides the list --------------
Write-Output "=== [3] Do they agree? This is the part that matters ==="
if ($wmi.Count -eq 0) {
    Write-Output "WMI returned nothing, so the app uses its fallback and adapters should still be listed."
    Write-Output "If the app is empty anyway, the cause is NOT this intersection."
} else {
    $guids = @{}
    foreach ($w in $wmi) {
        if (-not [string]::IsNullOrEmpty($w.GUID)) { $guids[$w.GUID] = $w.PhysicalAdapter }
    }
    Write-Output "usable GUIDs from WMI: $($guids.Count) of $($wmi.Count) rows"
    Write-Output ""

    $matched = 0
    foreach ($n in $nics) {
        if ($guids.ContainsKey($n.Id)) {
            $matched++
            Write-Output "  MATCH   $($n.Id)  $($n.Name)"
        }
    }
    foreach ($n in $nics) {
        if (-not $guids.ContainsKey($n.Id)) {
            Write-Output "  dropped $($n.Id)  $($n.Name)  [$($n.NetworkInterfaceType)]"
        }
    }
    Write-Output ""
    Write-Output "matched: $matched of $($nics.Count) interfaces"
    if ($matched -eq 0) {
        Write-Output ""
        Write-Output ">>> THIS IS THE FAULT. WMI returned rows, so the app trusts it, but not one"
        Write-Output ">>> of them matches a real interface -- so every adapter is dropped and the"
        Write-Output ">>> list comes out empty. The fallback never runs because it only triggers"
        Write-Output ">>> when WMI returns nothing at all."
    }
}
