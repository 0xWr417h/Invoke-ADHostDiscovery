<#
.SYNOPSIS
    AD-based host discovery using built-in Windows ADSI -- no RSAT required.

.DESCRIPTION
    Enumerates computer objects from Active Directory using [adsisearcher] (built
    into all Windows versions), resolves DNS hostnames to IPs, and optionally probes
    each IP for reachability via ICMP and TCP connects to 445 (SMB) and 135 (RPC).

    No modules. No installs. Runs as a standard domain user.

    Noise profile: LDAP queries to one GC or DC + DNS A-record lookups.

    Still detectable via:
      - DC/GC LDAP query logs
      - DNS query volume
      - Defender for Identity AD enumeration alerts

.PARAMETER Server
    Specific DC or GC to query (FQDN or IP). Defaults to auto-discovered GC.

.PARAMETER Domain
    LDAP distinguished name of the search base, e.g. "DC=corp,DC=local".
    Defaults to the current domain root.

.PARAMETER EnabledOnly
    Skip disabled computer objects. Recommended to cut stale-object noise.

.PARAMETER PingSweep
    After resolving IPs, ping each host. Marks each as Live or not.

.PARAMETER CheckLive
    After resolving IPs, probe each host via ICMP + TCP/445 + TCP/135.
    A host is marked live if ANY probe succeeds.

.PARAMETER ShowOS
    Include the OperatingSystem attribute from AD in output.

.PARAMETER TimeoutMs
    Timeout in milliseconds for ICMP and TCP probes. Default: 500.

.PARAMETER OutputPath
    Write results to CSV at this path. Omit for console output only.

.PARAMETER Threads
    Max concurrent threads for live-host checks. Default: 50.

.EXAMPLE
    .\Invoke-ADHostDiscovery.ps1

.EXAMPLE
    .\Invoke-ADHostDiscovery.ps1 -EnabledOnly -PingSweep -ShowOS

.EXAMPLE
    .\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -CheckLive -ShowOS -OutputPath .\hosts.csv

.NOTES
    Requirements: none. Uses ADSI built into Windows.
    Runs as standard authenticated domain user.
    License: MIT
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Domain,
    [switch]$EnabledOnly,
    [switch]$PingSweep,
    [switch]$CheckLive,
    [switch]$ShowOS,
    [int]$TimeoutMs    = 500,
    [string]$OutputPath,
    [int]$Threads      = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Banner ─────────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  Invoke-ADHostDiscovery" -ForegroundColor Cyan
    Write-Host "  AD-based host discovery | no RSAT | no installs" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Build LDAP path ────────────────────────────────────────────────────────────
function Get-LdapRoot {
    param([string]$Server, [string]$Domain)

    if (-not $Domain) {
        $root   = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $Domain = $root.GetDirectoryEntry().distinguishedName
        Write-Verbose "Auto-detected domain DN: $Domain"
    }

    if ($Server) {
        $path = "LDAP://$Server/$Domain"
    } else {
        try {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $gc     = $forest.FindGlobalCatalog()
            $path   = "GC://$($gc.Name)/$Domain"
            Write-Verbose "Auto-discovered GC: $($gc.Name)"
        } catch {
            $path = "LDAP://$Domain"
            Write-Verbose "GC discovery failed, falling back to LDAP://$Domain"
        }
    }

    Write-Verbose "LDAP path: $path"
    return $path
}

# ── Enumerate computer objects via ADSI ───────────────────────────────────────
function Get-ADHosts {
    param([string]$LdapPath, [bool]$EnabledOnly)

    $filter = if ($EnabledOnly) {
        '(&(objectCategory=computer)(dNSHostName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    } else {
        '(&(objectCategory=computer)(dNSHostName=*))'
    }

    Write-Verbose "LDAP filter: $filter"
    Write-Verbose "Search base: $LdapPath"

    try {
        $entry    = New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter   = $filter
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('dNSHostName', 'operatingSystem', 'lastLogonTimestamp'))

        $results = $searcher.FindAll()
        Write-Verbose "Raw results: $($results.Count)"

        $hostnames = foreach ($r in $results) {
            $dns = $r.Properties['dnshostname']
            $os  = $r.Properties['operatingsystem']
            if ($dns) {
                [PSCustomObject]@{
                    DNSHostName     = $dns[0].ToString()
                    OperatingSystem = if ($os) { $os[0].ToString() } else { 'Unknown' }
                }
            }
        }

        $results.Dispose()
        $searcher.Dispose()
        $entry.Dispose()

        $hostnames | Where-Object { $_ } | Sort-Object DNSHostName -Unique

    } catch {
        Write-Error "ADSI query failed: $_"
        return @()
    }
}

# ── DNS Resolution ─────────────────────────────────────────────────────────────
function Resolve-Hosts {
    param([PSCustomObject[]]$Hosts)

    Write-Verbose "Resolving $($Hosts.Count) hostnames..."
    $seen = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($h in $Hosts) {
        $answers = Resolve-DnsName -Name $h.DNSHostName -Type A -ErrorAction SilentlyContinue
        foreach ($a in $answers) {
            if ($a.IPAddress -and $seen.Add($a.IPAddress)) {
                [PSCustomObject]@{
                    Name            = $h.DNSHostName
                    IPAddress       = $a.IPAddress
                    OperatingSystem = $h.OperatingSystem
                    Live            = $null
                    ICMPOk          = $null
                    TCP445Ok        = $null
                    TCP135Ok        = $null
                }
            }
        }
    }
}

# ── Per-host live check ────────────────────────────────────────────────────────
function Test-HostLive {
    param([string]$IP, [int]$TimeoutMs)

    $r = [PSCustomObject]@{
        ICMPOk   = $false
        TCP445Ok = $false
        TCP135Ok = $false
        Live     = $false
    }

    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        if (($ping.Send($IP, $TimeoutMs)).Status -eq 'Success') { $r.ICMPOk = $true }
    } catch {}

    foreach ($port in 445, 135) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar  = $tcp.BeginConnect($IP, $port, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $tcp.EndConnect($ar)
                if ($port -eq 445) { $r.TCP445Ok = $true } else { $r.TCP135Ok = $true }
            }
            $tcp.Close()
        } catch {}
    }

    $r.Live = $r.ICMPOk -or $r.TCP445Ok -or $r.TCP135Ok
    return $r
}

# ── Parallel live checks ───────────────────────────────────────────────────────
function Invoke-LiveChecks {
    param([PSCustomObject[]]$Hosts, [int]$TimeoutMs, [int]$Threads)

    Write-Verbose "Live checks: $($Hosts.Count) hosts | $Threads threads | ${TimeoutMs}ms"

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()
    $jobs = @()

    foreach ($h in $Hosts) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($ip, $name, $os, $t)
            $icmp = $false; $t445 = $false; $t135 = $false
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $icmp = ($ping.Send($ip, $t)).Status -eq 'Success'
            } catch {}
            foreach ($port in 445, 135) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $ar  = $tcp.BeginConnect($ip, $port, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne($t)) {
                        $tcp.EndConnect($ar)
                        if ($port -eq 445) { $t445 = $true } else { $t135 = $true }
                    }
                    $tcp.Close()
                } catch {}
            }
            [PSCustomObject]@{
                Name            = $name
                IPAddress       = $ip
                Live            = ($icmp -or $t445 -or $t135)
                OperatingSystem = $os
                ICMPOk          = $icmp
                TCP445Ok        = $t445
                TCP135Ok        = $t135
            }
        }).AddParameters(@{ ip = $h.IPAddress; name = $h.Name; os = $h.OperatingSystem; t = $TimeoutMs })

        $jobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }

    $results = foreach ($job in $jobs) {
        $job.PS.EndInvoke($job.Handle)
        $job.PS.Dispose()
    }

    $pool.Close()
    $pool.Dispose()
    return $results | Sort-Object Name
}

# ── Ping sweep ─────────────────────────────────────────────────────────────────
function Invoke-PingSweep {
    param([PSCustomObject[]]$Hosts, [int]$TimeoutMs, [int]$Threads)

    Write-Verbose "Ping sweep: $($Hosts.Count) hosts | $Threads threads | ${TimeoutMs}ms"

    $pool    = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()
    $jobs    = @()

    foreach ($h in $Hosts) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($ip, $name, $os, $t)
            $alive = $false
            try {
                $ping  = New-Object System.Net.NetworkInformation.Ping
                $alive = ($ping.Send($ip, $t)).Status -eq 'Success'
            } catch {}
            [PSCustomObject]@{
                Name            = $name
                IPAddress       = $ip
                Live            = $alive
                OperatingSystem = $os
            }
        }).AddParameters(@{ ip = $h.IPAddress; name = $h.Name; os = $h.OperatingSystem; t = $TimeoutMs })

        $jobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }

    $results = foreach ($job in $jobs) {
        $job.PS.EndInvoke($job.Handle)
        $job.PS.Dispose()
    }

    $pool.Close()
    $pool.Dispose()
    return $results | Sort-Object Name
}

# ── Main ──────────────────────────────────────────────────────────────────────
Write-Banner

$ldapPath = Get-LdapRoot -Server $Server -Domain $Domain

Write-Host "[*] Search base : $ldapPath" -ForegroundColor Yellow
if ($EnabledOnly) { Write-Host "[*] Scope       : Enabled objects only" -ForegroundColor Yellow }

$adHosts = Get-ADHosts -LdapPath $ldapPath -EnabledOnly $EnabledOnly.IsPresent

if (-not $adHosts) {
    Write-Warning "No hostnames found. Try removing -EnabledOnly or check AD connectivity."
    exit 0
}

Write-Host "[*] AD objects  : $($adHosts.Count) unique hosts" -ForegroundColor Yellow

$resolved = @(Resolve-Hosts -Hosts $adHosts)
Write-Host "[*] Resolved    : $($resolved.Count) unique IPs" -ForegroundColor Yellow

if ($PingSweep) {
    Write-Host "[*] Ping sweep  : ICMP only (timeout=${TimeoutMs}ms)" -ForegroundColor Yellow
    $output    = Invoke-PingSweep -Hosts $resolved -TimeoutMs $TimeoutMs -Threads $Threads
    $liveCount = ($output | Where-Object { $_.Live }).Count
    Write-Host "[*] Live hosts  : $liveCount / $($output.Count)" -ForegroundColor Green
} elseif ($CheckLive) {
    Write-Host "[*] Live check  : ICMP + TCP/445 + TCP/135 (timeout=${TimeoutMs}ms)" -ForegroundColor Yellow
    $output    = Invoke-LiveChecks -Hosts $resolved -TimeoutMs $TimeoutMs -Threads $Threads
    $liveCount = ($output | Where-Object { $_.Live }).Count
    Write-Host "[*] Live hosts  : $liveCount / $($output.Count)" -ForegroundColor Green
} else {
    $output = $resolved
}

# Build output columns dynamically based on switches
$cols = [System.Collections.Generic.List[string]]::new()
$cols.Add('Name')
$cols.Add('IPAddress')
if ($PingSweep -or $CheckLive) { $cols.Add('Live') }
if ($CheckLive)                { $cols.Add('ICMPOk'); $cols.Add('TCP445Ok'); $cols.Add('TCP135Ok') }
if ($ShowOS)                   { $cols.Add('OperatingSystem') }

$output = $output | Select-Object $cols

Write-Host ""
$output | Format-Table -AutoSize

if ($OutputPath) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Saved: $OutputPath" -ForegroundColor Green
}