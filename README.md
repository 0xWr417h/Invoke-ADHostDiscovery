# Invoke-ADHostDiscovery

Low-noise Active Directory host discovery with optional ping sweep, full liveness checks, and OS enumeration. No RSAT. No installs. Runs as a standard domain user.

## What it does

1. Queries AD via ADSI (built into Windows) for all computer objects with a DNSHostName
2. Resolves each hostname to an IP via DNS
3. Optionally checks if each host is alive (ICMP and/or TCP probes)
4. Optionally surfaces the OS from AD

No packet crafting. No port scan. No SYN storms.

## Why this instead of nmap

| | This script | nmap sweep |
|---|---|---|
| Network packets | ~0 (LDAP + DNS) | Thousands |
| Requires domain creds | Yes | No |
| Finds non-AD hosts | No | Yes |
| Stale object handling | Yes (`-EnabledOnly`) | N/A |
| Detectable | Yes | Yes |

Use this to pull a clean, AD-sourced host list first. Feed confirmed live hosts into nmap, netexec, or BloodHound for deeper work.

## Requirements

- Any domain-joined Windows 10/11 machine
- Standard authenticated domain user -- no elevated rights needed
- No modules, no installs -- uses ADSI built into Windows

## Detection

This script is detectable. Do not assume stealth.

- Bulk LDAP queries to the DC/GC will appear in event logs
- DNS A-record lookups are logged on your resolver
- Defender for Identity and similar EDR tools have signatures for AD computer enumeration
- `-PingSweep` and `-CheckLive` add probe traffic visible on the wire and in host-based sensors

## Usage
```powershell
# Basic discovery -- hosts and IPs only
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local"

# Skip disabled objects (recommended)
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly

# Add OS info from AD
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -ShowOS

# Ping sweep -- ICMP only, fastest liveness check
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -PingSweep

# Full liveness check -- ICMP + TCP/445 + TCP/135
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -CheckLive

# Everything at once, save to CSV
.\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -CheckLive -ShowOS -OutputPath .\hosts.csv

# Pipe live hosts into netexec
$live = .\Invoke-ADHostDiscovery.ps1 -Server dc01.corp.local -Domain "DC=corp,DC=local" -EnabledOnly -CheckLive |
        Where-Object { $_.Live }
$live.IPAddress | ForEach-Object { nxc smb $_ }
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Server` | auto (first GC) | DC or GC FQDN or IP to query |
| `-Domain` | current domain | Search base as LDAP DN, e.g. `DC=corp,DC=local` |
| `-EnabledOnly` | off | Skip disabled computer objects |
| `-PingSweep` | off | ICMP ping each resolved IP |
| `-CheckLive` | off | ICMP + TCP/445 + TCP/135 per host |
| `-ShowOS` | off | Include OperatingSystem from AD in output |
| `-TimeoutMs` | 500 | Probe timeout in milliseconds |
| `-OutputPath` | none | Save results to CSV |
| `-Threads` | 50 | Concurrent threads for liveness checks |

## Output columns

| Column | When present |
|---|---|
| Name | Always |
| IPAddress | Always |
| Live | `-PingSweep` or `-CheckLive` |
| ICMPOk | `-CheckLive` only |
| TCP445Ok | `-CheckLive` only |
| TCP135Ok | `-CheckLive` only |
| OperatingSystem | `-ShowOS` |

## Known limitations

- Misses non-domain-joined hosts entirely
- Misses hosts with a blank DNSHostName attribute in AD
- Stale objects appear without `-EnabledOnly`
- DNS records can lag actual host state
- `-PingSweep` will show False for hosts that block ICMP -- use `-CheckLive` for those

## License

MIT