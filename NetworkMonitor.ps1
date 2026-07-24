<#
.SYNOPSIS
    Advanced Network Monitor v2.0 - Optimized Edition
.DESCRIPTION
    Production-ready network monitoring with parallel processing,
    smart caching, and advanced threat detection.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
.NOTES
    Performance: Parallel runspaces for DNS resolution
    Memory: Optimized for large-scale monitoring (1000+ connections)
#>

[CmdletBinding()]
param(
    [ValidateSet("Report", "Monitor", "Dashboard")]
    [string]$Mode = "Report",
    
    [ValidateSet("HTML", "CSV", "JSON")]
    [string]$OutputFormat = "HTML",
    
    [string]$OutputPath,
    
    [string]$MonitorLogPath,
    
    [int]$MonitorInterval = 5,
    
    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 20,
    
    [switch]$EnableGeoIP,
    
    [switch]$DetectThreats
)

# Set Strict Mode to catch errors
Set-StrictMode -Version 2.0

# Smart Cache System (Global Script Variables)
$script:DNSCache = @{}
$script:GeoIPCache = @{}
$script:DNSCacheFile = "$env:LOCALAPPDATA\NetworkMonitor\DNSCache.json"
$script:GeoIPCacheFile = "$env:LOCALAPPDATA\NetworkMonitor\GeoIPCache.json"

function Load-CacheFiles {
    # Load DNS Cache
    if (Test-Path $script:DNSCacheFile) {
        try {
            $json = Get-Content $script:DNSCacheFile -Raw -ErrorAction SilentlyContinue
            if ($json) {
                $obj = ConvertFrom-Json $json
                if ($obj) {
                    foreach ($prop in $obj.psobject.Properties) {
                        $script:DNSCache[$prop.Name] = $prop.Value
                    }
                }
            }
        } catch {}
    }
    
    # Load GeoIP Cache
    if (Test-Path $script:GeoIPCacheFile) {
        try {
            $json = Get-Content $script:GeoIPCacheFile -Raw -ErrorAction SilentlyContinue
            if ($json) {
                $obj = ConvertFrom-Json $json
                if ($obj) {
                    foreach ($prop in $obj.psobject.Properties) {
                        $script:GeoIPCache[$prop.Name] = $prop.Value
                    }
                }
            }
        } catch {}
    }
}

function Save-CacheFiles {
    try {
        $dir = Split-Path $script:DNSCacheFile
        if (-not (Test-Path $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue
        }
        $script:DNSCache | ConvertTo-Json -Compress | Set-Content $script:DNSCacheFile -ErrorAction SilentlyContinue
        $script:GeoIPCache | ConvertTo-Json -Compress | Set-Content $script:GeoIPCacheFile -ErrorAction SilentlyContinue
    } catch {}
}

# Optimized DNS Resolution with parallel .NET Runspaces
function Resolve-IPsParallel {
    param(
        [string[]]$IPs,
        [int]$MaxRunspaces = 20
    )
    
    $results = @{}
    $ipsToResolve = $IPs | Select-Object -Unique | Where-Object { $_ -and $_ -notin @('0.0.0.0', '::', '127.0.0.1', '::1') }
    
    if (-not $ipsToResolve) {
        return $results
    }
    
    $uncachedIPs = [System.Collections.ArrayList]::new()
    foreach ($ip in $ipsToResolve) {
        if ($script:DNSCache.ContainsKey($ip)) {
            $results[$ip] = $script:DNSCache[$ip]
        } else {
            [void]$uncachedIPs.Add($ip)
        }
    }
    
    if ($uncachedIPs.Count -eq 0) {
        return $results
    }
    
    # Create Runspace Pool
    try {
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $iss, $Host)
        $pool.Open()
        
        $jobs = [System.Collections.ArrayList]::new()
        foreach ($ip in $uncachedIPs) {
            $powershell = [PowerShell]::Create().AddScript({
                param($ipAddress)
                try {
                    $entry = [System.Net.Dns]::GetHostEntry($ipAddress)
                    return [PSCustomObject]@{ IP = $ipAddress; HostName = $entry.HostName }
                } catch {
                    return [PSCustomObject]@{ IP = $ipAddress; HostName = $null }
                }
            }).AddArgument($ip)
            $powershell.RunspacePool = $pool
            [void]$jobs.Add([PSCustomObject]@{
                PowerShell = $powershell
                AsyncResult = $powershell.BeginInvoke()
                IP = $ip
            })
        }
        
        # Wait for all jobs and collect results
        foreach ($job in $jobs) {
            try {
                $res = $job.PowerShell.EndInvoke($job.AsyncResult)
                if ($res -and $res.HostName) {
                    $results[$job.IP] = $res.HostName
                    $script:DNSCache[$job.IP] = $res.HostName
                } else {
                    $results[$job.IP] = $null
                    $script:DNSCache[$job.IP] = $null # Cache negative result
                }
            } catch {
                $results[$job.IP] = $null
                $script:DNSCache[$job.IP] = $null
            } finally {
                $job.PowerShell.Dispose()
            }
        }
        
        $pool.Close()
        $pool.Dispose()
    } catch {
        # Fallback to sequential resolution if runspaces fail
        foreach ($ip in $uncachedIPs) {
            try {
                $entry = [System.Net.Dns]::GetHostEntry($ip)
                $results[$ip] = $entry.HostName
                $script:DNSCache[$ip] = $entry.HostName
            } catch {
                $results[$ip] = $null
                $script:DNSCache[$ip] = $null
            }
        }
    }
    
    return $results
}

# GeoIP Lookup with Cache
function Resolve-GeoIP {
    param([string]$ip)
    
    if (-not $ip -or $ip -in @('0.0.0.0', '::', '127.0.0.1', '::1') -or $ip -like '127.*' -or $ip -like '169.254.*' -or $ip -like '192.168.*' -or $ip -match '^10\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
        return "LAN"
    }
    
    if ($script:GeoIPCache.ContainsKey($ip)) {
        return $script:GeoIPCache[$ip]
    }
    
    try {
        # Fetch from ip-api.com (free, rate limited to 45 requests per minute)
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip?fields=countryCode" -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response -and $response.countryCode) {
            $country = $response.countryCode
            $script:GeoIPCache[$ip] = $country
            return $country
        }
    } catch {}
    
    return "Unknown"
}

# Classify IP Address ranges
function Get-IPClassification {
    param([string]$ip)
    if (-not $ip -or $ip -eq '0.0.0.0' -or $ip -eq '::') {
        return "Unspecified"
    }
    if ($ip -eq '127.0.0.1' -or $ip -eq '::1' -or $ip -like '127.*') {
        return "Loopback"
    }
    if ($ip -like '169.254.*') {
        return "APIPA"
    }
    # IPv4 Private
    if ($ip -match '^10\.') { return "Private" }
    if ($ip -match '^192\.168\.') { return "Private" }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return "Private" }
    
    # IPv6 Link-Local/Unique-Local
    if ($ip -match '^(fe[89ab][0-9a-f]|fc[0-9a-f]{2}|fd[0-9a-f]{2})' -or $ip -like 'fe80:*') {
        return "Private"
    }
    
    return "Public"
}

# Process Table Lookup (Retrieves all process names, paths and commands)
function Get-ProcessTable {
    $table = @{}
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $table[$proc.ProcessId] = [PSCustomObject]@{
                Name = $proc.Name
                Path = if ($proc.ExecutablePath) { $proc.ExecutablePath } else { "N/A" }
                CommandLine = if ($proc.CommandLine) { $proc.CommandLine } else { "" }
            }
        }
    } catch {
        # Fallback to Get-Process if CIM fails
        Get-Process | ForEach-Object {
            $path = "N/A"
            try { $path = $_.MainModule.FileName } catch {}
            $table[$_.Id] = [PSCustomObject]@{
                Name = $_.ProcessName
                Path = $path
                CommandLine = ""
            }
        }
    }
    return $table
}

# Threat Detection Engine
function Test-SuspiciousConnection {
    param(
        [string]$RemoteIP,
        [int]$RemotePort,
        [string]$ProcessName
    )
    
    $threatScore = 0
    $threatReasons = [System.Collections.ArrayList]::new()
    
    # Known malicious ports
    $maliciousPorts = @{
        4444 = "Metasploit default"
        5555 = "Android ADB (unauthorized)"
        6666 = "IRC Botnet common"
        9999 = "Backdoor common"
        31337 = "Back Orifice"
        1337 = "WASTE/Leet"
    }
    
    if ($maliciousPorts.ContainsKey($RemotePort)) {
        $threatScore += 35
        [void]$threatReasons.Add("Suspicious port $RemotePort ($($maliciousPorts[$RemotePort]))")
    }
    
    # Unusual process behavior
    $suspiciousProcesses = @('powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32')
    if ($ProcessName.ToLower() -in $suspiciousProcesses -and $RemotePort -notin @(80, 443, 53)) {
        $threatScore += 30
        [void]$threatReasons.Add("$ProcessName connecting to non-standard port $RemotePort")
    }
    
    # Tor exit node range match (simplified ranges)
    if ($RemoteIP -match '^5\.|^37\.|^82\.|^93\.|^109\.|^185\.') {
        $threatScore += 15
        [void]$threatReasons.Add("IP range commonly associated with Tor exit nodes")
    }
    
    return [PSCustomObject]@{
        ThreatScore = $threatScore
        Reasons = $threatReasons -join "; "
        IsSuspicious = $threatScore -ge 30
    }
}

# Get active connections
function Get-ActiveConnections {
    $connections = [System.Collections.ArrayList]::new()
    
    # Get TCP connections
    try {
        $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($conn in $tcp) {
            [void]$connections.Add([PSCustomObject]@{
                Protocol = "TCP"
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State.ToString()
                OwningProcessId = $conn.OwningProcess
            })
        }
    } catch {}
    
    # Get UDP endpoints
    try {
        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        foreach ($conn in $udp) {
            [void]$connections.Add([PSCustomObject]@{
                Protocol = "UDP"
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = "BOUND"
                OwningProcessId = $conn.OwningProcess
            })
        }
    } catch {}
    
    return $connections
}

# Combine all connections, processes, services, DNS resolution and security audits
function Get-EnrichedConnections {
    param(
        [switch]$DetectThreats = $false,
        [int]$ThrottleLimit = 20,
        [switch]$EnableGeoIP = $false
    )
    
    $processTable = Get-ProcessTable
    
    # Build Service mapping PID -> ServiceNames
    $serviceMap = @{}
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($srv in $services) {
            if ($srv.ProcessId -gt 0) {
                if (-not $serviceMap.ContainsKey($srv.ProcessId)) {
                    $serviceMap[$srv.ProcessId] = [System.Collections.ArrayList]::new()
                }
                [void]$serviceMap[$srv.ProcessId].Add($srv.Name)
            }
        }
    } catch {}
    
    # Get Active raw connections
    $rawConnections = Get-ActiveConnections
    
    # Resolve IPs in parallel
    $remoteIPs = $rawConnections | ForEach-Object { $_.RemoteAddress } | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' }
    $resolvedIPs = Resolve-IPsParallel -IPs $remoteIPs -MaxRunspaces $ThrottleLimit
    
    # Enrich connection objects
    $enriched = [System.Collections.ArrayList]::new()
    foreach ($conn in $rawConnections) {
        $procInfo = $processTable[$conn.OwningProcessId]
        $procName = if ($procInfo) { $procInfo.Name } else { "System/Unknown" }
        $procPath = if ($procInfo) { $procInfo.Path } else { "N/A" }
        $cmdLine = if ($procInfo) { $procInfo.CommandLine } else { "" }
        
        # Services mapping
        $servicesList = if ($serviceMap.ContainsKey($conn.OwningProcessId)) {
            $serviceMap[$conn.OwningProcessId] -join ", "
        } else {
            ""
        }
        
        $ipClass = Get-IPClassification -ip $conn.RemoteAddress
        $hostname = if ($resolvedIPs.ContainsKey($conn.RemoteAddress)) { $resolvedIPs[$conn.RemoteAddress] } else { "" }
        
        # GeoIP check
        if ($EnableGeoIP -and $ipClass -eq "Public") {
            $geo = Resolve-GeoIP -ip $conn.RemoteAddress
            if ($geo -and $geo -ne "Unknown" -and $geo -ne "LAN") {
                $ipClass = "$ipClass ($geo)"
            }
        }
        
        # Security Threat Analysis
        $threatScore = 0
        $threatReasons = ""
        $isSuspicious = $false
        if ($DetectThreats) {
            $threatAudit = Test-SuspiciousConnection -RemoteIP $conn.RemoteAddress -RemotePort $conn.RemotePort -ProcessName $procName
            $threatScore = $threatAudit.ThreatScore
            $threatReasons = $threatAudit.Reasons
            $isSuspicious = $threatAudit.IsSuspicious
        }
        
        [void]$enriched.Add([PSCustomObject]@{
            Protocol        = $conn.Protocol
            LocalAddress    = $conn.LocalAddress
            LocalPort       = $conn.LocalPort
            RemoteAddress   = $conn.RemoteAddress
            RemotePort      = $conn.RemotePort
            State           = $conn.State
            OwningProcessId = $conn.OwningProcessId
            ProcessName     = $procName
            ProcessPath     = $procPath
            CommandLine     = $cmdLine
            Services        = $servicesList
            RemoteIPClass   = $ipClass
            RemoteHostName  = $hostname
            ThreatScore     = $threatScore
            ThreatReasons   = $threatReasons
            IsSuspicious    = $isSuspicious
        })
    }
    
    return $enriched
}

# Network Adapter Throughput stats
function Get-NetworkAdapterThroughput {
    try {
        $stats1 = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Where-Object { $_.ReceivedBytes -gt 0 -or $_.SentBytes -gt 0 }
        if (-not $stats1) {
            return @()
        }
        Start-Sleep -Seconds 1
        $stats2 = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Where-Object { $_.ReceivedBytes -gt 0 -or $_.SentBytes -gt 0 }
        
        $results = @()
        foreach ($s1 in $stats1) {
            $s2 = $stats2 | Where-Object { $_.Name -eq $s1.Name }
            if ($s2) {
                $recvRate = $s2.ReceivedBytes - $s1.ReceivedBytes
                $sendRate = $s2.SentBytes - $s1.SentBytes
                if ($recvRate -lt 0) { $recvRate = 0 }
                if ($sendRate -lt 0) { $sendRate = 0 }
                
                $results += [PSCustomObject]@{
                    Name = $s1.Name
                    ReceivedRate_Bps = $recvRate
                    SentRate_Bps = $sendRate
                    TotalRate_Bps = $recvRate + $sendRate
                }
            }
        }
        return $results
    } catch {
        return @()
    }
}

# Advanced Reporting Engine
function New-AdvancedReport {
    param(
        $Data,
        [string]$Format,
        [string]$Path
    )
    
    switch ($Format) {
        'HTML' {
            # Base64 encode details to ensure no encoding issues in HTML JS block
            $connJson = $Data.Connections | ConvertTo-Json -Depth 5
            $adapterJson = $Data.Adapters | ConvertTo-Json -Depth 5
            $summaryJson = $Data.Summary | ConvertTo-Json -Depth 5
            
            $connBytes = [System.Text.Encoding]::UTF8.GetBytes($connJson)
            $connBase64 = [Convert]::ToBase64String($connBytes)
            
            $adapterBytes = [System.Text.Encoding]::UTF8.GetBytes($adapterJson)
            $adapterBase64 = [Convert]::ToBase64String($adapterBytes)
            
            $summaryBytes = [System.Text.Encoding]::UTF8.GetBytes($summaryJson)
            $summaryBase64 = [Convert]::ToBase64String($summaryBytes)

            # Use single quotes for HTML template to prevent any PowerShell variable expansion
            $htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Activity Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 30, 49, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #00f0ff;
            --accent-glow: rgba(0, 240, 255, 0.15);
            --danger: #ff4a5a;
            --danger-glow: rgba(255, 74, 90, 0.15);
            --success: #10b981;
            --warning: #f59e0b;
            --info: #38bdf8;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
        }
        body {
            background: radial-gradient(circle at 50% 0%, #151e33 0%, var(--bg-color) 70%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
            overflow-x: hidden;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 1.5rem;
        }
        .header-title h1 {
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .header-title p {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }
        .timestamp-badge {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .timestamp-badge::before {
            content: '';
            display: inline-block;
            width: 8px;
            height: 8px;
            background-color: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            border-color: var(--accent);
            box-shadow: 0 12px 20px -10px var(--accent-glow);
        }
        .stat-card.threat:hover {
            border-color: var(--danger);
            box-shadow: 0 12px 20px -10px var(--danger-glow);
        }
        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-value {
            font-size: 2.25rem;
            font-weight: 700;
            margin-top: 0.75rem;
            color: #fff;
        }
        .stat-footer {
            margin-top: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        /* Charts Section */
        .charts-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }
        .chart-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            min-height: 350px;
        }
        .chart-card h2 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #fff;
            border-left: 3px solid var(--accent);
            padding-left: 0.5rem;
        }
        .chart-container {
            position: relative;
            height: 250px;
            width: 100%;
        }
        
        /* Table Controls */
        .controls-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.25rem 1.5rem;
            backdrop-filter: blur(12px);
            margin-bottom: 1.5rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            justify-content: space-between;
        }
        .search-wrapper {
            position: relative;
            flex: 1;
            min-width: 280px;
        }
        .search-input {
            width: 100%;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            padding: 0.75rem 1rem;
            border-radius: 10px;
            color: #fff;
            font-size: 0.9rem;
            transition: var(--transition);
        }
        .search-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 2px var(--accent-glow);
        }
        .filters-wrapper {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .filter-select {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            color: #fff;
            padding: 0.75rem 1rem;
            border-radius: 10px;
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
            transition: var(--transition);
        }
        .filter-select:focus {
            border-color: var(--accent);
        }
        .filter-select option {
            background: var(--bg-color);
            color: #fff;
        }
        .export-btn {
            background: linear-gradient(135deg, var(--accent) 0%, #00b0ff 100%);
            border: none;
            color: #0b0f19;
            padding: 0.75rem 1.25rem;
            border-radius: 10px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .export-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px var(--accent-glow);
            filter: brightness(1.1);
        }
        
        /* Data Table */
        .table-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            backdrop-filter: blur(12px);
            overflow: hidden;
            margin-bottom: 2rem;
        }
        .table-responsive {
            overflow-x: auto;
            width: 100%;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.88rem;
        }
        th {
            background: rgba(15, 23, 42, 0.4);
            padding: 1rem 1.25rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--card-border);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            cursor: pointer;
            user-select: none;
        }
        th:hover {
            color: #fff;
        }
        td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: middle;
            color: var(--text-primary);
        }
        tr {
            transition: var(--transition);
        }
        tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-tcp { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
        .badge-udp { background: rgba(167, 139, 250, 0.15); color: #a78bfa; }
        .badge-private { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .badge-public { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
        .badge-loopback { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
        .badge-apipa { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        
        .threat-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-weight: 600;
        }
        .threat-indicator.danger { color: var(--danger); }
        .threat-indicator.normal { color: var(--success); }
        .threat-indicator.warning { color: var(--warning); }
        
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }
        .dot-danger { background-color: var(--danger); box-shadow: 0 0 6px var(--danger); }
        .dot-success { background-color: var(--success); box-shadow: 0 0 6px var(--success); }
        .dot-warning { background-color: var(--warning); box-shadow: 0 0 6px var(--warning); }
        
        .process-cell {
            display: flex;
            flex-direction: column;
        }
        .process-name {
            font-weight: 600;
            color: #fff;
            text-overflow: ellipsis;
            overflow: hidden;
            max-width: 250px;
            white-space: nowrap;
        }
        .process-pid {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }
        
        /* Pagination */
        .pagination-bar {
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-top: 1px solid var(--card-border);
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        .page-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--card-border);
            color: #fff;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
        }
        .page-btn:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--accent);
        }
        .page-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        
        /* Services & Command lines */
        .service-tag {
            font-size: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 0.15rem 0.35rem;
            border-radius: 4px;
            margin-right: 0.25rem;
            color: var(--text-secondary);
            display: inline-block;
            max-width: 150px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        /* Tooltip */
        .tooltip {
            position: relative;
            cursor: help;
        }
        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background: #0f172a;
            border: 1px solid var(--card-border);
            color: #fff;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            white-space: nowrap;
            z-index: 10;
            box-shadow: 0 4px 10px rgba(0,0,0,0.5);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>&#127760; Windows Advanced Network Monitor</h1>
                <p>Comprehensive network connections, process mapping, and service correlation dashboard.</p>
            </div>
            <div class="timestamp-badge" id="report-timestamp">Generating...</div>
        </header>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">Total Connections</div>
                <div class="stat-value" id="stat-total">0</div>
                <div class="stat-footer" id="stat-proto-split">TCP: 0 | UDP: 0</div>
            </div>
            <div class="stat-card threat" id="threat-card">
                <div class="stat-header">Threat Analysis</div>
                <div class="stat-value" id="stat-threats">0</div>
                <div class="stat-footer" id="stat-threats-desc">Suspicious connections flagged</div>
            </div>
            <div class="stat-card">
                <div class="stat-header">Active Adapters</div>
                <div class="stat-value" id="stat-adapters">0</div>
                <div class="stat-footer" id="stat-bandwidth">Total Speed: 0 B/s</div>
            </div>
            <div class="stat-card">
                <div class="stat-header">Top Talker</div>
                <div class="stat-value" id="stat-toptalker">N/A</div>
                <div class="stat-footer" id="stat-toptalker-count">0 connections</div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-row">
            <div class="chart-card">
                <h2>Protocol Distribution</h2>
                <div class="chart-container">
                    <canvas id="protoChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h2>IP Classifications</h2>
                <div class="chart-container">
                    <canvas id="ipChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h2>Top Network Processes</h2>
                <div class="chart-container">
                    <canvas id="procChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Table Controls -->
        <div class="controls-card">
            <div class="search-wrapper">
                <input type="text" class="search-input" id="searchInput" placeholder="Search by IP, Port, Process Name, PID, Services...">
            </div>
            <div class="filters-wrapper">
                <select class="filter-select" id="filterProto">
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                </select>
                <select class="filter-select" id="filterIPClass">
                    <option value="ALL">All IP Classes</option>
                    <option value="Public">Public IP</option>
                    <option value="Private">Private IP</option>
                    <option value="Loopback">Loopback</option>
                    <option value="APIPA">APIPA</option>
                </select>
                <select class="filter-select" id="filterThreat">
                    <option value="ALL">All Security Statuses</option>
                    <option value="SUSPICIOUS">Suspicious Only</option>
                    <option value="NORMAL">Normal Only</option>
                </select>
                <button class="export-btn" id="exportBtn">
                    &#128229; Export CSV
                </button>
            </div>
        </div>

        <!-- Data Table -->
        <div class="table-card">
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th id="th-proto">Proto</th>
                            <th id="th-local">Local Address</th>
                            <th id="th-remote">Remote Address</th>
                            <th id="th-remotehost">Remote Hostname</th>
                            <th id="th-ipclass">IP Class</th>
                            <th id="th-state">State</th>
                            <th id="th-process">Process (PID)</th>
                            <th id="th-services">Services</th>
                            <th id="th-security">Security</th>
                        </tr>
                    </thead>
                    <tbody id="connectionsTableBody">
                        <!-- Filled by JS -->
                    </tbody>
                </table>
            </div>
            <div class="pagination-bar">
                <button class="page-btn" id="btnPrev" disabled>Previous</button>
                <span id="pageInfo">Page 1 of 1 (Showing 0-0 of 0)</span>
                <button class="page-btn" id="btnNext" disabled>Next</button>
            </div>
        </div>
    </div>

    <script>
        // Injected data - base64 decoded from placeholder values
        const connectionData = JSON.parse(atob("__CONN_DATA__"));
        const adapterData = JSON.parse(atob("__ADAPTER_DATA__"));
        const summaryData = JSON.parse(atob("__SUMMARY_DATA__"));

        // Global State
        let filteredData = [...connectionData];
        let currentPage = 1;
        const recordsPerPage = 15;
        let currentSortColumn = "";
        let currentSortOrder = "asc"; // "asc" or "desc"

        // Initialize UI Elements
        document.getElementById("report-timestamp").innerText = "Generated: " + summaryData.Timestamp;
        document.getElementById("stat-total").innerText = summaryData.TotalConnections;
        document.getElementById("stat-proto-split").innerText = "TCP: " + summaryData.TCPCount + " | UDP: " + summaryData.UDPCount;
        
        const threatsCount = summaryData.SuspiciousCount || 0;
        document.getElementById("stat-threats").innerText = threatsCount;
        const threatCard = document.getElementById("threat-card");
        if (threatsCount > 0) {
            threatCard.style.borderColor = "var(--danger)";
            document.getElementById("stat-threats").style.color = "var(--danger)";
            document.getElementById("stat-threats-desc").innerText = threatsCount + " flagged connections!";
            document.getElementById("stat-threats-desc").style.color = "var(--danger)";
        } else {
            document.getElementById("stat-threats").style.color = "var(--success)";
            document.getElementById("stat-threats-desc").innerText = "No threats detected";
        }

        // Adapters & Speed
        document.getElementById("stat-adapters").innerText = adapterData.length;
        let totalSentSpeed = 0;
        let totalRecvSpeed = 0;
        adapterData.forEach(ad => {
            totalSentSpeed += ad.SentRate_Bps || 0;
            totalRecvSpeed += ad.ReceivedRate_Bps || 0;
        });
        document.getElementById("stat-bandwidth").innerText = "Recv: " + formatBytes(totalRecvSpeed) + "/s | Sent: " + formatBytes(totalSentSpeed) + "/s";

        // Top Talker
        if (summaryData.TopTalkerProcess) {
            document.getElementById("stat-toptalker").innerText = summaryData.TopTalkerProcess;
            document.getElementById("stat-toptalker-count").innerText = summaryData.TopTalkerCount + " active connections";
            document.getElementById("stat-toptalker").setAttribute("data-tooltip", summaryData.TopTalkerProcess + " (" + summaryData.TopTalkerCount + " connections)");
        } else {
            document.getElementById("stat-toptalker").innerText = "N/A";
        }

        // Helper function to format bytes
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        // Filter Logic
        function applyFilters() {
            const searchQuery = document.getElementById("searchInput").value.toLowerCase();
            const protoFilter = document.getElementById("filterProto").value;
            const ipFilter = document.getElementById("filterIPClass").value;
            const threatFilter = document.getElementById("filterThreat").value;

            filteredData = connectionData.filter(item => {
                // Search query
                const procName = (item.ProcessName || "").toLowerCase();
                const pid = String(item.OwningProcessId || "");
                const local = (item.LocalAddress + ":" + item.LocalPort).toLowerCase();
                const remote = (item.RemoteAddress + ":" + item.RemotePort).toLowerCase();
                const hostname = (item.RemoteHostName || "").toLowerCase();
                const services = (item.Services || "").toLowerCase();
                const path = (item.ProcessPath || "").toLowerCase();

                const matchesSearch = !searchQuery || 
                    procName.includes(searchQuery) || 
                    pid.includes(searchQuery) || 
                    local.includes(searchQuery) || 
                    remote.includes(searchQuery) || 
                    hostname.includes(searchQuery) ||
                    path.includes(searchQuery) || 
                    services.includes(searchQuery);

                // Protocol
                const matchesProto = protoFilter === "ALL" || item.Protocol === protoFilter;

                // IP Class
                const matchesIPClass = ipFilter === "ALL" || item.RemoteIPClass.startsWith(ipFilter);

                // Threat Status
                const matchesThreat = threatFilter === "ALL" || 
                    (threatFilter === "SUSPICIOUS" && item.IsSuspicious) || 
                    (threatFilter === "NORMAL" && !item.IsSuspicious);

                return matchesSearch && matchesProto && matchesIPClass && matchesThreat;
            });

            currentPage = 1;
            renderTable();
        }

        // Setup Sort listeners
        const tableHeaders = [
            { id: "th-proto", field: "Protocol" },
            { id: "th-local", field: "LocalPort" },
            { id: "th-remote", field: "RemoteAddress" },
            { id: "th-remotehost", field: "RemoteHostName" },
            { id: "th-ipclass", field: "RemoteIPClass" },
            { id: "th-state", field: "State" },
            { id: "th-process", field: "ProcessName" },
            { id: "th-services", field: "Services" },
            { id: "th-security", field: "ThreatScore" }
        ];

        tableHeaders.forEach(header => {
            const el = document.getElementById(header.id);
            if (el) {
                el.addEventListener("click", () => {
                    if (currentSortColumn === header.field) {
                        currentSortOrder = currentSortOrder === "asc" ? "desc" : "asc";
                    } else {
                        currentSortColumn = header.field;
                        currentSortOrder = "asc";
                    }
                    sortData();
                    renderTable();
                });
            }
        });

        function sortData() {
            if (!currentSortColumn) return;
            filteredData.sort((a, b) => {
                let valA = a[currentSortColumn];
                let valB = b[currentSortColumn];

                if (valA === null || valA === undefined) valA = "";
                if (valB === null || valB === undefined) valB = "";

                if (typeof valA === 'string') {
                    return currentSortOrder === "asc" 
                        ? valA.localeCompare(valB) 
                        : valB.localeCompare(valA);
                } else {
                    return currentSortOrder === "asc" 
                        ? valA - valB 
                        : valB - valA;
                }
            });
        }

        // Render Table
        function renderTable() {
            const tbody = document.getElementById("connectionsTableBody");
            tbody.innerHTML = "";

            const totalRecords = filteredData.length;
            const totalPages = Math.max(1, Math.ceil(totalRecords / recordsPerPage));

            if (currentPage > totalPages) currentPage = totalPages;

            const startIndex = (currentPage - 1) * recordsPerPage;
            const endIndex = Math.min(startIndex + recordsPerPage, totalRecords);

            // Update Pagination info
            document.getElementById("btnPrev").disabled = currentPage === 1;
            document.getElementById("btnNext").disabled = currentPage === totalPages || totalRecords === 0;
            
            if (totalRecords === 0) {
                document.getElementById("pageInfo").innerText = "No entries found";
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-secondary); padding: 3rem;">&#128269; No connections match the search/filter criteria.</td></tr>`;
                return;
            }

            document.getElementById("pageInfo").innerText = "Page " + currentPage + " of " + totalPages + " (Showing " + (startIndex + 1) + "-" + endIndex + " of " + totalRecords + ")";

            const pageSlice = filteredData.slice(startIndex, endIndex);

            pageSlice.forEach(item => {
                const tr = document.createElement("tr");

                // Proto Badge
                const protoBadge = item.Protocol === "TCP" ? "badge-tcp" : "badge-udp";
                const tdProto = '<td><span class="badge ' + protoBadge + '">' + item.Protocol + '</span></td>';

                // Address cells
                const tdLocal = '<td>' + item.LocalAddress + ':' + item.LocalPort + '</td>';
                const tdRemote = '<td>' + item.RemoteAddress + ':' + item.RemotePort + '</td>';
                const tdHost = '<td style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="' + (item.RemoteHostName || '') + '">' + (item.RemoteHostName || '-') + '</td>';

                // IP Class Badge
                let ipBadge = "badge-public";
                if (item.RemoteIPClass.startsWith("Private")) ipBadge = "badge-private";
                else if (item.RemoteIPClass.startsWith("Loopback")) ipBadge = "badge-loopback";
                else if (item.RemoteIPClass.startsWith("APIPA")) ipBadge = "badge-apipa";
                const tdIPClass = '<td><span class="badge ' + ipBadge + '">' + item.RemoteIPClass + '</span></td>';

                // State
                const tdState = '<td><code>' + item.State + '</code></td>';

                // Process Info
                const serviceList = item.Services 
                    ? item.Services.split(', ').map(s => '<span class="service-tag" title="' + s + '">' + s + '</span>').join('')
                    : '';
                const tdProcess = '<td>' +
                    '<div class="process-cell">' +
                        '<span class="process-name" title="' + (item.ProcessPath || '') + '">' + item.ProcessName + '</span>' +
                        '<span class="process-pid">PID: ' + item.OwningProcessId + '</span>' +
                    '</div>' +
                '</td>';

                const tdServices = '<td style="max-width: 250px;">' + (serviceList || '-') + '</td>';

                // Security Status
                let threatIndicator = '<span class="threat-indicator normal"><span class="dot dot-success"></span>Safe</span>';
                if (item.IsSuspicious) {
                    threatIndicator = '<span class="threat-indicator danger tooltip" data-tooltip="' + item.ThreatReasons + '"><span class="dot dot-danger"></span>Threat (' + item.ThreatScore + ')</span>';
                } else if (item.ThreatScore > 0) {
                    threatIndicator = '<span class="threat-indicator warning tooltip" data-tooltip="' + item.ThreatReasons + '"><span class="dot dot-warning"></span>Alert (' + item.ThreatScore + ')</span>';
                }
                const tdSecurity = '<td>' + threatIndicator + '</td>';

                tr.innerHTML = tdProto + tdLocal + tdRemote + tdHost + tdIPClass + tdState + tdProcess + tdServices + tdSecurity;
                tbody.appendChild(tr);
            });
        }

        // Export to CSV Function
        document.getElementById("exportBtn").addEventListener("click", () => {
            if (filteredData.length === 0) return;
            
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessName,PID,ProcessPath,Services,IPClass,Hostname,ThreatScore,IsSuspicious,ThreatReasons\r\n";
            
            filteredData.forEach(item => {
                let row = [
                    item.Protocol,
                    item.LocalAddress,
                    item.LocalPort,
                    item.RemoteAddress,
                    item.RemotePort,
                    item.State,
                    '"' + item.ProcessName.replace(/"/g, '""') + '"',
                    item.OwningProcessId,
                    '"' + (item.ProcessPath || '').replace(/"/g, '""') + '"',
                    '"' + (item.Services || '').replace(/"/g, '""') + '"',
                    item.RemoteIPClass,
                    '"' + (item.RemoteHostName || '').replace(/"/g, '""') + '"',
                    item.ThreatScore,
                    item.IsSuspicious,
                    '"' + (item.ThreatReasons || '').replace(/"/g, '""') + '"'
                ];
                csvContent += row.join(",") + "\r\n";
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "NetworkReport_" + summaryData.Timestamp.replace(/[: ]/g, '_') + ".csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });

        // Pagination Buttons
        document.getElementById("btnPrev").addEventListener("click", () => {
            if (currentPage > 1) {
                currentPage--;
                renderTable();
            }
        });

        document.getElementById("btnNext").addEventListener("click", () => {
            const totalPages = Math.ceil(filteredData.length / recordsPerPage);
            if (currentPage < totalPages) {
                currentPage++;
                renderTable();
            }
        });

        // Event listeners for inputs
        document.getElementById("searchInput").addEventListener("input", applyFilters);
        document.getElementById("filterProto").addEventListener("change", applyFilters);
        document.getElementById("filterIPClass").addEventListener("change", applyFilters);
        document.getElementById("filterThreat").addEventListener("change", applyFilters);

        // Chart.js Graphs Setup
        // 1. Protocol Chart
        const protoCtx = document.getElementById('protoChart').getContext('2d');
        const protoChart = new Chart(protoCtx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP'],
                datasets: [{
                    data: [summaryData.TCPCount, summaryData.UDPCount],
                    backgroundColor: ['#38bdf8', '#a78bfa'],
                    borderColor: 'rgba(255, 255, 255, 0.05)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans' } }
                    }
                }
            }
        });

        // 2. IP Class Chart
        const ipCounts = { Public: 0, Private: 0, Loopback: 0, APIPA: 0 };
        connectionData.forEach(item => {
            let cls = "Public";
            if (item.RemoteIPClass.startsWith("Private")) cls = "Private";
            else if (item.RemoteIPClass.startsWith("Loopback")) cls = "Loopback";
            else if (item.RemoteIPClass.startsWith("APIPA")) cls = "APIPA";
            if (ipCounts[cls] !== undefined) {
                ipCounts[cls]++;
            }
        });
        const ipCtx = document.getElementById('ipChart').getContext('2d');
        const ipChart = new Chart(ipCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(ipCounts),
                datasets: [{
                    label: 'Connections',
                    data: Object.values(ipCounts),
                    backgroundColor: ['#f59e0b', '#10b981', '#94a3b8', '#f87171'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });

        // 3. Top Processes Chart
        const procCounts = {};
        connectionData.forEach(item => {
            procCounts[item.ProcessName] = (procCounts[item.ProcessName] || 0) + 1;
        });
        const sortedProcs = Object.entries(procCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);

        const procCtx = document.getElementById('procChart').getContext('2d');
        const procChart = new Chart(procCtx, {
            type: 'bar',
            data: {
                labels: sortedProcs.map(p => p[0]),
                datasets: [{
                    label: 'Connections',
                    data: sortedProcs.map(p => p[1]),
                    backgroundColor: 'rgba(0, 240, 255, 0.75)',
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                }
            }
        });

        // Initial table load
        renderTable();
    </script>
</body>
</html>
'@
            # Replace placeholders in HTML string
            $html = $htmlTemplate.Replace("__CONN_DATA__", $connBase64).Replace("__ADAPTER_DATA__", $adapterBase64).Replace("__SUMMARY_DATA__", $summaryBase64)
            $html | Out-File $Path -Encoding UTF8 -Force
        }
        
        'JSON' {
            $Data | ConvertTo-Json -Depth 10 | Set-Content $Path -Encoding UTF8 -Force
        }
        
        'CSV' {
            $Data.Connections | Export-Csv $Path -NoTypeInformation -Encoding UTF8 -Force
        }
    }
}

# Initializing Advanced Network Monitor execution
Load-CacheFiles

# Default output paths
if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    if ($OutputFormat -eq "HTML") {
        $OutputPath = Join-Path $PSScriptRoot "NetworkReport_$timestamp.html"
    } elseif ($OutputFormat -eq "CSV") {
        $OutputPath = Join-Path $PSScriptRoot "NetworkReport_$timestamp.csv"
    } else {
        $OutputPath = Join-Path $PSScriptRoot "NetworkReport_$timestamp.json"
    }
}

# Default monitor log path
if (-not $MonitorLogPath) {
    $timestamp = Get-Date -Format "yyyyMMdd"
    $MonitorLogPath = Join-Path $PSScriptRoot "ConnectionChanges_$timestamp.log"
}

if ($Mode -eq "Report" -or $Mode -eq "Dashboard") {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "[*] Initializing Advanced Network Monitor Report (Mode: $Mode)..."
    
    # Measure Throughput
    Write-Host "[*] Measuring network throughput (1s snapshot)..."
    $adapters = Get-NetworkAdapterThroughput
    
    # Enrich active connections
    Write-Host "[*] Collecting and auditing active network connections..."
    $connections = Get-EnrichedConnections -DetectThreats:$DetectThreats -ThrottleLimit:$ThrottleLimit -EnableGeoIP:$EnableGeoIP
    
    # Calculate summaries
    $tcpCount = @($connections | Where-Object { $_.Protocol -eq "TCP" }).Count
    $udpCount = @($connections | Where-Object { $_.Protocol -eq "UDP" }).Count
    $suspiciousCount = @($connections | Where-Object { $_.IsSuspicious -eq $true }).Count
    
    # Find top talker
    $topTalker = $connections | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 1
    $topTalkerProcess = if ($topTalker) { $topTalker.Name } else { "N/A" }
    $topTalkerCount = if ($topTalker) { $topTalker.Count } else { 0 }
    
    $summary = [PSCustomObject]@{
        Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalConnections = @($connections).Count
        TCPCount         = $tcpCount
        UDPCount         = $udpCount
        SuspiciousCount  = $suspiciousCount
        TopTalkerProcess = $topTalkerProcess
        TopTalkerCount   = $topTalkerCount
    }
    
    $reportData = [PSCustomObject]@{
        Summary     = $summary
        Adapters    = $adapters
        Connections = $connections
    }
    
    # Generate report
    Write-Host "[*] Generating $OutputFormat report..."
    New-AdvancedReport -Data $reportData -Format $OutputFormat -Path $OutputPath
    Write-Host "[OK] Report successfully saved to: $OutputPath"
    
    $stopwatch.Stop()
    Write-Host "[*] Completed in $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds"
    
    if ($Mode -eq "Dashboard") {
        Write-Host "[OK] Opening interactive dashboard in browser..."
        Start-Process $OutputPath
    }
}
elseif ($Mode -eq "Monitor") {
    Write-Host "======================================================================"
    Write-Host "[*] Starting Real-Time Connection Monitor (Interval: $MonitorInterval seconds)"
    Write-Host "[*] Logs are saved to: $MonitorLogPath"
    Write-Host "Press Ctrl+C to stop monitoring and save DNS caches."
    Write-Host "======================================================================"
    
    # Setup log directory
    $logDir = Split-Path $MonitorLogPath
    if (-not (Test-Path $logDir)) {
        $null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue
    }
    
    # Track existing connections snapshot
    Write-Host "[*] Establishing baseline snapshot of active connections..."
    $connections = Get-EnrichedConnections -DetectThreats:$DetectThreats -ThrottleLimit:$ThrottleLimit -EnableGeoIP:$EnableGeoIP
    $snapshot = @{}
    foreach ($c in $connections) {
        $key = "$($c.Protocol)_$($c.LocalAddress)_$($c.LocalPort)_$($c.RemoteAddress)_$($c.RemotePort)_$($c.OwningProcessId)"
        $snapshot[$key] = $c
    }
    Write-Host "[OK] Baseline active connections: $($snapshot.Count)"
    
    while ($true) {
        Start-Sleep -Seconds $MonitorInterval
        
        $currentConnections = Get-EnrichedConnections -DetectThreats:$DetectThreats -ThrottleLimit:$ThrottleLimit -EnableGeoIP:$EnableGeoIP
        $currentKeys = @{}
        
        # Detect new connections
        foreach ($c in $currentConnections) {
            $key = "$($c.Protocol)_$($c.LocalAddress)_$($c.LocalPort)_$($c.RemoteAddress)_$($c.RemotePort)_$($c.OwningProcessId)"
            $currentKeys[$key] = $c
            
            if (-not $snapshot.ContainsKey($key)) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logMsg = "[$timestamp] [NEW] $($c.Protocol) $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) (Process: $($c.ProcessName), PID: $($c.OwningProcessId))"
                
                # Check for threats
                if ($c.IsSuspicious) {
                    $logMsg += " [!] THREAT WARNING: $($c.ThreatReasons)"
                    Write-Host $logMsg -ForegroundColor Red
                } else {
                    Write-Host $logMsg -ForegroundColor Green
                }
                
                $logMsg | Out-File $MonitorLogPath -Append -Encoding UTF8
            }
        }
        
        # Detect closed connections
        foreach ($key in $snapshot.Keys) {
            if (-not $currentKeys.ContainsKey($key)) {
                $c = $snapshot[$key]
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logMsg = "[$timestamp] [CLOSED] $($c.Protocol) $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) (Process: $($c.ProcessName), PID: $($c.OwningProcessId))"
                
                Write-Host $logMsg -ForegroundColor DarkYellow
                $logMsg | Out-File $MonitorLogPath -Append -Encoding UTF8
            }
        }
        
        # Update snapshot
        $snapshot = $currentKeys
    }
}

# Save cache on exit
Save-CacheFiles