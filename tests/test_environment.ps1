# Windows Advanced Network Monitor - Environment Test Script
# Verifies system requirements, privileges, and CIM class access.

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Environment Test: Windows Advanced Network Monitor" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$success = $true

# 1. Check Operating System
Write-Host -NoNewline "Checking OS Platform... "
if ($PSVersionTable.OS -or $env:OS -eq "Windows_NT") {
    Write-Host "PASS (Windows)" -ForegroundColor Green
} else {
    Write-Host "FAIL (Non-Windows platform)" -ForegroundColor Red
    $success = $false
}

# 2. Check PowerShell Version
Write-Host -NoNewline "Checking PowerShell Version... "
$psVersion = $PSVersionTable.PSVersion
Write-Host "Found v$psVersion (Required: 5.1+)" -ForegroundColor Yellow
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-Host "  Failed: PowerShell version is too old. Please upgrade to 5.1 or 7+." -ForegroundColor Red
    $success = $false
} else {
    Write-Host "  Passed" -ForegroundColor Green
}

# 3. Check Administrative Privileges
Write-Host -NoNewline "Checking Administrator Privileges... "
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "PASS (Admin privileges verified)" -ForegroundColor Green
} else {
    Write-Host "WARNING (Running as Standard User)" -ForegroundColor Yellow
    Write-Host "  Note: Running as standard user works but will limit process/service mappings for system processes." -ForegroundColor Yellow
}

# 4. Check Network Cmdlet Availability
Write-Host -NoNewline "Checking Network Connection Cmdlets... "
$tcpCmd = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
$udpCmd = Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue
if ($tcpCmd -and $udpCmd) {
    Write-Host "PASS" -ForegroundColor Green
} else {
    Write-Host "FAIL (Cmdlets not found)" -ForegroundColor Red
    Write-Host "  Failed: Get-NetTCPConnection or Get-NetUDPEndpoint is unavailable on this OS." -ForegroundColor Red
    $success = $false
}

# 5. Check CIM/WMI Classes
Write-Host -NoNewline "Checking CIM/WMI Interface Access... "
try {
    $null = Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object -First 1
    $null = Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object -First 1
    $null = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction Stop | Select-Object -First 1
    Write-Host "PASS" -ForegroundColor Green
} catch {
    Write-Host "FAIL" -ForegroundColor Red
    Write-Host "  Failed to query required CIM classes. Error: $_" -ForegroundColor Red
    $success = $false
}

Write-Host "==========================================" -ForegroundColor Cyan
if ($success) {
    Write-Host "System is ready to run Windows Advanced Network Monitor!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "System check failed. Please resolve the errors above." -ForegroundColor Red
    exit 1
}
