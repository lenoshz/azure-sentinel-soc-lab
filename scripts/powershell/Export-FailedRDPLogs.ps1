<#
.SYNOPSIS
    Exports failed RDP login events from Windows Security Log.

.DESCRIPTION
    This script extracts failed RDP login attempts (Event ID 4625) from the 
    Windows Security Event Log and exports them to a CSV file for analysis.
    It includes IP geolocation data if the Get-GeoLocation.ps1 script is available.

.PARAMETER Hours
    Number of hours to look back for events. Default is 24.

.PARAMETER OutputPath
    Path where the CSV file will be saved. Default is current directory.

.PARAMETER IncludeGeoLocation
    If specified, attempts to enrich data with IP geolocation.

.EXAMPLE
    .\Export-FailedRDPLogs.ps1 -Hours 48 -OutputPath "C:\Logs"

.EXAMPLE
    .\Export-FailedRDPLogs.ps1 -IncludeGeoLocation

.NOTES
    Author: SOC Lab
    Version: 1.0
    Requires: Run as Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 24,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PWD,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGeoLocation
)

# Ensure running as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Failed RDP Login Log Exporter" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Calculate time range
$startTime = (Get-Date).AddHours(-$Hours)
Write-Host "[*] Searching for events in the last $Hours hours..." -ForegroundColor Yellow
Write-Host "[*] Start time: $startTime" -ForegroundColor Yellow

# Query failed RDP logins (Event ID 4625, Logon Type 10)
try {
    Write-Host "[*] Querying Security Event Log for Event ID 4625..." -ForegroundColor Yellow
    
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4625
        StartTime = $startTime
    } -ErrorAction Stop

    Write-Host "[+] Found $($events.Count) failed login events" -ForegroundColor Green
}
catch [System.Exception] {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "[!] No failed login events found in the specified time range." -ForegroundColor Yellow
        exit 0
    }
    else {
        Write-Error "Error querying event log: $_"
        exit 1
    }
}

# Parse events
$failedLogins = @()

Write-Host "[*] Parsing events..." -ForegroundColor Yellow

foreach ($event in $events) {
    # Parse XML data
    $xml = [xml]$event.ToXml()
    $eventData = $xml.Event.EventData.Data

    # Extract relevant fields
    $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $targetDomain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $sourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $sourcePort = ($eventData | Where-Object { $_.Name -eq 'IpPort' }).'#text'
    $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    $failureReason = ($eventData | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
    $subStatus = ($eventData | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
    $workstation = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'

    # Only include RDP logins (LogonType 10) or Network logins (LogonType 3)
    if ($logonType -notin @('10', '3')) {
        continue
    }

    # Skip local IPs
    if ($sourceIP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|-)') {
        continue
    }

    # Create object
    $loginAttempt = [PSCustomObject]@{
        TimeGenerated    = $event.TimeCreated
        TargetUser       = $targetUser
        TargetDomain     = $targetDomain
        SourceIP         = $sourceIP
        SourcePort       = $sourcePort
        LogonType        = $logonType
        LogonTypeDesc    = if ($logonType -eq '10') { 'RDP' } elseif ($logonType -eq '3') { 'Network' } else { $logonType }
        FailureReason    = $failureReason
        SubStatus        = $subStatus
        WorkstationName  = $workstation
        Computer         = $event.MachineName
        Country          = $null
        City             = $null
        Latitude         = $null
        Longitude        = $null
    }

    $failedLogins += $loginAttempt
}

Write-Host "[+] Parsed $($failedLogins.Count) RDP/Network failed logins from external IPs" -ForegroundColor Green

# Optionally add geolocation data
if ($IncludeGeoLocation -and $failedLogins.Count -gt 0) {
    Write-Host "[*] Enriching with geolocation data..." -ForegroundColor Yellow
    
    $geoScript = Join-Path $PSScriptRoot "Get-GeoLocation.ps1"
    
    if (Test-Path $geoScript) {
        . $geoScript
        
        $uniqueIPs = $failedLogins | Select-Object -ExpandProperty SourceIP -Unique
        $geoCache = @{}
        
        foreach ($ip in $uniqueIPs) {
            if ($ip -and $ip -ne '-') {
                try {
                    $geoData = Get-GeoLocation -IPAddress $ip
                    $geoCache[$ip] = $geoData
                }
                catch {
                    Write-Warning "Could not get geolocation for IP: $ip"
                }
                Start-Sleep -Milliseconds 500  # Rate limiting
            }
        }
        
        # Update records with geo data
        foreach ($login in $failedLogins) {
            if ($geoCache.ContainsKey($login.SourceIP)) {
                $geo = $geoCache[$login.SourceIP]
                $login.Country = $geo.Country
                $login.City = $geo.City
                $login.Latitude = $geo.Latitude
                $login.Longitude = $geo.Longitude
            }
        }
        
        Write-Host "[+] Geolocation enrichment complete" -ForegroundColor Green
    }
    else {
        Write-Warning "Get-GeoLocation.ps1 not found. Skipping geolocation enrichment."
    }
}

# Generate summary statistics
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Summary Statistics" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$stats = $failedLogins | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 10
Write-Host ""
Write-Host "Top 10 Attacking IPs:" -ForegroundColor Yellow
$stats | ForEach-Object {
    Write-Host ("  {0,-20} : {1} attempts" -f $_.Name, $_.Count)
}

$userStats = $failedLogins | Group-Object TargetUser | Sort-Object Count -Descending | Select-Object -First 10
Write-Host ""
Write-Host "Top 10 Targeted Accounts:" -ForegroundColor Yellow
$userStats | ForEach-Object {
    Write-Host ("  {0,-20} : {1} attempts" -f $_.Name, $_.Count)
}

# Export to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path $OutputPath "FailedRDPLogins_$timestamp.csv"

try {
    $failedLogins | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host ""
    Write-Host "[+] Exported $($failedLogins.Count) records to: $csvPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export CSV: $_"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Export Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
