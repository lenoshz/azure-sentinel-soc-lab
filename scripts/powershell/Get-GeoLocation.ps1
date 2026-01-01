<#
.SYNOPSIS
    Gets geolocation information for an IP address.

.DESCRIPTION
    This script queries free IP geolocation APIs to retrieve location data
    for a given IP address. It supports multiple APIs with automatic fallback.

.PARAMETER IPAddress
    The IP address to look up.

.PARAMETER ApiKey
    Optional API key for ipgeolocation.io (provides higher rate limits).

.EXAMPLE
    .\Get-GeoLocation.ps1 -IPAddress "8.8.8.8"

.EXAMPLE
    Get-GeoLocation -IPAddress "1.1.1.1" -ApiKey "your_api_key"

.NOTES
    Author: SOC Lab
    Version: 1.0
    
    Free API Rate Limits:
    - ip-api.com: 45 requests/minute
    - ipgeolocation.io: 1000 requests/day (with free API key)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$IPAddress,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey = ""
)

function Get-GeoLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $false)]
        [string]$ApiKey = ""
    )

    # Validate IP address format
    if (-not ($IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')) {
        Write-Warning "Invalid IP address format: $IPAddress"
        return $null
    }

    # Skip private/reserved IPs
    if ($IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.|255\.)') {
        Write-Warning "Private/Reserved IP address: $IPAddress"
        return [PSCustomObject]@{
            IP        = $IPAddress
            Country   = "Private"
            CountryCode = "XX"
            Region    = "N/A"
            City      = "N/A"
            Latitude  = 0
            Longitude = 0
            ISP       = "Private Network"
            Timezone  = "N/A"
        }
    }

    # Try ip-api.com first (no API key required)
    try {
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$IPAddress" -Method Get -TimeoutSec 10
        
        if ($response.status -eq "success") {
            return [PSCustomObject]@{
                IP          = $IPAddress
                Country     = $response.country
                CountryCode = $response.countryCode
                Region      = $response.regionName
                City        = $response.city
                Latitude    = $response.lat
                Longitude   = $response.lon
                ISP         = $response.isp
                Timezone    = $response.timezone
                Source      = "ip-api.com"
            }
        }
    }
    catch {
        Write-Verbose "ip-api.com failed: $_"
    }

    # Fallback to ipgeolocation.io (requires API key for better limits)
    if ($ApiKey) {
        try {
            $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$ApiKey&ip=$IPAddress"
            $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10
            
            return [PSCustomObject]@{
                IP          = $IPAddress
                Country     = $response.country_name
                CountryCode = $response.country_code2
                Region      = $response.state_prov
                City        = $response.city
                Latitude    = [double]$response.latitude
                Longitude   = [double]$response.longitude
                ISP         = $response.isp
                Timezone    = $response.time_zone.name
                Source      = "ipgeolocation.io"
            }
        }
        catch {
            Write-Verbose "ipgeolocation.io failed: $_"
        }
    }

    # Fallback to ipinfo.io (no API key, limited data)
    try {
        $response = Invoke-RestMethod -Uri "https://ipinfo.io/$IPAddress/json" -Method Get -TimeoutSec 10
        
        $loc = $response.loc -split ','
        
        return [PSCustomObject]@{
            IP          = $IPAddress
            Country     = $response.country
            CountryCode = $response.country
            Region      = $response.region
            City        = $response.city
            Latitude    = if ($loc.Count -eq 2) { [double]$loc[0] } else { 0 }
            Longitude   = if ($loc.Count -eq 2) { [double]$loc[1] } else { 0 }
            ISP         = $response.org
            Timezone    = $response.timezone
            Source      = "ipinfo.io"
        }
    }
    catch {
        Write-Warning "All geolocation APIs failed for IP: $IPAddress"
        return $null
    }
}

# Main execution
if ($IPAddress) {
    $result = Get-GeoLocation -IPAddress $IPAddress -ApiKey $ApiKey
    
    if ($result) {
        Write-Host ""
        Write-Host "Geolocation Results for $IPAddress" -ForegroundColor Cyan
        Write-Host "=================================" -ForegroundColor Cyan
        Write-Host "Country:   $($result.Country) ($($result.CountryCode))"
        Write-Host "Region:    $($result.Region)"
        Write-Host "City:      $($result.City)"
        Write-Host "Latitude:  $($result.Latitude)"
        Write-Host "Longitude: $($result.Longitude)"
        Write-Host "ISP:       $($result.ISP)"
        Write-Host "Timezone:  $($result.Timezone)"
        Write-Host "Source:    $($result.Source)"
        Write-Host ""
        
        return $result
    }
}

# Export function for use by other scripts
Export-ModuleMember -Function Get-GeoLocation -ErrorAction SilentlyContinue
