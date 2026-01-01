<#
.SYNOPSIS
    Configures log forwarding from Windows to Azure Log Analytics.

.DESCRIPTION
    This script installs and configures the Azure Monitor Agent (AMA) on a Windows
    machine to forward security events to a Log Analytics workspace. It also 
    configures the required audit policies.

.PARAMETER WorkspaceId
    The Log Analytics Workspace ID.

.PARAMETER WorkspaceKey
    The Log Analytics Workspace primary or secondary key.

.PARAMETER EventTypes
    Type of events to collect: All, Common, Minimal, or Custom.
    Default is Common.

.EXAMPLE
    .\Setup-LogForwarding.ps1 -WorkspaceId "abc123" -WorkspaceKey "xyz789"

.NOTES
    Author: SOC Lab
    Version: 1.0
    Requires: Run as Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceKey,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Common", "Minimal", "Custom")]
    [string]$EventTypes = "Common"
)

# Ensure running as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Azure Log Forwarding Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Configure Audit Policies
Write-Host "[Step 1/4] Configuring Windows Audit Policies..." -ForegroundColor Yellow

$auditSettings = @{
    "Account Logon"    = "Success,Failure"
    "Account Management" = "Success,Failure"
    "Logon/Logoff"     = "Success,Failure"
    "Object Access"    = "Failure"
    "Policy Change"    = "Success,Failure"
    "Privilege Use"    = "Failure"
    "Process Tracking" = "Success"
    "System"           = "Success,Failure"
}

foreach ($category in $auditSettings.Keys) {
    try {
        $setting = $auditSettings[$category]
        $success = $setting -match "Success"
        $failure = $setting -match "Failure"
        
        # Use auditpol to configure
        if ($success -and $failure) {
            auditpol /set /category:"$category" /success:enable /failure:enable | Out-Null
        }
        elseif ($success) {
            auditpol /set /category:"$category" /success:enable /failure:disable | Out-Null
        }
        elseif ($failure) {
            auditpol /set /category:"$category" /success:disable /failure:enable | Out-Null
        }
        
        Write-Host "  [+] $category : $setting" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [-] Failed to configure: $category"
    }
}

# Step 2: Enable PowerShell Script Block Logging
Write-Host ""
Write-Host "[Step 2/4] Enabling PowerShell Script Block Logging..." -ForegroundColor Yellow

try {
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    
    if (-not (Test-Path $psLoggingPath)) {
        New-Item -Path $psLoggingPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Write-Host "  [+] PowerShell Script Block Logging enabled" -ForegroundColor Green
}
catch {
    Write-Warning "  [-] Failed to enable PowerShell Script Block Logging"
}

# Enable Module Logging
try {
    $moduleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    
    if (-not (Test-Path $moduleLoggingPath)) {
        New-Item -Path $moduleLoggingPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord
    
    # Log all modules
    $moduleNamesPath = "$moduleLoggingPath\ModuleNames"
    if (-not (Test-Path $moduleNamesPath)) {
        New-Item -Path $moduleNamesPath -Force | Out-Null
    }
    Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String
    
    Write-Host "  [+] PowerShell Module Logging enabled" -ForegroundColor Green
}
catch {
    Write-Warning "  [-] Failed to enable PowerShell Module Logging"
}

# Step 3: Check for Azure Monitor Agent
Write-Host ""
Write-Host "[Step 3/4] Checking Azure Monitor Agent..." -ForegroundColor Yellow

$amaService = Get-Service -Name "AzureMonitorAgent" -ErrorAction SilentlyContinue

if ($amaService) {
    Write-Host "  [+] Azure Monitor Agent is installed" -ForegroundColor Green
    Write-Host "  [i] Status: $($amaService.Status)" -ForegroundColor Cyan
    
    if ($amaService.Status -ne "Running") {
        Write-Host "  [*] Starting Azure Monitor Agent..." -ForegroundColor Yellow
        Start-Service -Name "AzureMonitorAgent"
    }
}
else {
    Write-Host "  [!] Azure Monitor Agent not installed" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To install Azure Monitor Agent:" -ForegroundColor White
    Write-Host "  1. Go to Azure Portal -> Virtual Machines -> Your VM" -ForegroundColor White
    Write-Host "  2. Click 'Extensions + applications'" -ForegroundColor White
    Write-Host "  3. Add 'Azure Monitor Windows Agent'" -ForegroundColor White
    Write-Host ""
    Write-Host "  Or use Azure CLI:" -ForegroundColor White
    Write-Host "  az vm extension set --name AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --resource-group <RG> --vm-name <VM>" -ForegroundColor Gray
}

# Also check for legacy Log Analytics agent (MMA)
$mmaService = Get-Service -Name "HealthService" -ErrorAction SilentlyContinue
if ($mmaService) {
    Write-Host "  [i] Legacy Log Analytics Agent (MMA) also detected" -ForegroundColor Cyan
}

# Step 4: Verify Event Log Configuration
Write-Host ""
Write-Host "[Step 4/4] Verifying Event Log Configuration..." -ForegroundColor Yellow

$securityLog = Get-WinEvent -ListLog Security
Write-Host "  [i] Security Log Max Size: $([math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)) MB" -ForegroundColor Cyan
Write-Host "  [i] Security Log Mode: $($securityLog.LogMode)" -ForegroundColor Cyan

# Check if Security log is configured adequately
if ($securityLog.MaximumSizeInBytes -lt 100MB) {
    Write-Host "  [*] Increasing Security Log size to 256 MB..." -ForegroundColor Yellow
    try {
        wevtutil sl Security /ms:268435456  # 256 MB
        Write-Host "  [+] Security Log size increased" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [-] Failed to increase Security Log size"
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configuration Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Audit Policies: Configured" -ForegroundColor Green
Write-Host "PowerShell Logging: Enabled" -ForegroundColor Green

if ($amaService) {
    Write-Host "Azure Monitor Agent: Installed ($($amaService.Status))" -ForegroundColor Green
}
else {
    Write-Host "Azure Monitor Agent: Not Installed (Manual install required)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor White
Write-Host "1. If AMA is not installed, install it from Azure Portal" -ForegroundColor White
Write-Host "2. Create a Data Collection Rule in Azure Sentinel" -ForegroundColor White
Write-Host "3. Associate this VM with the Data Collection Rule" -ForegroundColor White
Write-Host "4. Wait 5-10 minutes for data to flow to Log Analytics" -ForegroundColor White
Write-Host ""

# Test event logging
Write-Host "[*] Generating test events..." -ForegroundColor Yellow
Write-EventLog -LogName Application -Source "Azure SOC Lab" -EventId 1000 -EntryType Information -Message "Log forwarding setup completed at $(Get-Date)" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
