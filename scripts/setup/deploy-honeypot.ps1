<#
.SYNOPSIS
    Deploys a Windows honeypot VM in Azure for the SOC Lab.

.DESCRIPTION
    This script automates the deployment of a Windows VM configured as a honeypot
    to attract RDP brute force attacks. It creates all necessary Azure resources
    including resource group, virtual network, NSG, and the VM itself.

.PARAMETER ResourceGroupName
    Name of the Azure Resource Group. Default: SOC-Lab-RG

.PARAMETER Location
    Azure region for deployment. Default: eastus

.PARAMETER VMName
    Name of the virtual machine. Default: Honeypot-VM

.PARAMETER AdminUsername
    Administrator username for the VM.

.PARAMETER AdminPassword
    Administrator password for the VM.

.PARAMETER VMSize
    Size of the VM. Default: Standard_B1s (cheapest)

.EXAMPLE
    .\deploy-honeypot.ps1 -AdminUsername "psychonaut" -AdminPassword "YourSecurePassword123!"

.NOTES
    Author: SOC Lab
    Version: 1.0
    Requires: Azure PowerShell module (Az)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "SOC-Lab-RG",

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$VMName = "Honeypot-VM",

    [Parameter(Mandatory = $true)]
    [string]$AdminUsername,

    [Parameter(Mandatory = $true)]
    [SecureString]$AdminPassword,

    [Parameter(Mandatory = $false)]
    [string]$VMSize = "Standard_B1s",

    [Parameter(Mandatory = $false)]
    [string]$VNetName = "SOC-Lab-VNet",

    [Parameter(Mandatory = $false)]
    [string]$SubnetName = "default",

    [Parameter(Mandatory = $false)]
    [string]$NSGName = "Honeypot-VM-nsg",

    [Parameter(Mandatory = $false)]
    [string]$PublicIPName = "Honeypot-VM-ip",

    [Parameter(Mandatory = $false)]
    [switch]$EnableAutoShutdown
)

# Check for Azure module
if (-not (Get-Module -ListAvailable -Name Az.Compute)) {
    Write-Error "Azure PowerShell module (Az) is required. Install with: Install-Module -Name Az -AllowClobber -Scope CurrentUser"
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Azure Honeypot VM Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Connect to Azure (if not already connected)
$context = Get-AzContext
if (-not $context) {
    Write-Host "[*] Connecting to Azure..." -ForegroundColor Yellow
    Connect-AzAccount
}
else {
    Write-Host "[+] Connected to Azure as: $($context.Account.Id)" -ForegroundColor Green
    Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
}

Write-Host ""
Write-Host "[Step 1/6] Creating Resource Group..." -ForegroundColor Yellow

# Create Resource Group
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Host "  [+] Resource Group created: $ResourceGroupName" -ForegroundColor Green
}
else {
    Write-Host "  [i] Resource Group already exists: $ResourceGroupName" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[Step 2/6] Creating Virtual Network and Subnet..." -ForegroundColor Yellow

# Create VNet and Subnet
$vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $vnet) {
    $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix "10.0.1.0/24"
    $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location `
        -Name $VNetName -AddressPrefix "10.0.0.0/16" -Subnet $subnetConfig
    Write-Host "  [+] Virtual Network created: $VNetName" -ForegroundColor Green
}
else {
    Write-Host "  [i] Virtual Network already exists: $VNetName" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[Step 3/6] Creating Network Security Group (Allow RDP from Any)..." -ForegroundColor Yellow

# Create NSG with RDP rule (INTENTIONALLY OPEN for honeypot)
$nsg = Get-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $nsg) {
    # Create RDP allow rule
    $rdpRule = New-AzNetworkSecurityRuleConfig -Name "Allow-RDP-All" `
        -Description "Allow RDP from any source (Honeypot)" `
        -Access Allow `
        -Protocol Tcp `
        -Direction Inbound `
        -Priority 100 `
        -SourceAddressPrefix * `
        -SourcePortRange * `
        -DestinationAddressPrefix * `
        -DestinationPortRange 3389

    $nsg = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location `
        -Name $NSGName -SecurityRules $rdpRule
    
    Write-Host "  [+] NSG created with RDP open to ANY: $NSGName" -ForegroundColor Green
    Write-Host "  [!] WARNING: RDP is open to the internet (intentional for honeypot)" -ForegroundColor Yellow
}
else {
    Write-Host "  [i] NSG already exists: $NSGName" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[Step 4/6] Creating Public IP Address..." -ForegroundColor Yellow

# Create Public IP
$publicIP = Get-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $publicIP) {
    $publicIP = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Location $Location `
        -Name $PublicIPName -AllocationMethod Static -Sku Standard
    Write-Host "  [+] Public IP created: $($publicIP.IpAddress)" -ForegroundColor Green
}
else {
    Write-Host "  [i] Public IP already exists: $($publicIP.IpAddress)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[Step 5/6] Creating Network Interface..." -ForegroundColor Yellow

# Create NIC
$nicName = "$VMName-nic"
$nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $nic) {
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vnet
    $nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $ResourceGroupName -Location $Location `
        -SubnetId $subnet.Id -PublicIpAddressId $publicIP.Id -NetworkSecurityGroupId $nsg.Id
    Write-Host "  [+] NIC created: $nicName" -ForegroundColor Green
}
else {
    Write-Host "  [i] NIC already exists: $nicName" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[Step 6/6] Creating Virtual Machine (this may take 5-10 minutes)..." -ForegroundColor Yellow

# Check if VM exists
$vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $vm) {
    # Create VM configuration
    $credential = New-Object System.Management.Automation.PSCredential ($AdminUsername, $AdminPassword)
    
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName `
        -Credential $credential -ProvisionVMAgent -EnableAutoUpdate
    $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsDesktop" `
        -Offer "Windows-10" -Skus "win10-22h2-pro" -Version "latest"
    $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
    $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig -Disable

    # Create the VM
    $newVM = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig
    Write-Host "  [+] VM created: $VMName" -ForegroundColor Green
}
else {
    Write-Host "  [i] VM already exists: $VMName" -ForegroundColor Cyan
}

# Configure Auto-Shutdown if requested
if ($EnableAutoShutdown) {
    Write-Host ""
    Write-Host "[*] Configuring Auto-Shutdown at 7:00 PM..." -ForegroundColor Yellow
    
    $shutdownTime = "1900"  # 7 PM
    $timezone = "Eastern Standard Time"
    
    $properties = @{
        "status"                = "Enabled"
        "taskType"              = "ComputerShutdownTask"
        "dailyRecurrence"       = @{
            "time" = $shutdownTime
        }
        "timeZoneId"            = $timezone
        "targetResourceId"      = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VMName"
    }
    
    try {
        New-AzResource -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName" `
            -Location $Location -Properties $properties -Force | Out-Null
        Write-Host "  [+] Auto-Shutdown configured for 7:00 PM $timezone" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [-] Failed to configure Auto-Shutdown. Configure manually in Azure Portal."
    }
}

# Final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Deployment Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "VM Details:" -ForegroundColor White
Write-Host "  Name:       $VMName" -ForegroundColor Gray
Write-Host "  Public IP:  $($publicIP.IpAddress)" -ForegroundColor Green
Write-Host "  Username:   $AdminUsername" -ForegroundColor Gray
Write-Host "  RDP Port:   3389 (Open to Internet)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Connect with RDP:" -ForegroundColor White
Write-Host "  mstsc /v:$($publicIP.IpAddress)" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Connect to the VM and run Setup-LogForwarding.ps1" -ForegroundColor White
Write-Host "2. Disable Windows Firewall on the VM (for honeypot)" -ForegroundColor White
Write-Host "3. Configure Data Collection Rule in Azure Sentinel" -ForegroundColor White
Write-Host ""
Write-Host "[!] This VM will attract attacks - never store sensitive data!" -ForegroundColor Red
Write-Host ""
