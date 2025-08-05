[CmdletBinding()]
param(
    [string]$OutputPath = ".\AzureNetworkDiscovery",
    [switch]$GenerateTopology = $true,
    [switch]$GenerateHTMLReport = $true,
    [string[]]$SubscriptionFilter = @(),
    [string[]]$ResourceGroupFilter = @(),
    [switch]$ExportNSGRules = $true,
    [switch]$IncludeDiagnostics = $true,
    [switch]$IncludeCostAnalysis = $false,
    [switch]$EnableRanking = $true,
    [switch]$OnlyCoreNetwork = $false,
    [switch]$Sanitize = $false,
    [string]$Prefix = "",
    [ValidateSet("PDF", "PNG", "SVG", "DOT", "All")]
    [string[]]$DiagramFormats = @("SVG", "PNG", "DOT")
)

# Azure Network Discovery and Topology Generator - Enhanced Version
# This version includes Get-AzNetworkDiagram style topology generation

# Ensure PowerShell 7+ compatibility
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 or later. Please upgrade your PowerShell version."
    exit
}

# Enhanced error handling
$ErrorActionPreference = "Stop"
$Global:Errors = @()

# Suppress the breaking change warnings
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { 
            Write-Host $logMessage -ForegroundColor Red
            $Global:Errors += $logMessage
        }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    if (Test-Path $OutputPath) {
        $logFile = Join-Path $OutputPath "NetworkDiscovery_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
}

# Check for Graphviz installation
function Test-GraphvizInstalled {
    $dotPath = Get-Command dot -ErrorAction SilentlyContinue
    if ($dotPath) {
        Write-Log "Graphviz found at: $($dotPath.Source)" -Level Success
        return $true
    } else {
        Write-Log "Graphviz not found. Install it for PDF/PNG generation. SVG and HTML will still work." -Level Warning
        Write-Log "Install with: choco install graphviz OR winget install graphviz" -Level Info
        return $false
    }
}

# Initialize Azure modules
function Initialize-AzureModules {
    $RequiredModules = @("Az.Accounts", "Az.Network", "Az.Resources", "Az.Compute")
    
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            Write-Log "Installing module: $Module" -Level Info
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
        }
        Import-Module $Module
    }
}

# Create output directory structure
function Initialize-OutputStructure {
    $paths = @(
        $OutputPath,
        (Join-Path $OutputPath "JSON"),
        (Join-Path $OutputPath "Topology"),
        (Join-Path $OutputPath "Reports")
    )
    
    foreach ($path in $paths) {
        if (!(Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

# Initialize data collection structure
$Global:NetworkData = @{
    Metadata = @{
        CollectionStartTime = Get-Date
        CollectionEndTime = $null
        TotalExecutionTime = $null
        ErrorCount = 0
    }
    Subscriptions = @()
    VirtualNetworks = @()
    Subnets = @()
    NetworkSecurityGroups = @()
    NSGRules = @()
    VirtualNetworkGateways = @()
    LocalNetworkGateways = @()
    ExpressRouteCircuits = @()
    ApplicationGateways = @()
    LoadBalancers = @()
    PublicIPs = @()
    NetworkInterfaces = @()
    RouteTables = @()
    Routes = @()
    VNetPeerings = @()
    PrivateEndpoints = @()
    NATGateways = @()
    Firewalls = @()
    BastionHosts = @()
    NetworkWatchers = @()
    TrafficManagerProfiles = @()
    Connections = @()
    VirtualWANs = @()
    VirtualHubs = @()
    AzureFirewalls = @()
    DNSZones = @()
    VirtualMachines = @()
    VMScaleSets = @()
}

# Ensure all arrays are properly initialized
foreach ($key in $Global:NetworkData.Keys) {
    if ($key -ne "Metadata" -and $null -eq $Global:NetworkData[$key]) {
        $Global:NetworkData[$key] = @()
    }
}

# Sanitize names for DOT compatibility
function Get-SanitizedName {
    param([string]$Name)
    
    if ($Sanitize) {
        # Remove special characters and replace with underscores
        $sanitized = $Name -replace '[^a-zA-Z0-9\-_]', '_'
        if ($Prefix) {
            return "$Prefix$sanitized"
        }
        return $sanitized
    }
    return $Name
}

# Get icon for resource type (for enhanced diagrams)
function Get-ResourceIcon {
    param([string]$ResourceType)
    
    $iconMap = @{
        "VirtualNetwork" = "🌐"
        "Subnet" = "📁"
        "NetworkSecurityGroup" = "🔒"
        "PublicIP" = "🌍"
        "LoadBalancer" = "⚖️"
        "ApplicationGateway" = "🚪"
        "VPNGateway" = "🔐"
        "ExpressRoute" = "⚡"
        "Firewall" = "🔥"
        "Bastion" = "🛡️"
        "VirtualMachine" = "💻"
        "RouteTable" = "🗺️"
        "PrivateEndpoint" = "🔗"
        "NATGateway" = "↔️"
    }
    
    return $iconMap[$ResourceType]
}

# Get NSG rules detailed
function Get-NSGRulesDetailed {
    param($NSG, $SubscriptionId, $SubscriptionName)
    
    $rules = @()
    
    # Process custom security rules
    if ($NSG.SecurityRules) {
        foreach ($rule in $NSG.SecurityRules) {
            $ruleObject = [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                NSGName = $NSG.Name
                NSGId = $NSG.Id
                RuleName = $rule.Name
                Priority = $rule.Priority
                Direction = $rule.Direction
                Access = $rule.Access
                Protocol = $rule.Protocol
                SourcePortRange = ($rule.SourcePortRange -join ",")
                DestinationPortRange = ($rule.DestinationPortRange -join ",")
                SourceAddressPrefix = ($rule.SourceAddressPrefix -join ",")
                DestinationAddressPrefix = ($rule.DestinationAddressPrefix -join ",")
                Description = if ($rule.Description) { $rule.Description } else { "" }
                Type = "Custom"
            }
            $rules += $ruleObject
        }
    }
    
    # Always include default rules
    if ($NSG.DefaultSecurityRules) {
        foreach ($rule in $NSG.DefaultSecurityRules) {
            $ruleObject = [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                NSGName = $NSG.Name
                NSGId = $NSG.Id
                RuleName = $rule.Name
                Priority = $rule.Priority
                Direction = $rule.Direction
                Access = $rule.Access
                Protocol = $rule.Protocol
                SourcePortRange = ($rule.SourcePortRange -join ",")
                DestinationPortRange = ($rule.DestinationPortRange -join ",")
                SourceAddressPrefix = ($rule.SourceAddressPrefix -join ",")
                DestinationAddressPrefix = ($rule.DestinationAddressPrefix -join ",")
                Description = if ($rule.Description) { $rule.Description } else { "" }
                Type = "Default"
            }
            $rules += $ruleObject
        }
    }
    
    return $rules
}

# Main resource collection function using direct cmdlets
function Get-NetworkingResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )
    
    try {
        Write-Log "Processing subscription: $SubscriptionName" -Level Info
        
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        
        $SubData = @{
            SubscriptionId = $SubscriptionId
            SubscriptionName = $SubscriptionName
            ResourceGroups = @()
            ResourceCounts = @{}
        }
        
        # Get resource groups
        $ResourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue
        if ($ResourceGroupFilter.Count -gt 0) {
            $ResourceGroups = $ResourceGroups | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        $SubData.ResourceGroups = $ResourceGroups | ForEach-Object {
            @{
                Name = $_.ResourceGroupName
                Location = $_.Location
                Tags = $_.Tags
            }
        }
        
        Write-Log "Found $($ResourceGroups.Count) resource groups" -Level Info
        
        # Process Virtual Networks
        Write-Log "Processing Virtual Networks..." -Level Info
        $VNets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $VNets = $VNets | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($VNet in $VNets) {
            $VNetData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $VNet.ResourceGroupName
                Name = $VNet.Name
                Location = $VNet.Location
                AddressSpace = $VNet.AddressSpace.AddressPrefixes -join ","
                DnsServers = ($VNet.DhcpOptions.DnsServers) -join ","
                EnableDdosProtection = $VNet.EnableDdosProtection
                EnableVmProtection = $VNet.EnableVmProtection
                Tags = $VNet.Tag
                Id = $VNet.Id
                SubnetCount = $VNet.Subnets.Count
                PeeringCount = $VNet.VirtualNetworkPeerings.Count
            }
            $Global:NetworkData.VirtualNetworks += $VNetData
            
            # Process Subnets
            foreach ($Subnet in $VNet.Subnets) {
                $SubnetData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    VNetName = $VNet.Name
                    VNetId = $VNet.Id
                    Name = $Subnet.Name
                    AddressPrefix = $Subnet.AddressPrefix
                    AddressPrefixes = $Subnet.AddressPrefixes -join ","
                    NetworkSecurityGroup = if ($Subnet.NetworkSecurityGroup) { $Subnet.NetworkSecurityGroup.Id } else { "" }
                    RouteTable = if ($Subnet.RouteTable) { $Subnet.RouteTable.Id } else { "" }
                    ServiceEndpoints = ($Subnet.ServiceEndpoints | ForEach-Object { $_.Service }) -join ","
                    Delegations = ($Subnet.Delegations | ForEach-Object { $_.ServiceName }) -join ","
                    PrivateEndpointNetworkPolicies = $Subnet.PrivateEndpointNetworkPolicies
                    PrivateLinkServiceNetworkPolicies = $Subnet.PrivateLinkServiceNetworkPolicies
                    Id = $Subnet.Id
                    IsSpecialSubnet = $Subnet.Name -in @('GatewaySubnet', 'AzureFirewallSubnet', 'AzureBastionSubnet')
                }
                $Global:NetworkData.Subnets += $SubnetData
            }
            
            # Process VNet Peerings
            foreach ($Peering in $VNet.VirtualNetworkPeerings) {
                $PeeringData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    VNetName = $VNet.Name
                    VNetId = $VNet.Id
                    Name = $Peering.Name
                    RemoteVirtualNetwork = $Peering.RemoteVirtualNetwork.Id
                    AllowVirtualNetworkAccess = $Peering.AllowVirtualNetworkAccess
                    AllowForwardedTraffic = $Peering.AllowForwardedTraffic
                    AllowGatewayTransit = $Peering.AllowGatewayTransit
                    UseRemoteGateways = $Peering.UseRemoteGateways
                    PeeringState = $Peering.PeeringState
                    PeeringSyncLevel = $Peering.PeeringSyncLevel
                    Id = $Peering.Id
                }
                $Global:NetworkData.VNetPeerings += $PeeringData
            }
        }
        Write-Log "Found $($VNets.Count) Virtual Networks" -Level Info
        
        # Process Network Security Groups
        Write-Log "Processing Network Security Groups..." -Level Info
        $NSGs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $NSGs = $NSGs | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($NSG in $NSGs) {
            $NSGData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $NSG.ResourceGroupName
                Name = $NSG.Name
                Location = $NSG.Location
                SecurityRulesCount = $NSG.SecurityRules.Count
                DefaultSecurityRulesCount = $NSG.DefaultSecurityRules.Count
                AssociatedSubnets = ($NSG.Subnets | ForEach-Object { $_.Id }) -join ","
                AssociatedNetworkInterfaces = ($NSG.NetworkInterfaces | ForEach-Object { $_.Id }) -join ","
                Tags = $NSG.Tag
                Id = $NSG.Id
            }
            $Global:NetworkData.NetworkSecurityGroups += $NSGData
            
            # Always collect rules, regardless of $ExportNSGRules setting
            $rules = Get-NSGRulesDetailed -NSG $NSG -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
            if ($rules.Count -gt 0) {
                $Global:NetworkData.NSGRules += $rules
                Write-Log "Collected $($rules.Count) rules for NSG: $($NSG.Name)" -Level Info
            } else {
                Write-Log "No rules found for NSG: $($NSG.Name)" -Level Warning
            }
        }
        Write-Log "Found $($NSGs.Count) Network Security Groups with $($Global:NetworkData.NSGRules.Count) total rules" -Level Info
        
        # Process Public IP Addresses
        Write-Log "Processing Public IP Addresses..." -Level Info
        $PIPs = Get-AzPublicIpAddress -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $PIPs = $PIPs | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($PIP in $PIPs) {
            $PIPData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $PIP.ResourceGroupName
                Name = $PIP.Name
                Location = $PIP.Location
                IpAddress = $PIP.IpAddress
                AllocationMethod = $PIP.PublicIpAllocationMethod
                IpVersion = $PIP.PublicIpAddressVersion
                SkuName = $PIP.Sku.Name
                SkuTier = $PIP.Sku.Tier
                DomainNameLabel = $PIP.DnsSettings.DomainNameLabel
                Fqdn = $PIP.DnsSettings.Fqdn
                AssociatedResourceType = if ($PIP.IpConfiguration) { 
                    $PIP.IpConfiguration.Id.Split('/')[-3] 
                } else { "Unassociated" }
                AssociatedResource = if ($PIP.IpConfiguration) { $PIP.IpConfiguration.Id } else { "" }
                Tags = $PIP.Tag
                Id = $PIP.Id
            }
            $Global:NetworkData.PublicIPs += $PIPData
        }
        Write-Log "Found $($PIPs.Count) Public IP Addresses" -Level Info
        
        # Process Network Interfaces
        Write-Log "Processing Network Interfaces..." -Level Info
        $NICs = Get-AzNetworkInterface -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $NICs = $NICs | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($NIC in $NICs) {
            $NICData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $NIC.ResourceGroupName
                Name = $NIC.Name
                Location = $NIC.Location
                MacAddress = $NIC.MacAddress
                Primary = $NIC.Primary
                EnableAcceleratedNetworking = $NIC.EnableAcceleratedNetworking
                EnableIPForwarding = $NIC.EnableIPForwarding
                NetworkSecurityGroup = if ($NIC.NetworkSecurityGroup) { $NIC.NetworkSecurityGroup.Id } else { "" }
                VirtualMachine = if ($NIC.VirtualMachine) { $NIC.VirtualMachine.Id } else { "" }
                IpConfigurations = ($NIC.IpConfigurations | ForEach-Object {
                    "$($_.Name):$($_.PrivateIpAddress):$($_.PrivateIpAllocationMethod)"
                }) -join ";"
                Tags = $NIC.Tag
                Id = $NIC.Id
                SubnetId = if ($NIC.IpConfigurations.Count -gt 0) { $NIC.IpConfigurations[0].Subnet.Id } else { "" }
            }
            $Global:NetworkData.NetworkInterfaces += $NICData
        }
        Write-Log "Found $($NICs.Count) Network Interfaces" -Level Info
        
        # Process Route Tables
        Write-Log "Processing Route Tables..." -Level Info
        $RouteTables = Get-AzRouteTable -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $RouteTables = $RouteTables | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($RT in $RouteTables) {
            $RTData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $RT.ResourceGroupName
                Name = $RT.Name
                Location = $RT.Location
                DisableBgpRoutePropagation = $RT.DisableBgpRoutePropagation
                RouteCount = $RT.Routes.Count
                AssociatedSubnets = ($RT.Subnets | ForEach-Object { $_.Id }) -join ","
                Tags = $RT.Tag
                Id = $RT.Id
            }
            $Global:NetworkData.RouteTables += $RTData
            
            # Process individual routes
            if ($RT.Routes) {
                foreach ($Route in $RT.Routes) {
                    $RouteData = [PSCustomObject]@{
                        SubscriptionId = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        RouteTableName = $RT.Name
                        RouteTableId = $RT.Id
                        Name = $Route.Name
                        AddressPrefix = $Route.AddressPrefix
                        NextHopType = $Route.NextHopType
                        NextHopIpAddress = if ($Route.NextHopIpAddress) { $Route.NextHopIpAddress } else { "" }
                    }
                    $Global:NetworkData.Routes += $RouteData
                }
                Write-Log "Collected $($RT.Routes.Count) routes for Route Table: $($RT.Name)" -Level Info
            } else {
                Write-Log "No routes found for Route Table: $($RT.Name)" -Level Warning
            }
        }
        Write-Log "Found $($RouteTables.Count) Route Tables with $($Global:NetworkData.Routes.Count) total routes" -Level Info
        
        # Process Load Balancers
        Write-Log "Processing Load Balancers..." -Level Info
        $LoadBalancers = Get-AzLoadBalancer -ErrorAction SilentlyContinue
        
        if ($ResourceGroupFilter.Count -gt 0) {
            $LoadBalancers = $LoadBalancers | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
        }
        
        foreach ($LB in $LoadBalancers) {
            $LBData = @{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroupName = $LB.ResourceGroupName
                Name = $LB.Name
                Location = $LB.Location
                SkuName = $LB.Sku.Name
                SkuTier = $LB.Sku.Tier
                FrontendIPCount = $LB.FrontendIpConfigurations.Count
                BackendPoolCount = $LB.BackendAddressPools.Count
                LoadBalancingRuleCount = $LB.LoadBalancingRules.Count
                ProbeCount = $LB.Probes.Count
                InboundNatRuleCount = $LB.InboundNatRules.Count
                OutboundRuleCount = $LB.OutboundRules.Count
                Tags = $LB.Tag
                Id = $LB.Id
            }
            $Global:NetworkData.LoadBalancers += $LBData
        }
        Write-Log "Found $($LoadBalancers.Count) Load Balancers" -Level Info
        
        # Process Application Gateways
        Write-Log "Processing Application Gateways..." -Level Info
        try {
            $AppGateways = Get-AzApplicationGateway -ErrorAction SilentlyContinue
            
            if ($ResourceGroupFilter.Count -gt 0) {
                $AppGateways = $AppGateways | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
            }
            
            foreach ($AppGW in $AppGateways) {
                $AppGWData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $AppGW.ResourceGroupName
                    Name = $AppGW.Name
                    Location = $AppGW.Location
                    SkuName = $AppGW.Sku.Name
                    SkuTier = $AppGW.Sku.Tier
                    SkuCapacity = $AppGW.Sku.Capacity
                    OperationalState = $AppGW.OperationalState
                    ProvisioningState = $AppGW.ProvisioningState
                    EnableHttp2 = $AppGW.EnableHttp2
                    Tags = $AppGW.Tag
                    Id = $AppGW.Id
                }
                $Global:NetworkData.ApplicationGateways += $AppGWData
            }
            Write-Log "Found $($AppGateways.Count) Application Gateways" -Level Info
        } catch {
            Write-Log "Error processing Application Gateways: $_" -Level Warning
        }
        
        # Process VPN Gateways
        Write-Log "Processing VPN Gateways..." -Level Info
        try {
            # For VPN Gateways, we need to check each resource group
            $VPNGateways = @()
            foreach ($rg in $ResourceGroups) {
                $rgGateways = Get-AzVirtualNetworkGateway -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                if ($rgGateways) {
                    $VPNGateways += $rgGateways
                }
            }
            
            foreach ($Gateway in $VPNGateways) {
                $GatewayData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $Gateway.ResourceGroupName
                    Name = $Gateway.Name
                    Location = $Gateway.Location
                    GatewayType = $Gateway.GatewayType
                    VpnType = $Gateway.VpnType
                    EnableBgp = $Gateway.EnableBgp
                    ActiveActive = $Gateway.ActiveActive
                    GatewaySku = $Gateway.Sku.Name
                    Tags = $Gateway.Tag
                    Id = $Gateway.Id
                }
                $Global:NetworkData.VirtualNetworkGateways += $GatewayData
            }
            Write-Log "Found $($VPNGateways.Count) VPN Gateways" -Level Info
        } catch {
            Write-Log "Error processing VPN Gateways: $_" -Level Warning
        }
        
        # Process Local Network Gateways
        Write-Log "Processing Local Network Gateways..." -Level Info
        try {
            $LocalGateways = @()
            foreach ($rg in $ResourceGroups) {
                $rgLocalGateways = Get-AzLocalNetworkGateway -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                if ($rgLocalGateways) {
                    $LocalGateways += $rgLocalGateways
                }
            }
            
            foreach ($LocalGW in $LocalGateways) {
                $LocalGWData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $LocalGW.ResourceGroupName
                    Name = $LocalGW.Name
                    Location = $LocalGW.Location
                    GatewayIpAddress = $LocalGW.GatewayIpAddress
                    AddressPrefixes = $LocalGW.LocalNetworkAddressSpace.AddressPrefixes -join ","
                    Tags = $LocalGW.Tag
                    Id = $LocalGW.Id
                }
                $Global:NetworkData.LocalNetworkGateways += $LocalGWData
            }
            Write-Log "Found $($LocalGateways.Count) Local Network Gateways" -Level Info
        } catch {
            Write-Log "Error processing Local Network Gateways: $_" -Level Warning
        }
        
        # Process ExpressRoute Circuits
        Write-Log "Processing ExpressRoute Circuits..." -Level Info
        try {
            $ERCircuits = Get-AzExpressRouteCircuit -ErrorAction SilentlyContinue
            
            if ($ResourceGroupFilter.Count -gt 0) {
                $ERCircuits = $ERCircuits | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
            }
            
            foreach ($Circuit in $ERCircuits) {
                $CircuitData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $Circuit.ResourceGroupName
                    Name = $Circuit.Name
                    Location = $Circuit.Location
                    ServiceProviderName = $Circuit.ServiceProviderProperties.ServiceProviderName
                    PeeringLocation = $Circuit.ServiceProviderProperties.PeeringLocation
                    BandwidthInMbps = $Circuit.ServiceProviderProperties.BandwidthInMbps
                    SkuName = $Circuit.Sku.Name
                    SkuTier = $Circuit.Sku.Tier
                    CircuitProvisioningState = $Circuit.ProvisioningState
                    ServiceProviderProvisioningState = $Circuit.ServiceProviderProvisioningState
                    Tags = $Circuit.Tag
                    Id = $Circuit.Id
                }
                $Global:NetworkData.ExpressRouteCircuits += $CircuitData
            }
            Write-Log "Found $($ERCircuits.Count) ExpressRoute Circuits" -Level Info
        } catch {
            Write-Log "Error processing ExpressRoute Circuits: $_" -Level Warning
        }
        
        # Process Private Endpoints
        Write-Log "Processing Private Endpoints..." -Level Info
        try {
            $PrivateEndpoints = Get-AzPrivateEndpoint -ErrorAction SilentlyContinue
            
            if ($ResourceGroupFilter.Count -gt 0) {
                $PrivateEndpoints = $PrivateEndpoints | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
            }
            
            foreach ($PE in $PrivateEndpoints) {
                $PEData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $PE.ResourceGroupName
                    Name = $PE.Name
                    Location = $PE.Location
                    Subnet = $PE.Subnet.Id
                    PrivateLinkServiceConnections = ($PE.PrivateLinkServiceConnections | ForEach-Object { $_.Name }) -join ","
                    Tags = $PE.Tag
                    Id = $PE.Id
                }
                $Global:NetworkData.PrivateEndpoints += $PEData
            }
            Write-Log "Found $($PrivateEndpoints.Count) Private Endpoints" -Level Info
        } catch {
            Write-Log "Error processing Private Endpoints: $_" -Level Warning
        }
        
        # Process NAT Gateways
        Write-Log "Processing NAT Gateways..." -Level Info
        try {
            $NATGateways = Get-AzNatGateway -ErrorAction SilentlyContinue
            
            if ($ResourceGroupFilter.Count -gt 0) {
                $NATGateways = $NATGateways | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
            }
            
            foreach ($NAT in $NATGateways) {
                $NATData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $NAT.ResourceGroupName
                    Name = $NAT.Name
                    Location = $NAT.Location
                    SkuName = $NAT.Sku.Name
                    IdleTimeoutInMinutes = $NAT.IdleTimeoutInMinutes
                    PublicIpAddresses = ($NAT.PublicIpAddresses | ForEach-Object { $_.Id }) -join ","
                    Subnets = ($NAT.Subnets | ForEach-Object { $_.Id }) -join ","
                    Tags = $NAT.Tag
                    Id = $NAT.Id
                }
                $Global:NetworkData.NATGateways += $NATData
            }
            Write-Log "Found $($NATGateways.Count) NAT Gateways" -Level Info
        } catch {
            Write-Log "Error processing NAT Gateways: $_" -Level Warning
        }
        
        # Process Azure Firewalls
        Write-Log "Processing Azure Firewalls..." -Level Info
        try {
            # For Azure Firewalls, we need to check each resource group
            $AzureFirewalls = @()
            foreach ($rg in $ResourceGroups) {
                $rgFirewalls = Get-AzFirewall -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                if ($rgFirewalls) {
                    $AzureFirewalls += $rgFirewalls
                }
            }
            
            foreach ($Firewall in $AzureFirewalls) {
                $FirewallData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $Firewall.ResourceGroupName
                    Name = $Firewall.Name
                    Location = $Firewall.Location
                    SkuName = $Firewall.Sku.Name
                    SkuTier = $Firewall.Sku.Tier
                    ThreatIntelMode = $Firewall.ThreatIntelMode
                    FirewallPolicy = if ($Firewall.FirewallPolicy) { $Firewall.FirewallPolicy.Id } else { "" }
                    Tags = $Firewall.Tag
                    Id = $Firewall.Id
                    SubnetId = if ($Firewall.IpConfigurations.Count -gt 0) { $Firewall.IpConfigurations[0].Subnet.Id } else { "" }
                }
                $Global:NetworkData.AzureFirewalls += $FirewallData
            }
            Write-Log "Found $($AzureFirewalls.Count) Azure Firewalls" -Level Info
        } catch {
            Write-Log "Error processing Azure Firewalls: $_" -Level Warning
        }
        
        # Process Bastion Hosts
        Write-Log "Processing Bastion Hosts..." -Level Info
        try {
            $BastionHosts = Get-AzBastion -ErrorAction SilentlyContinue
            
            if ($ResourceGroupFilter.Count -gt 0) {
                $BastionHosts = $BastionHosts | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
            }
            
            foreach ($Bastion in $BastionHosts) {
                $BastionData = @{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroupName = $Bastion.ResourceGroupName
                    Name = $Bastion.Name
                    Location = $Bastion.Location
                    SkuName = $Bastion.Sku.Name
                    ScaleUnits = $Bastion.ScaleUnits
                    Tags = $Bastion.Tag
                    Id = $Bastion.Id
                }
                $Global:NetworkData.BastionHosts += $BastionData
            }
            Write-Log "Found $($BastionHosts.Count) Bastion Hosts" -Level Info
        } catch {
            Write-Log "Error processing Bastion Hosts: $_" -Level Warning
        }
        
        # Process Virtual Machines (for topology)
        if (!$OnlyCoreNetwork) {
            Write-Log "Processing Virtual Machines..." -Level Info
            try {
                $VMs = Get-AzVM -ErrorAction SilentlyContinue
                
                if ($ResourceGroupFilter.Count -gt 0) {
                    $VMs = $VMs | Where-Object { $_.ResourceGroupName -in $ResourceGroupFilter }
                }
                
                foreach ($VM in $VMs) {
                    $VMData = @{
                        SubscriptionId = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        ResourceGroupName = $VM.ResourceGroupName
                        Name = $VM.Name
                        Location = $VM.Location
                        VmSize = $VM.HardwareProfile.VmSize
                        NetworkInterfaces = ($VM.NetworkProfile.NetworkInterfaces | ForEach-Object { $_.Id }) -join ","
                        Tags = $VM.Tags
                        Id = $VM.Id
                    }
                    $Global:NetworkData.VirtualMachines += $VMData
                }
                Write-Log "Found $($VMs.Count) Virtual Machines" -Level Info
            } catch {
                Write-Log "Error processing Virtual Machines: $_" -Level Warning
            }
        }
        
        $SubData.ResourceCounts = @{
            VirtualNetworks = ($Global:NetworkData.VirtualNetworks | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            Subnets = ($Global:NetworkData.Subnets | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            NetworkSecurityGroups = ($Global:NetworkData.NetworkSecurityGroups | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            PublicIPs = ($Global:NetworkData.PublicIPs | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            LoadBalancers = ($Global:NetworkData.LoadBalancers | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            ApplicationGateways = ($Global:NetworkData.ApplicationGateways | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            VPNGateways = ($Global:NetworkData.VirtualNetworkGateways | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            ExpressRouteCircuits = ($Global:NetworkData.ExpressRouteCircuits | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            NetworkInterfaces = ($Global:NetworkData.NetworkInterfaces | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            RouteTables = ($Global:NetworkData.RouteTables | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            PrivateEndpoints = ($Global:NetworkData.PrivateEndpoints | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            NATGateways = ($Global:NetworkData.NATGateways | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
            VirtualMachines = ($Global:NetworkData.VirtualMachines | Where-Object { $_.SubscriptionId -eq $SubscriptionId }).Count
        }
        
        $Global:NetworkData.Subscriptions += $SubData
        Write-Log "Completed processing subscription: $SubscriptionName" -Level Success
        
    } catch {
        Write-Log "Error processing subscription $SubscriptionName : $_" -Level Error
        $Global:NetworkData.Metadata.ErrorCount++
    }
}

# Generate Interactive HTML Topology (Self-Contained, No External Dependencies)
function Generate-InteractiveHTMLTopology {
    param(
        [string]$TopologyPath,
        [string]$Timestamp
    )
    
    Write-Log "Generating self-contained interactive HTML topology..." -Level Info
    
    $HtmlFile = Join-Path $TopologyPath "NetworkMap_Interactive_$Timestamp.html"
    
    # Build nodes and edges data
    $nodes = @()
    $edges = @()
    $nodeId = 1
    $nodeMap = @{}
    
    # Process VNets
    foreach ($VNet in $Global:NetworkData.VirtualNetworks) {
        $nodeMap[$VNet.Id] = $nodeId
        $nodes += @{
            id = $nodeId
            label = "$($VNet.Name)"
            sublabel = "$($VNet.AddressSpace)"
            location = "$($VNet.Location)"
            type = 'vnet'
            level = 0
            details = "VNet: $($VNet.Name)<br/>Address Space: $($VNet.AddressSpace)<br/>Location: $($VNet.Location)<br/>DNS: $($VNet.DnsServers)"
            x = 0
            y = 0
        }
        $nodeId++
    }
    
    # Process Subnets
    foreach ($Subnet in $Global:NetworkData.Subnets) {
        $nodeMap[$Subnet.Id] = $nodeId
        $subnetLabel = $Subnet.Name
        $nodeType = 'subnet'
        
        if ($Subnet.IsSpecialSubnet) {
            $subnetLabel = "[$($Subnet.Name)]"
            $nodeType = 'specialsubnet'
        }
        
        if ($Subnet.Delegations) {
            $subnetLabel += "*"
        }
        
        $nodes += @{
            id = $nodeId
            label = $subnetLabel
            sublabel = $Subnet.AddressPrefix
            type = $nodeType
            level = 1
            details = "Subnet: $($Subnet.Name)<br/>Address: $($Subnet.AddressPrefix)<br/>Delegations: $($Subnet.Delegations)<br/>Service Endpoints: $($Subnet.ServiceEndpoints)"
            parentId = if ($nodeMap.ContainsKey($Subnet.VNetId)) { $nodeMap[$Subnet.VNetId] } else { $null }
            x = 0
            y = 0
        }
        $nodeId++
    }
    
    # Process NSGs
    foreach ($NSG in $Global:NetworkData.NetworkSecurityGroups) {
        if ($NSG.AssociatedSubnets -or $NSG.AssociatedNetworkInterfaces) {
            $nodeMap[$NSG.Id] = $nodeId
            $nodes += @{
                id = $nodeId
                label = "NSG: $($NSG.Name)"
                sublabel = "Rules: $($NSG.SecurityRulesCount)"
                type = 'nsg'
                level = 2
                details = "NSG: $($NSG.Name)<br/>Custom Rules: $($NSG.SecurityRulesCount)<br/>Default Rules: $($NSG.DefaultSecurityRulesCount)"
                x = 0
                y = 0
            }
            $nodeId++
        }
    }
    
    # Process Route Tables
    foreach ($RT in $Global:NetworkData.RouteTables) {
        if ($RT.AssociatedSubnets) {
            $nodeMap[$RT.Id] = $nodeId
            $nodes += @{
                id = $nodeId
                label = "RT: $($RT.Name)"
                sublabel = "Routes: $($RT.RouteCount)"
                type = 'routetable'
                level = 2
                details = "Route Table: $($RT.Name)<br/>Routes: $($RT.RouteCount)<br/>BGP Propagation: $(if($RT.DisableBgpRoutePropagation){'Disabled'}else{'Enabled'})"
                x = 0
                y = 0
            }
            $nodeId++
        }
    }
    
    # Process Load Balancers
    foreach ($LB in $Global:NetworkData.LoadBalancers) {
        $nodeMap[$LB.Id] = $nodeId
        $nodes += @{
            id = $nodeId
            label = "LB: $($LB.Name)"
            sublabel = $LB.SkuName
            type = 'loadbalancer'
            level = 2
            details = "Load Balancer: $($LB.Name)<br/>SKU: $($LB.SkuName)<br/>Frontend IPs: $($LB.FrontendIPCount)<br/>Backend Pools: $($LB.BackendPoolCount)"
            x = 0
            y = 0
        }
        $nodeId++
    }
    
    # Process Application Gateways
    foreach ($AppGW in $Global:NetworkData.ApplicationGateways) {
        $nodeMap[$AppGW.Id] = $nodeId
        $nodes += @{
            id = $nodeId
            label = "AppGW: $($AppGW.Name)"
            sublabel = $AppGW.SkuTier
            type = 'appgateway'
            level = 2
            details = "App Gateway: $($AppGW.Name)<br/>SKU: $($AppGW.SkuTier)<br/>State: $($AppGW.OperationalState)"
            x = 0
            y = 0
        }
        $nodeId++
    }
    
    # Process VPN Gateways
    foreach ($Gateway in $Global:NetworkData.VirtualNetworkGateways) {
        $nodeMap[$Gateway.Id] = $nodeId
        $nodes += @{
            id = $nodeId
            label = "VPN: $($Gateway.Name)"
            sublabel = $Gateway.GatewaySku
            type = 'vpngateway'
            level = 2
            details = "VPN Gateway: $($Gateway.Name)<br/>SKU: $($Gateway.GatewaySku)<br/>Type: $($Gateway.VpnType)"
            x = 0
            y = 0
        }
        $nodeId++
    }
    
    # Build edges
    foreach ($Subnet in $Global:NetworkData.Subnets) {
        if ($nodeMap.ContainsKey($Subnet.VNetId) -and $nodeMap.ContainsKey($Subnet.Id)) {
            $edges += @{
                from = $nodeMap[$Subnet.VNetId]
                to = $nodeMap[$Subnet.Id]
                type = 'contains'
                label = ''
            }
        }
    }
    
    # NSG associations
    foreach ($NSG in $Global:NetworkData.NetworkSecurityGroups) {
        if ($NSG.AssociatedSubnets -and $nodeMap.ContainsKey($NSG.Id)) {
            foreach ($SubnetId in ($NSG.AssociatedSubnets -split ',')) {
                if ($SubnetId -and $nodeMap.ContainsKey($SubnetId)) {
                    $edges += @{
                        from = $nodeMap[$NSG.Id]
                        to = $nodeMap[$SubnetId]
                        type = 'nsg'
                        label = 'NSG'
                    }
                }
            }
        }
    }
    
    # Route Table associations
    foreach ($RT in $Global:NetworkData.RouteTables) {
        if ($RT.AssociatedSubnets -and $nodeMap.ContainsKey($RT.Id)) {
            foreach ($SubnetId in ($RT.AssociatedSubnets -split ',')) {
                if ($SubnetId -and $nodeMap.ContainsKey($SubnetId)) {
                    $edges += @{
                        from = $nodeMap[$RT.Id]
                        to = $nodeMap[$SubnetId]
                        type = 'routes'
                        label = 'Routes'
                    }
                }
            }
        }
    }
    
    # VNet Peerings
    foreach ($Peering in $Global:NetworkData.VNetPeerings) {
        if ($Peering.PeeringState -eq "Connected" -and 
            $nodeMap.ContainsKey($Peering.VNetId) -and 
            $nodeMap.ContainsKey($Peering.RemoteVirtualNetwork)) {
            $edges += @{
                from = $nodeMap[$Peering.VNetId]
                to = $nodeMap[$Peering.RemoteVirtualNetwork]
                type = 'peering'
                label = 'Peering'
            }
        }
    }
    
    $nodesJson = $nodes | ConvertTo-Json -Depth 10 -Compress
    $edgesJson = $edges | ConvertTo-Json -Depth 10 -Compress
    
    $HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Network Topology - Interactive</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            overflow: hidden;
        }
        .container {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 10px 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 20px;
        }
        .main-content {
            display: flex;
            flex: 1;
            overflow: hidden;
        }
        .sidebar {
            width: 250px;
            background-color: white;
            box-shadow: 2px 0 4px rgba(0,0,0,0.1);
            padding: 20px;
            overflow-y: auto;
        }
        .controls button {
            width: 100%;
            padding: 8px;
            margin-bottom: 8px;
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .controls button:hover {
            background-color: #106ebe;
        }
        #canvas-container {
            flex: 1;
            position: relative;
            background-color: white;
        }
        .tooltip {
            position: absolute;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            display: none;
            z-index: 1000;
        }
        .node-details {
            margin-top: 20px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
            font-size: 12px;
            display: none;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 5px 0;
            font-size: 12px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 8px;
            border-radius: 3px;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Azure Network Topology - Interactive Visualization</h1>
            <span style="float:right;font-size:14px;">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span>
        </div>
        
        <div class="main-content">
            <div class="sidebar">
                <div class="controls">
                    <h3>Controls</h3>
                    <button onclick="resetView()">Reset View</button>
                    <button onclick="fitToScreen()">Fit to Screen</button>
                    <button onclick="forceLayout()">Re-Layout</button>
                    <input type="text" id="search" placeholder="Search nodes..." style="width:100%;padding:8px;margin-bottom:8px;">
                </div>
                
                <h3>Legend</h3>
                <div class="legend-item">
                    <div class="legend-color" style="background:#4a90e2;"></div>
                    <span>Virtual Network</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background:#5cb85c;"></div>
                    <span>Subnet</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background:#f0ad4e;"></div>
                    <span>Special Subnet</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background:#d9534f;"></div>
                    <span>NSG</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background:#777;"></div>
                    <span>Route Table</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background:#5bc0de;"></div>
                    <span>Load Balancer</span>
                </div>
                
                <div class="node-details" id="nodeDetails">
                    <h4>Node Details</h4>
                    <div id="nodeDetailsContent"></div>
                </div>
            </div>
            
            <div id="canvas-container">
                <canvas id="canvas"></canvas>
                <div class="tooltip" id="tooltip"></div>
            </div>
        </div>
    </div>
    
    <script>
        // Data
        const nodes = $nodesJson;
        const edges = $edgesJson;
        
        // Canvas setup
        const container = document.getElementById('canvas-container');
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        const tooltip = document.getElementById('tooltip');
        
        // State
        let transform = { x: 0, y: 0, scale: 1 };
        let mouse = { x: 0, y: 0, down: false, dragStart: null };
        let selectedNode = null;
        let hoveredNode = null;
        let animationId = null;
        
        // Force-directed layout parameters
        const FORCE_STRENGTH = 0.1;
        const REPULSION = 5000;
        const ATTRACTION = 0.001;
        const DAMPING = 0.95;
        const MIN_DISTANCE = 100;
        
        // Visual parameters
        const nodeSize = { width: 140, height: 50 };
        const colors = {
            vnet: '#4a90e2',
            subnet: '#5cb85c',
            specialsubnet: '#f0ad4e',
            nsg: '#d9534f',
            routetable: '#777',
            loadbalancer: '#5bc0de',
            appgateway: '#f39c12',
            vpngateway: '#8e44ad',
            default: '#95a5a6'
        };
        
        // Initialize node positions with better spread
        function initializeNodePositions() {
            // Group nodes by type and level
            const groups = {};
            nodes.forEach(node => {
                const key = node.type + '_' + node.level;
                if (!groups[key]) groups[key] = [];
                groups[key].push(node);
            });
            
            // Position groups in a grid-like layout
            let groupIndex = 0;
            const groupsPerRow = Math.ceil(Math.sqrt(Object.keys(groups).length));
            
            Object.entries(groups).forEach(([key, groupNodes]) => {
                const row = Math.floor(groupIndex / groupsPerRow);
                const col = groupIndex % groupsPerRow;
                const baseX = (col - groupsPerRow / 2) * 400;
                const baseY = row * 300;
                
                // Position nodes within each group
                const nodesPerRow = Math.ceil(Math.sqrt(groupNodes.length));
                groupNodes.forEach((node, i) => {
                    const nodeRow = Math.floor(i / nodesPerRow);
                    const nodeCol = i % nodesPerRow;
                    
                    node.x = baseX + (nodeCol - nodesPerRow / 2) * 180;
                    node.y = baseY + nodeRow * 80;
                    node.vx = 0;
                    node.vy = 0;
                });
                
                groupIndex++;
            });
        }
        
        // Force-directed simulation
        function applyForces() {
            // Apply repulsion between all nodes
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dx = nodes[j].x - nodes[i].x;
                    const dy = nodes[j].y - nodes[i].y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    if (distance < MIN_DISTANCE * 3) {
                        const force = REPULSION / (distance * distance);
                        const fx = (dx / distance) * force;
                        const fy = (dy / distance) * force;
                        
                        nodes[i].vx -= fx;
                        nodes[i].vy -= fy;
                        nodes[j].vx += fx;
                        nodes[j].vy += fy;
                    }
                }
            }
            
            // Apply attraction along edges
            edges.forEach(edge => {
                const source = nodes.find(n => n.id === edge.from);
                const target = nodes.find(n => n.id === edge.to);
                
                if (source && target) {
                    const dx = target.x - source.x;
                    const dy = target.y - source.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    const force = distance * ATTRACTION;
                    const fx = (dx / distance) * force;
                    const fy = (dy / distance) * force;
                    
                    source.vx += fx;
                    source.vy += fy;
                    target.vx -= fx;
                    target.vy -= fy;
                }
            });
            
            // Update positions
            nodes.forEach(node => {
                node.vx *= DAMPING;
                node.vy *= DAMPING;
                node.x += node.vx;
                node.y += node.vy;
            });
        }
        
        // Drawing functions
        function draw() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.save();
            
            // Apply transform
            ctx.translate(transform.x, transform.y);
            ctx.scale(transform.scale, transform.scale);
            
            // Draw edges
            ctx.strokeStyle = '#ddd';
            ctx.lineWidth = 1;
            edges.forEach(edge => {
                const source = nodes.find(n => n.id === edge.from);
                const target = nodes.find(n => n.id === edge.to);
                
                if (source && target) {
                    ctx.beginPath();
                    ctx.moveTo(source.x, source.y);
                    
                    // Different line styles for different edge types
                    if (edge.type === 'nsg') {
                        ctx.strokeStyle = '#ff6b6b';
                        ctx.setLineDash([5, 5]);
                    } else if (edge.type === 'routes') {
                        ctx.strokeStyle = '#4ecdc4';
                        ctx.setLineDash([5, 5]);
                    } else if (edge.type === 'peering') {
                        ctx.strokeStyle = '#45b7d1';
                        ctx.setLineDash([]);
                        ctx.lineWidth = 2;
                    } else {
                        ctx.strokeStyle = '#ddd';
                        ctx.setLineDash([]);
                    }
                    
                    ctx.lineTo(target.x, target.y);
                    ctx.stroke();
                }
            });
            
            // Reset line style
            ctx.setLineDash([]);
            ctx.lineWidth = 1;
            
            // Draw nodes
            nodes.forEach(node => {
                const isHovered = hoveredNode === node;
                const isSelected = selectedNode === node;
                
                // Node background
                ctx.fillStyle = colors[node.type] || colors.default;
                ctx.strokeStyle = isSelected ? '#333' : '#666';
                ctx.lineWidth = isSelected ? 3 : 1;
                
                ctx.beginPath();
                ctx.roundRect(
                    node.x - nodeSize.width / 2,
                    node.y - nodeSize.height / 2,
                    nodeSize.width,
                    nodeSize.height,
                    5
                );
                ctx.fill();
                ctx.stroke();
                
                // Node text
                ctx.fillStyle = 'white';
                ctx.font = 'bold 12px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                
                // Draw label
                ctx.fillText(node.label, node.x, node.y - 8);
                
                // Draw sublabel
                if (node.sublabel) {
                    ctx.font = '10px Arial';
                    ctx.fillText(node.sublabel, node.x, node.y + 8);
                }
                
                // Hover effect
                if (isHovered) {
                    ctx.strokeStyle = '#ffeb3b';
                    ctx.lineWidth = 3;
                    ctx.stroke();
                }
            });
            
            ctx.restore();
        }
        
        // Event handlers
        function handleMouseMove(e) {
            const rect = canvas.getBoundingClientRect();
            mouse.x = e.clientX - rect.left;
            mouse.y = e.clientY - rect.top;
            
            if (mouse.down && mouse.dragStart) {
                if (!hoveredNode) {
                    // Pan view
                    transform.x += mouse.x - mouse.dragStart.x;
                    transform.y += mouse.y - mouse.dragStart.y;
                } else {
                    // Drag node
                    const worldMouse = screenToWorld(mouse.x, mouse.y);
                    hoveredNode.x = worldMouse.x;
                    hoveredNode.y = worldMouse.y;
                    hoveredNode.vx = 0;
                    hoveredNode.vy = 0;
                }
                mouse.dragStart = { x: mouse.x, y: mouse.y };
            } else {
                // Check hover
                const worldMouse = screenToWorld(mouse.x, mouse.y);
                hoveredNode = null;
                
                for (const node of nodes) {
                    if (Math.abs(worldMouse.x - node.x) < nodeSize.width / 2 &&
                        Math.abs(worldMouse.y - node.y) < nodeSize.height / 2) {
                        hoveredNode = node;
                        canvas.style.cursor = 'pointer';
                        
                        // Show tooltip
                        tooltip.innerHTML = node.details;
                        tooltip.style.left = mouse.x + 10 + 'px';
                        tooltip.style.top = mouse.y + 10 + 'px';
                        tooltip.style.display = 'block';
                        break;
                    }
                }
                
                if (!hoveredNode) {
                    canvas.style.cursor = 'default';
                    tooltip.style.display = 'none';
                }
            }
            
            draw();
        }
        
        function handleMouseDown(e) {
            mouse.down = true;
            mouse.dragStart = { x: mouse.x, y: mouse.y };
            
            if (hoveredNode) {
                selectedNode = hoveredNode;
                document.getElementById('nodeDetails').style.display = 'block';
                document.getElementById('nodeDetailsContent').innerHTML = hoveredNode.details;
            }
        }
        
        function handleMouseUp() {
            mouse.down = false;
            mouse.dragStart = null;
        }
        
        function handleWheel(e) {
            e.preventDefault();
            const delta = e.deltaY > 0 ? 0.9 : 1.1;
            const newScale = transform.scale * delta;
            
            if (newScale >= 0.1 && newScale <= 5) {
                // Zoom to mouse position
                const worldMouse = screenToWorld(mouse.x, mouse.y);
                transform.scale = newScale;
                const newWorldMouse = screenToWorld(mouse.x, mouse.y);
                
                transform.x += (newWorldMouse.x - worldMouse.x) * transform.scale;
                transform.y += (newWorldMouse.y - worldMouse.y) * transform.scale;
            }
            
            draw();
        }
        
        // Utility functions
        function screenToWorld(x, y) {
            return {
                x: (x - transform.x) / transform.scale,
                y: (y - transform.y) / transform.scale
            };
        }
        
        function resizeCanvas() {
            canvas.width = container.clientWidth;
            canvas.height = container.clientHeight;
            draw();
        }
        
        // Control functions
        function resetView() {
            transform = { x: canvas.width / 2, y: canvas.height / 2, scale: 1 };
            draw();
        }
        
        function fitToScreen() {
            if (nodes.length === 0) return;
            
            let minX = Infinity, maxX = -Infinity;
            let minY = Infinity, maxY = -Infinity;
            
            nodes.forEach(node => {
                minX = Math.min(minX, node.x - nodeSize.width / 2);
                maxX = Math.max(maxX, node.x + nodeSize.width / 2);
                minY = Math.min(minY, node.y - nodeSize.height / 2);
                maxY = Math.max(maxY, node.y + nodeSize.height / 2);
            });
            
            const width = maxX - minX;
            const height = maxY - minY;
            const centerX = (minX + maxX) / 2;
            const centerY = (minY + maxY) / 2;
            
            const scaleX = (canvas.width - 100) / width;
            const scaleY = (canvas.height - 100) / height;
            transform.scale = Math.min(scaleX, scaleY, 1);
            
            transform.x = canvas.width / 2 - centerX * transform.scale;
            transform.y = canvas.height / 2 - centerY * transform.scale;
            
            draw();
        }
        
        function forceLayout() {
            let iterations = 100;
            function animate() {
                applyForces();
                draw();
                
                if (--iterations > 0) {
                    animationId = requestAnimationFrame(animate);
                }
            }
            
            if (animationId) cancelAnimationFrame(animationId);
            animate();
        }
        
        // Search functionality
        document.getElementById('search').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            
            if (query) {
                const found = nodes.find(n => 
                    n.label.toLowerCase().includes(query) ||
                    (n.sublabel && n.sublabel.toLowerCase().includes(query))
                );
                
                if (found) {
                    selectedNode = found;
                    transform.x = canvas.width / 2 - found.x * transform.scale;
                    transform.y = canvas.height / 2 - found.y * transform.scale;
                    
                    document.getElementById('nodeDetails').style.display = 'block';
                    document.getElementById('nodeDetailsContent').innerHTML = found.details;
                    
                    draw();
                }
            }
        });
        
        // Add roundRect polyfill for older browsers
        if (!ctx.roundRect) {
            CanvasRenderingContext2D.prototype.roundRect = function(x, y, w, h, r) {
                if (w < 2 * r) r = w / 2;
                if (h < 2 * r) r = h / 2;
                this.moveTo(x + r, y);
                this.arcTo(x + w, y, x + w, y + h, r);
                this.arcTo(x + w, y + h, x, y + h, r);
                this.arcTo(x, y + h, x, y, r);
                this.arcTo(x, y, x + w, y, r);
            };
        }
        
        // Initialize
        window.addEventListener('resize', resizeCanvas);
        canvas.addEventListener('mousemove', handleMouseMove);
        canvas.addEventListener('mousedown', handleMouseDown);
        canvas.addEventListener('mouseup', handleMouseUp);
        canvas.addEventListener('mouseleave', handleMouseUp);
        canvas.addEventListener('wheel', handleWheel);
        
        // Start
        resizeCanvas();
        initializeNodePositions();
        forceLayout();
        setTimeout(fitToScreen, 1000);
    </script>
</body>
</html>
"@
    
    $HtmlContent | Out-File $HtmlFile -Encoding utf8NoBOM
    Write-Log "Self-contained interactive HTML topology saved to: $HtmlFile" -Level Success
}

# Generate Enhanced Network Topology
function Generate-EnhancedNetworkTopology {
    param([string]$OutputPath)
    
    Write-Log "Starting enhanced network topology generation..." -Level Info
    
    $TopologyPath = Join-Path $OutputPath "Topology"
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Check if Graphviz is installed
    $GraphvizInstalled = Test-GraphvizInstalled
    
    # Generate interactive HTML topology (always works, no dependencies)
    try {
        Generate-InteractiveHTMLTopology -TopologyPath $TopologyPath -Timestamp $Timestamp
    } catch {
        Write-Log "Error generating interactive HTML topology: $_" -Level Error
    }
    
    # Only proceed with DOT-based generation if we have data and Graphviz
    if ($Global:NetworkData.VirtualNetworks.Count -eq 0) {
        Write-Log "No Virtual Networks found. Skipping DOT topology generation." -Level Warning
        return
    }
    
    Write-Log "Generating DOT topology for $($Global:NetworkData.VirtualNetworks.Count) VNets..." -Level Info
    
    # Build the DOT content
    $DotContent = @"
digraph AzureNetworkTopology {
    // Graph settings
    rankdir=TB;
    compound=true;
    fontname="Arial";
    node [shape=box, style="rounded,filled", fontname="Arial", fontsize=10];
    edge [fontname="Arial", fontsize=9];
    bgcolor="#f5f5f5";
    
    // Title
    labelloc="t";
    label="Azure Network Topology\nGenerated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')";
    fontsize=16;
    
"@
    
    # Define color scheme
    $Colors = @{
        VNet = "#4a90e2"
        Subnet = "#5cb85c"
        SpecialSubnet = "#f0ad4e"
        NSG = "#d9534f"
        RouteTable = "#777777"
        LoadBalancer = "#5bc0de"
        AppGateway = "#f39c12"
        VPNGateway = "#8e44ad"
        ExpressRoute = "#e74c3c"
        PublicIP = "#95a5a6"
        Firewall = "#e67e22"
        Bastion = "#34495e"
        PrivateEndpoint = "#16a085"
        NATGateway = "#2c3e50"
        VM = "#3498db"
    }
    
    # Track node IDs for relationships
    $NodeMap = @{}
    $NodeId = 1
    
    # Process each subscription as a cluster
    foreach ($Sub in $Global:NetworkData.Subscriptions) {
        $SubId = $Sub.SubscriptionId
        $SubName = Get-SanitizedName -Name $Sub.SubscriptionName
        
        $DotContent += @"
    
    // Subscription: $($Sub.SubscriptionName)
    subgraph "cluster_sub_$NodeId" {
        label="Subscription: $($Sub.SubscriptionName)";
        style="filled,rounded";
        fillcolor="#e8f4fd";
        fontsize=12;
        
"@
        
        # Process VNets in this subscription
        $SubVNets = $Global:NetworkData.VirtualNetworks | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($VNet in $SubVNets) {
            $VNetNodeId = "vnet_$NodeId"
            $NodeMap[$VNet.Id] = $VNetNodeId
            $VNetName = Get-SanitizedName -Name $VNet.Name
            
            $DotContent += @"
        
        // VNet: $($VNet.Name)
        subgraph "cluster_$VNetNodeId" {
            label="$($VNet.Name)\n$($VNet.AddressSpace)\n$($VNet.Location)";
            style="filled,rounded";
            fillcolor="$($Colors.VNet)";
            fontcolor="white";
            
"@
            
            # Process Subnets
            $VNetSubnets = $Global:NetworkData.Subnets | Where-Object { $_.VNetId -eq $VNet.Id }
            
            foreach ($Subnet in $VNetSubnets) {
                $SubnetNodeId = "subnet_$NodeId"
                $NodeMap[$Subnet.Id] = $SubnetNodeId
                $SubnetName = Get-SanitizedName -Name $Subnet.Name
                
                # Determine subnet type and styling
                $SubnetColor = $Colors.Subnet
                $SubnetLabel = $Subnet.Name
                
                if ($Subnet.IsSpecialSubnet) {
                    $SubnetColor = $Colors.SpecialSubnet
                    $SubnetLabel = "[$($Subnet.Name)]"
                }
                
                if ($Subnet.Delegations) {
                    $SubnetLabel += "\n(Delegated)"
                }
                
                $DotContent += @"
            $SubnetNodeId [label="$SubnetLabel\n$($Subnet.AddressPrefix)", fillcolor="$SubnetColor", fontcolor="white"];
"@
                $NodeId++
            }
            
            $DotContent += @"
        }
        
"@
            $NodeId++
        }
        
        # Add other resources in the subscription
        
        # NSGs
        $SubNSGs = $Global:NetworkData.NetworkSecurityGroups | Where-Object { 
            $_.SubscriptionId -eq $SubId -and ($_.AssociatedSubnets -or $_.AssociatedNetworkInterfaces)
        }
        
        foreach ($NSG in $SubNSGs) {
            $NSGNodeId = "nsg_$NodeId"
            $NodeMap[$NSG.Id] = $NSGNodeId
            $NSGName = Get-SanitizedName -Name $NSG.Name
            
            $DotContent += @"
        $NSGNodeId [label="NSG: $($NSG.Name)\nRules: $($NSG.SecurityRulesCount)", fillcolor="$($Colors.NSG)", fontcolor="white", shape="octagon"];
"@
            $NodeId++
        }
        
        # Route Tables
        $SubRouteTables = $Global:NetworkData.RouteTables | Where-Object { 
            $_.SubscriptionId -eq $SubId -and $_.AssociatedSubnets
        }
        
        foreach ($RT in $SubRouteTables) {
            $RTNodeId = "rt_$NodeId"
            $NodeMap[$RT.Id] = $RTNodeId
            $RTName = Get-SanitizedName -Name $RT.Name
            
            $DotContent += @"
        $RTNodeId [label="Route Table: $($RT.Name)\nRoutes: $($RT.RouteCount)", fillcolor="$($Colors.RouteTable)", fontcolor="white", shape="folder"];
"@
            $NodeId++
        }
        
        # Load Balancers
        $SubLBs = $Global:NetworkData.LoadBalancers | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($LB in $SubLBs) {
            $LBNodeId = "lb_$NodeId"
            $NodeMap[$LB.Id] = $LBNodeId
            
            $DotContent += @"
        $LBNodeId [label="LB: $($LB.Name)\n$($LB.SkuName)", fillcolor="$($Colors.LoadBalancer)", fontcolor="white", shape="house"];
"@
            $NodeId++
        }
        
        # Application Gateways
        $SubAppGWs = $Global:NetworkData.ApplicationGateways | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($AppGW in $SubAppGWs) {
            $AppGWNodeId = "appgw_$NodeId"
            $NodeMap[$AppGW.Id] = $AppGWNodeId
            
            $DotContent += @"
        $AppGWNodeId [label="AppGW: $($AppGW.Name)\n$($AppGW.SkuTier)", fillcolor="$($Colors.AppGateway)", fontcolor="white", shape="house"];
"@
            $NodeId++
        }
        
        # VPN Gateways
        $SubVPNGWs = $Global:NetworkData.VirtualNetworkGateways | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($VPNGW in $SubVPNGWs) {
            $VPNGWNodeId = "vpngw_$NodeId"
            $NodeMap[$VPNGW.Id] = $VPNGWNodeId
            
            $DotContent += @"
        $VPNGWNodeId [label="VPN: $($VPNGW.Name)\n$($VPNGW.GatewaySku)", fillcolor="$($Colors.VPNGateway)", fontcolor="white", shape="invhouse"];
"@
            $NodeId++
        }
        
        # Azure Firewalls
        $SubFirewalls = $Global:NetworkData.AzureFirewalls | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($Firewall in $SubFirewalls) {
            $FirewallNodeId = "fw_$NodeId"
            $NodeMap[$Firewall.Id] = $FirewallNodeId
            
            $DotContent += @"
        $FirewallNodeId [label="Firewall: $($Firewall.Name)\n$($Firewall.SkuTier)", fillcolor="$($Colors.Firewall)", fontcolor="white", shape="invtriangle"];
"@
            $NodeId++
        }
        
        # Bastion Hosts
        $SubBastions = $Global:NetworkData.BastionHosts | Where-Object { $_.SubscriptionId -eq $SubId }
        
        foreach ($Bastion in $SubBastions) {
            $BastionNodeId = "bastion_$NodeId"
            $NodeMap[$Bastion.Id] = $BastionNodeId
            
            $DotContent += @"
        $BastionNodeId [label="Bastion: $($Bastion.Name)\n$($Bastion.SkuName)", fillcolor="$($Colors.Bastion)", fontcolor="white", shape="diamond"];
"@
            $NodeId++
        }
        
        $DotContent += @"
    }
    
"@
    }
    
    # Add relationships (edges)
    $DotContent += @"
    
    // Relationships
"@
    
    # NSG associations
    foreach ($NSG in $Global:NetworkData.NetworkSecurityGroups) {
        if ($NSG.AssociatedSubnets -and $NodeMap.ContainsKey($NSG.Id)) {
            foreach ($SubnetId in ($NSG.AssociatedSubnets -split ',')) {
                if ($SubnetId -and $NodeMap.ContainsKey($SubnetId)) {
                    $DotContent += @"
    $($NodeMap[$NSG.Id]) -> $($NodeMap[$SubnetId]) [label="Protects", style="dashed", color="red"];
"@
                }
            }
        }
    }
    
    # Route Table associations
    foreach ($RT in $Global:NetworkData.RouteTables) {
        if ($RT.AssociatedSubnets -and $NodeMap.ContainsKey($RT.Id)) {
            foreach ($SubnetId in ($RT.AssociatedSubnets -split ',')) {
                if ($SubnetId -and $NodeMap.ContainsKey($SubnetId)) {
                    $DotContent += @"
    $($NodeMap[$RT.Id]) -> $($NodeMap[$SubnetId]) [label="Routes", style="dashed", color="blue"];
"@
                }
            }
        }
    }
    
    # VNet Peerings
    foreach ($Peering in $Global:NetworkData.VNetPeerings) {
        if ($Peering.PeeringState -eq "Connected" -and 
            $NodeMap.ContainsKey($Peering.VNetId) -and 
            $NodeMap.ContainsKey($Peering.RemoteVirtualNetwork)) {
            $DotContent += @"
    $($NodeMap[$Peering.VNetId]) -> $($NodeMap[$Peering.RemoteVirtualNetwork]) [label="Peering", style="bold", color="green", dir="both"];
"@
        }
    }
    
    # Azure Firewall associations
    foreach ($Firewall in $Global:NetworkData.AzureFirewalls) {
        if ($Firewall.SubnetId -and $NodeMap.ContainsKey($Firewall.Id) -and $NodeMap.ContainsKey($Firewall.SubnetId)) {
            $DotContent += @"
    $($NodeMap[$Firewall.Id]) -> $($NodeMap[$Firewall.SubnetId]) [label="Deployed in", color="orange"];
"@
        }
    }
    
    $DotContent += @"
}
"@
    
    # Save DOT file
    $DotFile = Join-Path $TopologyPath "NetworkTopology_$Timestamp.dot"
    $DotContent | Out-File $DotFile -Encoding utf8NoBOM
    Write-Log "DOT file saved to: $DotFile" -Level Success
    
    # Generate visualizations if Graphviz is installed
    if ($GraphvizInstalled) {
        foreach ($Format in $DiagramFormats) {
            if ($Format -eq "DOT") { continue }
            
            try {
                $OutputFile = Join-Path $TopologyPath "NetworkTopology_$Timestamp.$($Format.ToLower())"
                $Arguments = @(
                    "-T$($Format.ToLower())",
                    "`"$DotFile`"",
                    "-o",
                    "`"$OutputFile`""
                )
                
                Write-Log "Generating $Format topology..." -Level Info
                $Process = Start-Process -FilePath "dot" -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
                
                if ($Process.ExitCode -eq 0) {
                    Write-Log "$Format topology saved to: $OutputFile" -Level Success
                } else {
                    Write-Log "Error generating $Format topology. Exit code: $($Process.ExitCode)" -Level Warning
                }
            } catch {
                Write-Log "Error generating $Format topology: $_" -Level Warning
            }
        }
    } else {
        Write-Log "Graphviz not installed. Only DOT and HTML files generated." -Level Warning
        Write-Log "To generate PNG/PDF/SVG diagrams, install Graphviz:" -Level Info
        Write-Log "  choco install graphviz" -Level Info
        Write-Log "  OR" -Level Info
        Write-Log "  winget install graphviz" -Level Info
    }
    
    Write-Log "Enhanced network topology generation completed" -Level Success
}

# Generate Network Topology (wrapper function)
function Generate-NetworkTopology {
    param($OutputPath)
    
    # Call the enhanced topology generation
    Generate-EnhancedNetworkTopology -OutputPath $OutputPath
}

# Generate HTML Report
function Generate-HTMLReport {
    param($OutputPath)
    
    Write-Log "Generating HTML report..." -Level Info
    
    $htmlFile = Join-Path $OutputPath "Reports\NetworkDiscovery_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Network Discovery Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #0078d4; }
        h1 { border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { border-bottom: 1px solid #0078d4; padding-bottom: 5px; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 30px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078d4; color: white; position: sticky; top: 0; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #e7f3ff; }
        .summary { background-color: #e7f3ff; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        .metric-label { color: #666; }
        .toc { background-color: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .toc h3 { margin-top: 0; }
        .toc ul { list-style-type: none; padding-left: 0; }
        .toc li { margin: 5px 0; }
        .toc a { text-decoration: none; color: #0078d4; }
        .toc a:hover { text-decoration: underline; }
        .no-data { color: #666; font-style: italic; padding: 20px; text-align: center; }
        .tag { display: inline-block; padding: 2px 8px; margin: 2px; background-color: #e1e4e8; border-radius: 3px; font-size: 12px; }
        .status-connected { color: green; font-weight: bold; }
        .status-disconnected { color: red; font-weight: bold; }
        .back-to-top { position: fixed; bottom: 20px; right: 20px; background-color: #0078d4; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; }
        .back-to-top:hover { background-color: #106ebe; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Network Discovery Report</h1>
        <p><strong>Generated on:</strong> $(Get-Date)</p>
        <p><strong>Execution Time:</strong> $($Global:NetworkData.Metadata.TotalExecutionTime)</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.Subscriptions.Count)</div>
                <div class="metric-label">Subscriptions</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.VirtualNetworks.Count)</div>
                <div class="metric-label">Virtual Networks</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.Subnets.Count)</div>
                <div class="metric-label">Subnets</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.NetworkSecurityGroups.Count)</div>
                <div class="metric-label">NSGs</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.PublicIPs.Count)</div>
                <div class="metric-label">Public IPs</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.LoadBalancers.Count)</div>
                <div class="metric-label">Load Balancers</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.ApplicationGateways.Count)</div>
                <div class="metric-label">App Gateways</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.VirtualNetworkGateways.Count)</div>
                <div class="metric-label">VPN Gateways</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.ExpressRouteCircuits.Count)</div>
                <div class="metric-label">ExpressRoute</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Global:NetworkData.NetworkInterfaces.Count)</div>
                <div class="metric-label">Network Interfaces</div>
            </div>
        </div>
        
        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                <li><a href="#subscriptions">Subscriptions Overview</a></li>
                <li><a href="#vnets">Virtual Networks</a></li>
                <li><a href="#subnets">Subnets</a></li>
                <li><a href="#nsgs">Network Security Groups</a></li>
                <li><a href="#nsgrules">NSG Rules Details</a></li>
                <li><a href="#publicips">Public IP Addresses</a></li>
                <li><a href="#loadbalancers">Load Balancers</a></li>
                <li><a href="#appgateways">Application Gateways</a></li>
                <li><a href="#vpngateways">VPN Gateways</a></li>
                <li><a href="#expressroute">ExpressRoute Circuits</a></li>
                <li><a href="#nics">Network Interfaces</a></li>
                <li><a href="#routetables">Route Tables</a></li>
                <li><a href="#routes">Route Details</a></li>
                <li><a href="#peerings">VNet Peerings</a></li>
                <li><a href="#privateendpoints">Private Endpoints</a></li>
                <li><a href="#natgateways">NAT Gateways</a></li>
                <li><a href="#firewalls">Azure Firewalls</a></li>
                <li><a href="#bastions">Bastion Hosts</a></li>
            </ul>
        </div>
        
        <h2 id="subscriptions">Subscriptions Overview</h2>
        <table>
            <tr>
                <th>Subscription Name</th>
                <th>Subscription ID</th>
                <th>VNets</th>
                <th>Subnets</th>
                <th>NSGs</th>
                <th>Public IPs</th>
                <th>Load Balancers</th>
                <th>App Gateways</th>
                <th>VPN Gateways</th>
                <th>NICs</th>
            </tr>
$(
    $Global:NetworkData.Subscriptions | ForEach-Object {
        "<tr>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.SubscriptionId)</td>
            <td>$($_.ResourceCounts.VirtualNetworks)</td>
            <td>$($_.ResourceCounts.Subnets)</td>
            <td>$($_.ResourceCounts.NetworkSecurityGroups)</td>
            <td>$($_.ResourceCounts.PublicIPs)</td>
            <td>$($_.ResourceCounts.LoadBalancers)</td>
            <td>$($_.ResourceCounts.ApplicationGateways)</td>
            <td>$($_.ResourceCounts.VPNGateways)</td>
            <td>$($_.ResourceCounts.NetworkInterfaces)</td>
        </tr>"
    }
)
        </table>
        
        <h2 id="vnets">Virtual Networks</h2>
$(
    if ($Global:NetworkData.VirtualNetworks.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Address Space</th>
                <th>DNS Servers</th>
                <th>Subnets</th>
                <th>Peerings</th>
                <th>DDoS Protection</th>
            </tr>
$(
    $Global:NetworkData.VirtualNetworks | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.AddressSpace)</td>
            <td>$(if($_.DnsServers){"$($_.DnsServers)"}else{"Azure Default"})</td>
            <td>$($_.SubnetCount)</td>
            <td>$($_.PeeringCount)</td>
            <td>$(if($_.EnableDdosProtection){'<span style="color:green">Yes</span>'}else{'<span style="color:gray">No</span>'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Virtual Networks found</div>'
    }
)
        
        <h2 id="subnets">Subnets</h2>
$(
    if ($Global:NetworkData.Subnets.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>VNet</th>
                <th>Address Prefix</th>
                <th>Service Endpoints</th>
                <th>Delegations</th>
                <th>NSG</th>
                <th>Route Table</th>
            </tr>
$(
    $Global:NetworkData.Subnets | ForEach-Object {
        $nsgName = if($_.NetworkSecurityGroup) { $_.NetworkSecurityGroup.Split('/')[-1] } else { "None" }
        $rtName = if($_.RouteTable) { $_.RouteTable.Split('/')[-1] } else { "None" }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.VNetName)</td>
            <td>$($_.AddressPrefix)</td>
            <td>$(if($_.ServiceEndpoints){"$($_.ServiceEndpoints)"}else{"None"})</td>
            <td>$(if($_.Delegations){"$($_.Delegations)"}else{"None"})</td>
            <td>$nsgName</td>
            <td>$rtName</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Subnets found</div>'
    }
)
        
        <h2 id="nsgs">Network Security Groups</h2>
$(
    if ($Global:NetworkData.NetworkSecurityGroups.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Custom Rules</th>
                <th>Default Rules</th>
                <th>Associated Subnets</th>
                <th>Associated NICs</th>
            </tr>
$(
    $Global:NetworkData.NetworkSecurityGroups | ForEach-Object {
        $subnetCount = if($_.AssociatedSubnets) { ($_.AssociatedSubnets -split ',').Count } else { 0 }
        $nicCount = if($_.AssociatedNetworkInterfaces) { ($_.AssociatedNetworkInterfaces -split ',').Count } else { 0 }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SecurityRulesCount)</td>
            <td>$($_.DefaultSecurityRulesCount)</td>
            <td>$subnetCount</td>
            <td>$nicCount</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Network Security Groups found</div>'
    }
)
        
        <h2 id="nsgrules">Network Security Group Rules</h2>
$(
    if ($Global:NetworkData.NSGRules.Count -gt 0) {
        @"
        <p><em>Showing all NSG rules (custom and default). Rules are sorted by NSG and Priority.</em></p>
        <table>
            <tr>
                <th>NSG Name</th>
                <th>Rule Name</th>
                <th>Priority</th>
                <th>Direction</th>
                <th>Access</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Source Port</th>
                <th>Destination</th>
                <th>Dest Port</th>
                <th>Type</th>
            </tr>
$(
    $Global:NetworkData.NSGRules | Sort-Object NSGName, Priority | ForEach-Object {
        $rowClass = if($_.Access -eq "Allow") { 'style="background-color: #e8f5e9;"' } else { 'style="background-color: #ffebee;"' }
        "<tr $rowClass>
            <td>$($_.NSGName)</td>
            <td>$($_.RuleName)</td>
            <td>$($_.Priority)</td>
            <td>$($_.Direction)</td>
            <td><strong>$($_.Access)</strong></td>
            <td>$($_.Protocol)</td>
            <td>$($_.SourceAddressPrefix)</td>
            <td>$($_.SourcePortRange)</td>
            <td>$($_.DestinationAddressPrefix)</td>
            <td>$($_.DestinationPortRange)</td>
            <td>$($_.Type)</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No NSG Rules found</div>'
    }
)
        
        <h2 id="publicips">Public IP Addresses</h2>
$(
    if ($Global:NetworkData.PublicIPs.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>IP Address</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Allocation</th>
                <th>SKU</th>
                <th>Associated Resource</th>
                <th>FQDN</th>
            </tr>
$(
    $Global:NetworkData.PublicIPs | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$(if($_.IpAddress){"<strong>$($_.IpAddress)</strong>"}else{'<em>Not Assigned</em>'})</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.AllocationMethod)</td>
            <td>$($_.SkuName)</td>
            <td>$(if($_.AssociatedResourceType -eq 'Unassociated'){'<span style="color:orange">Unassociated</span>'}else{$_.AssociatedResourceType})</td>
            <td>$(if($_.Fqdn){$_.Fqdn}else{'-'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Public IP Addresses found</div>'
    }
)
        
        <h2 id="loadbalancers">Load Balancers</h2>
$(
    if ($Global:NetworkData.LoadBalancers.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>SKU</th>
                <th>Frontend IPs</th>
                <th>Backend Pools</th>
                <th>Rules</th>
                <th>Probes</th>
            </tr>
$(
    $Global:NetworkData.LoadBalancers | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SkuName) / $($_.SkuTier)</td>
            <td>$($_.FrontendIPCount)</td>
            <td>$($_.BackendPoolCount)</td>
            <td>$($_.LoadBalancingRuleCount)</td>
            <td>$($_.ProbeCount)</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Load Balancers found</div>'
    }
)
        
        <h2 id="appgateways">Application Gateways</h2>
$(
    if ($Global:NetworkData.ApplicationGateways.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>SKU</th>
                <th>Tier</th>
                <th>Capacity</th>
                <th>State</th>
                <th>HTTP2</th>
            </tr>
$(
    $Global:NetworkData.ApplicationGateways | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SkuName)</td>
            <td>$($_.SkuTier)</td>
            <td>$($_.SkuCapacity)</td>
            <td>$($_.OperationalState)</td>
            <td>$(if($_.EnableHttp2){'Yes'}else{'No'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Application Gateways found</div>'
    }
)
        
        <h2 id="vpngateways">VPN Gateways</h2>
$(
    if ($Global:NetworkData.VirtualNetworkGateways.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Gateway Type</th>
                <th>VPN Type</th>
                <th>SKU</th>
                <th>BGP Enabled</th>
                <th>Active-Active</th>
            </tr>
$(
    $Global:NetworkData.VirtualNetworkGateways | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.GatewayType)</td>
            <td>$($_.VpnType)</td>
            <td>$($_.GatewaySku)</td>
            <td>$(if($_.EnableBgp){'Yes'}else{'No'})</td>
            <td>$(if($_.ActiveActive){'Yes'}else{'No'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No VPN Gateways found</div>'
    }
)
        
        <h2 id="expressroute">ExpressRoute Circuits</h2>
$(
    if ($Global:NetworkData.ExpressRouteCircuits.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Provider</th>
                <th>Peering Location</th>
                <th>Bandwidth</th>
                <th>SKU</th>
                <th>Circuit State</th>
            </tr>
$(
    $Global:NetworkData.ExpressRouteCircuits | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.ServiceProviderName)</td>
            <td>$($_.PeeringLocation)</td>
            <td>$($_.BandwidthInMbps) Mbps</td>
            <td>$($_.SkuName) / $($_.SkuTier)</td>
            <td>$($_.CircuitProvisioningState)</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No ExpressRoute Circuits found</div>'
    }
)
        
        <h2 id="nics">Network Interfaces</h2>
$(
    if ($Global:NetworkData.NetworkInterfaces.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Primary</th>
                <th>Accelerated Networking</th>
                <th>IP Forwarding</th>
                <th>IP Configurations</th>
                <th>Associated VM</th>
            </tr>
$(
    $Global:NetworkData.NetworkInterfaces | ForEach-Object {
        $vmName = if($_.VirtualMachine) { $_.VirtualMachine.Split('/')[-1] } else { "None" }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$(if($_.Primary){'Yes'}else{'No'})</td>
            <td>$(if($_.EnableAcceleratedNetworking){'<span style=""color:green"">Yes</span>'}else{'No'})</td>
            <td>$(if($_.EnableIPForwarding){'Yes'}else{'No'})</td>
            <td>$($_.IpConfigurations)</td>
            <td>$vmName</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Network Interfaces found</div>'
    }
)
        
        <h2 id="routetables">Route Tables</h2>
$(
    if ($Global:NetworkData.RouteTables.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Routes Count</th>
                <th>BGP Route Propagation</th>
                <th>Associated Subnets</th>
            </tr>
$(
    $Global:NetworkData.RouteTables | ForEach-Object {
        $subnetCount = if($_.AssociatedSubnets) { ($_.AssociatedSubnets -split ',').Count } else { 0 }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.RouteCount)</td>
            <td>$(if($_.DisableBgpRoutePropagation){'<span style=""color:red"">Disabled</span>'}else{'<span style=""color:green"">Enabled</span>'})</td>
            <td>$subnetCount</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Route Tables found</div>'
    }
)
        
        <h2 id="routes">Route Table Routes</h2>
$(
    if ($Global:NetworkData.Routes.Count -gt 0) {
        @"
        <p><em>Showing all custom routes configured in Route Tables.</em></p>
        <table>
            <tr>
                <th>Route Table</th>
                <th>Route Name</th>
                <th>Address Prefix</th>
                <th>Next Hop Type</th>
                <th>Next Hop IP Address</th>
            </tr>
$(
    $Global:NetworkData.Routes | Sort-Object RouteTableName, Name | ForEach-Object {
        "<tr>
            <td>$($_.RouteTableName)</td>
            <td>$($_.Name)</td>
            <td><strong>$($_.AddressPrefix)</strong></td>
            <td>$($_.NextHopType)</td>
            <td>$(if($_.NextHopIpAddress){"$($_.NextHopIpAddress)"}else{"-"})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Routes found</div>'
    }
)
        
        <h2 id="peerings">VNet Peerings</h2>
$(
    if ($Global:NetworkData.VNetPeerings.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Source VNet</th>
                <th>Remote VNet</th>
                <th>State</th>
                <th>Allow VNet Access</th>
                <th>Allow Forwarded Traffic</th>
                <th>Allow Gateway Transit</th>
                <th>Use Remote Gateways</th>
            </tr>
$(
    $Global:NetworkData.VNetPeerings | ForEach-Object {
        $stateClass = if($_.PeeringState -eq "Connected"){"status-connected"}else{"status-disconnected"}
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.VNetName)</td>
            <td>$($_.RemoteVirtualNetwork.Split('/')[-1])</td>
            <td><span class='$stateClass'>$($_.PeeringState)</span></td>
            <td>$(if($_.AllowVirtualNetworkAccess){'Yes'}else{'No'})</td>
            <td>$(if($_.AllowForwardedTraffic){'Yes'}else{'No'})</td>
            <td>$(if($_.AllowGatewayTransit){'Yes'}else{'No'})</td>
            <td>$(if($_.UseRemoteGateways){'Yes'}else{'No'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No VNet Peerings found</div>'
    }
)
        
        <h2 id="privateendpoints">Private Endpoints</h2>
$(
    if ($Global:NetworkData.PrivateEndpoints.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>Subnet</th>
                <th>Private Link Connections</th>
            </tr>
$(
    $Global:NetworkData.PrivateEndpoints | ForEach-Object {
        $subnetName = if($_.Subnet) { $_.Subnet.Split('/')[-1] } else { "None" }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$subnetName</td>
            <td>$($_.PrivateLinkServiceConnections)</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Private Endpoints found</div>'
    }
)
        
        <h2 id="natgateways">NAT Gateways</h2>
$(
    if ($Global:NetworkData.NATGateways.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>SKU</th>
                <th>Idle Timeout</th>
                <th>Public IPs</th>
                <th>Subnets</th>
            </tr>
$(
    $Global:NetworkData.NATGateways | ForEach-Object {
        $pipCount = if($_.PublicIpAddresses) { ($_.PublicIpAddresses -split ',').Count } else { 0 }
        $subnetCount = if($_.Subnets) { ($_.Subnets -split ',').Count } else { 0 }
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SkuName)</td>
            <td>$($_.IdleTimeoutInMinutes) min</td>
            <td>$pipCount</td>
            <td>$subnetCount</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No NAT Gateways found</div>'
    }
)
        
        <h2 id="firewalls">Azure Firewalls</h2>
$(
    if ($Global:NetworkData.AzureFirewalls -and $Global:NetworkData.AzureFirewalls.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>SKU</th>
                <th>Tier</th>
                <th>Threat Intel Mode</th>
                <th>Firewall Policy</th>
            </tr>
$(
    $Global:NetworkData.AzureFirewalls | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SkuName)</td>
            <td>$($_.SkuTier)</td>
            <td>$($_.ThreatIntelMode)</td>
            <td>$(if($_.FirewallPolicy){'Yes'}else{'No'})</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Azure Firewalls found</div>'
    }
)
        
        <h2 id="bastions">Bastion Hosts</h2>
$(
    if ($Global:NetworkData.BastionHosts -and $Global:NetworkData.BastionHosts.Count -gt 0) {
        @"
        <table>
            <tr>
                <th>Name</th>
                <th>Subscription</th>
                <th>Resource Group</th>
                <th>Location</th>
                <th>SKU</th>
                <th>Scale Units</th>
            </tr>
$(
    $Global:NetworkData.BastionHosts | ForEach-Object {
        "<tr>
            <td>$($_.Name)</td>
            <td>$($_.SubscriptionName)</td>
            <td>$($_.ResourceGroupName)</td>
            <td>$($_.Location)</td>
            <td>$($_.SkuName)</td>
            <td>$($_.ScaleUnits)</td>
        </tr>"
    }
)
        </table>
"@
    } else {
        '<div class="no-data">No Bastion Hosts found</div>'
    }
)
        
        <a href="#" class="back-to-top">Back to Top</a>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File $htmlFile -Encoding utf8NoBOM
    Write-Log "HTML report saved to: $htmlFile" -Level Success
}

# MAIN EXECUTION BLOCK
try {
    Write-Log "Azure Network Discovery Script Starting..." -Level Success
    Write-Log "Enhanced version with Get-AzNetworkDiagram style topology" -Level Info
    
    Initialize-AzureModules
    Initialize-OutputStructure
    
    Write-Log "Authenticating to Azure..." -Level Info
    try {
        $Context = Get-AzContext
        if (!$Context) {
            Connect-AzAccount
            $Context = Get-AzContext
        }
        Write-Log "Connected to Azure as: $($Context.Account.Id)" -Level Success
    } catch {
        Connect-AzAccount
        $Context = Get-AzContext
    }
    
    # Get all subscriptions, handling multi-tenant scenarios
    Write-Log "Retrieving subscriptions..." -Level Info
    $AllSubscriptions = @()
    
    try {
        # First try to get subscriptions from current context
        $Subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        
        if ($Subscriptions) {
            $AllSubscriptions += $Subscriptions
        }
        
        # Get list of tenants
        $Tenants = Get-AzTenant
        Write-Log "Found $($Tenants.Count) tenant(s)" -Level Info
        
        foreach ($Tenant in $Tenants) {
            try {
                Write-Log "Attempting to access tenant: $($Tenant.Name) ($($Tenant.Id))" -Level Info
                
                # Try to set context to this tenant
                $null = Set-AzContext -TenantId $Tenant.Id -ErrorAction SilentlyContinue
                
                # Get subscriptions from this tenant
                $TenantSubs = Get-AzSubscription -TenantId $Tenant.Id -ErrorAction SilentlyContinue
                
                if ($TenantSubs) {
                    # Add only unique subscriptions
                    foreach ($Sub in $TenantSubs) {
                        if ($AllSubscriptions.Id -notcontains $Sub.Id) {
                            $AllSubscriptions += $Sub
                        }
                    }
                }
            } catch {
                Write-Log "Could not access tenant $($Tenant.Name): $($_.Exception.Message)" -Level Warning
                Write-Log "If you need to access this tenant, run: Connect-AzAccount -TenantId $($Tenant.Id)" -Level Info
            }
        }
    } catch {
        Write-Log "Error retrieving subscriptions: $_" -Level Error
        
        # Fall back to just current context subscriptions
        $AllSubscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
    }
    
    $Subscriptions = $AllSubscriptions
    
    if ($SubscriptionFilter.Count -gt 0) {
        $Subscriptions = $Subscriptions | Where-Object { 
            $_.Name -in $SubscriptionFilter -or $_.Id -in $SubscriptionFilter 
        }
    }
    
    if ($Subscriptions.Count -eq 0) {
        Write-Log "No accessible subscriptions found. Please ensure you are logged in with appropriate permissions." -Level Error
        Write-Log "Try running: Connect-AzAccount" -Level Info
        exit
    }
    
    Write-Log "Found $($Subscriptions.Count) subscription(s) to process" -Level Info
    
    $Counter = 0
    foreach ($Subscription in $Subscriptions) {
        $Counter++
        Write-Log "`nProcessing subscription $Counter of $($Subscriptions.Count): $($Subscription.Name)" -Level Info
        Get-NetworkingResources -SubscriptionId $Subscription.Id -SubscriptionName $Subscription.Name
    }
    
    $Global:NetworkData.Metadata.CollectionEndTime = Get-Date
    $Global:NetworkData.Metadata.TotalExecutionTime = 
        ($Global:NetworkData.Metadata.CollectionEndTime - $Global:NetworkData.Metadata.CollectionStartTime).ToString()
    
    Write-Log "`nGenerating output files..." -Level Info
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $JsonPath = Join-Path $OutputPath "JSON"
    
    # Export individual JSON files for each resource type
    Write-Log "Generating individual JSON files for each resource type..." -Level Info
    
    # Virtual Networks
    if ($Global:NetworkData.VirtualNetworks -and $Global:NetworkData.VirtualNetworks.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "VirtualNetworks_$Timestamp.json"
            $Global:NetworkData.VirtualNetworks | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.VirtualNetworks.Count) Virtual Networks to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Virtual Networks to JSON: $_" -Level Warning
        }
    }
    
    # Subnets
    if ($Global:NetworkData.Subnets -and $Global:NetworkData.Subnets.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "Subnets_$Timestamp.json"
            $Global:NetworkData.Subnets | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.Subnets.Count) Subnets to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Subnets to JSON: $_" -Level Warning
        }
    }
    
    # Network Security Groups
    if ($Global:NetworkData.NetworkSecurityGroups -and $Global:NetworkData.NetworkSecurityGroups.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "NetworkSecurityGroups_$Timestamp.json"
            $Global:NetworkData.NetworkSecurityGroups | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.NetworkSecurityGroups.Count) Network Security Groups to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Network Security Groups to JSON: $_" -Level Warning
        }
    }
    
    # NSG Rules
    if ($Global:NetworkData.NSGRules -and $Global:NetworkData.NSGRules.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "NSGRules_$Timestamp.json"
            $Global:NetworkData.NSGRules | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.NSGRules.Count) NSG Rules to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting NSG Rules to JSON: $_" -Level Warning
        }
    }
    
    # Public IP Addresses
    if ($Global:NetworkData.PublicIPs -and $Global:NetworkData.PublicIPs.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "PublicIPAddresses_$Timestamp.json"
            $Global:NetworkData.PublicIPs | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.PublicIPs.Count) Public IP Addresses to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Public IP Addresses to JSON: $_" -Level Warning
        }
    }
    
    # Network Interfaces
    if ($Global:NetworkData.NetworkInterfaces -and $Global:NetworkData.NetworkInterfaces.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "NetworkInterfaces_$Timestamp.json"
            $Global:NetworkData.NetworkInterfaces | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.NetworkInterfaces.Count) Network Interfaces to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Network Interfaces to JSON: $_" -Level Warning
        }
    }
    
    # Route Tables
    if ($Global:NetworkData.RouteTables -and $Global:NetworkData.RouteTables.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "RouteTables_$Timestamp.json"
            $Global:NetworkData.RouteTables | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.RouteTables.Count) Route Tables to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Route Tables to JSON: $_" -Level Warning
        }
    }
    
    # Routes
    if ($Global:NetworkData.Routes -and $Global:NetworkData.Routes.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "Routes_$Timestamp.json"
            $Global:NetworkData.Routes | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.Routes.Count) Routes to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Routes to JSON: $_" -Level Warning
        }
    }
    
    # Load Balancers
    if ($Global:NetworkData.LoadBalancers -and $Global:NetworkData.LoadBalancers.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "LoadBalancers_$Timestamp.json"
            $Global:NetworkData.LoadBalancers | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.LoadBalancers.Count) Load Balancers to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Load Balancers to JSON: $_" -Level Warning
        }
    }
    
    # Application Gateways
    if ($Global:NetworkData.ApplicationGateways -and $Global:NetworkData.ApplicationGateways.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "ApplicationGateways_$Timestamp.json"
            $Global:NetworkData.ApplicationGateways | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.ApplicationGateways.Count) Application Gateways to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Application Gateways to JSON: $_" -Level Warning
        }
    }
    
    # Virtual Network Gateways (VPN Gateways)
    if ($Global:NetworkData.VirtualNetworkGateways -and $Global:NetworkData.VirtualNetworkGateways.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "VPNGateways_$Timestamp.json"
            $Global:NetworkData.VirtualNetworkGateways | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.VirtualNetworkGateways.Count) VPN Gateways to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting VPN Gateways to JSON: $_" -Level Warning
        }
    }
    
    # Local Network Gateways
    if ($Global:NetworkData.LocalNetworkGateways -and $Global:NetworkData.LocalNetworkGateways.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "LocalNetworkGateways_$Timestamp.json"
            $Global:NetworkData.LocalNetworkGateways | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.LocalNetworkGateways.Count) Local Network Gateways to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Local Network Gateways to JSON: $_" -Level Warning
        }
    }
    
    # ExpressRoute Circuits
    if ($Global:NetworkData.ExpressRouteCircuits -and $Global:NetworkData.ExpressRouteCircuits.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "ExpressRouteCircuits_$Timestamp.json"
            $Global:NetworkData.ExpressRouteCircuits | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.ExpressRouteCircuits.Count) ExpressRoute Circuits to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting ExpressRoute Circuits to JSON: $_" -Level Warning
        }
    }
    
    # VNet Peerings
    if ($Global:NetworkData.VNetPeerings -and $Global:NetworkData.VNetPeerings.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "VNetPeerings_$Timestamp.json"
            $Global:NetworkData.VNetPeerings | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.VNetPeerings.Count) VNet Peerings to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting VNet Peerings to JSON: $_" -Level Warning
        }
    }
    
    # Private Endpoints
    if ($Global:NetworkData.PrivateEndpoints -and $Global:NetworkData.PrivateEndpoints.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "PrivateEndpoints_$Timestamp.json"
            $Global:NetworkData.PrivateEndpoints | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.PrivateEndpoints.Count) Private Endpoints to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Private Endpoints to JSON: $_" -Level Warning
        }
    }
    
    # NAT Gateways
    if ($Global:NetworkData.NATGateways -and $Global:NetworkData.NATGateways.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "NATGateways_$Timestamp.json"
            $Global:NetworkData.NATGateways | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.NATGateways.Count) NAT Gateways to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting NAT Gateways to JSON: $_" -Level Warning
        }
    }
    
    # Azure Firewalls
    if ($Global:NetworkData.AzureFirewalls -and $Global:NetworkData.AzureFirewalls.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "AzureFirewalls_$Timestamp.json"
            $Global:NetworkData.AzureFirewalls | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.AzureFirewalls.Count) Azure Firewalls to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Azure Firewalls to JSON: $_" -Level Warning
        }
    }
    
    # Bastion Hosts
    if ($Global:NetworkData.BastionHosts -and $Global:NetworkData.BastionHosts.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "BastionHosts_$Timestamp.json"
            $Global:NetworkData.BastionHosts | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.BastionHosts.Count) Bastion Hosts to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Bastion Hosts to JSON: $_" -Level Warning
        }
    }
    
    # Virtual Machines
    if ($Global:NetworkData.VirtualMachines -and $Global:NetworkData.VirtualMachines.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "VirtualMachines_$Timestamp.json"
            $Global:NetworkData.VirtualMachines | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.VirtualMachines.Count) Virtual Machines to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Virtual Machines to JSON: $_" -Level Warning
        }
    }
    
    # Subscriptions Summary
    if ($Global:NetworkData.Subscriptions -and $Global:NetworkData.Subscriptions.Count -gt 0) {
        try {
            $fileName = Join-Path $JsonPath "Subscriptions_$Timestamp.json"
            $Global:NetworkData.Subscriptions | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
            Write-Log "Exported $($Global:NetworkData.Subscriptions.Count) Subscriptions to JSON: $fileName" -Level Success
        } catch {
            Write-Log "Error exporting Subscriptions to JSON: $_" -Level Warning
        }
    }
    
    # Metadata
    try {
        $fileName = Join-Path $JsonPath "Metadata_$Timestamp.json"
        $Global:NetworkData.Metadata | ConvertTo-Json -Depth 10 | Out-File $fileName -Encoding utf8NoBOM
        Write-Log "Exported Metadata to JSON: $fileName" -Level Success
    } catch {
        Write-Log "Error exporting Metadata to JSON: $_" -Level Warning
    }
    
    Write-Log "JSON export completed" -Level Success
    
    # Generate reports with error handling
    try {
        Generate-HTMLReport -OutputPath $OutputPath
    } catch {
        Write-Log "Error generating HTML report: $_" -Level Warning
    }
    
    if ($GenerateTopology) {
        try {
            Generate-NetworkTopology -OutputPath $OutputPath
        } catch {
            Write-Log "Error generating network topology: $_" -Level Warning
        }
    }
    
    # Generate summary report
    $SummaryFile = Join-Path $OutputPath "Reports\NetworkSummary_$Timestamp.txt"
    $Summary = @"
Azure Network Discovery Summary Report
=====================================
Generated: $(Get-Date)
Execution Time: $($Global:NetworkData.Metadata.TotalExecutionTime)
Errors Encountered: $($Global:NetworkData.Metadata.ErrorCount)

SUBSCRIPTIONS ANALYZED: $($Global:NetworkData.Subscriptions.Count)

TOTAL RESOURCES DISCOVERED:
- Virtual Networks: $($Global:NetworkData.VirtualNetworks.Count)
- Subnets: $($Global:NetworkData.Subnets.Count)
- Network Security Groups: $($Global:NetworkData.NetworkSecurityGroups.Count)
- Public IP Addresses: $($Global:NetworkData.PublicIPs.Count)
- Load Balancers: $($Global:NetworkData.LoadBalancers.Count)
- Application Gateways: $($Global:NetworkData.ApplicationGateways.Count)
- VPN Gateways: $($Global:NetworkData.VirtualNetworkGateways.Count)
- ExpressRoute Circuits: $($Global:NetworkData.ExpressRouteCircuits.Count)
- Network Interfaces: $($Global:NetworkData.NetworkInterfaces.Count)
- Route Tables: $($Global:NetworkData.RouteTables.Count)
- VNet Peerings: $($Global:NetworkData.VNetPeerings.Count)
- Private Endpoints: $($Global:NetworkData.PrivateEndpoints.Count)
- NAT Gateways: $($Global:NetworkData.NATGateways.Count)
- Azure Firewalls: $($Global:NetworkData.AzureFirewalls.Count)
- Bastion Hosts: $($Global:NetworkData.BastionHosts.Count)

OUTPUT FILES GENERATED IN: $OutputPath
"@
    
    $Summary | Out-File $SummaryFile -Encoding utf8NoBOM
    Write-Log "Summary report saved to: $SummaryFile" -Level Success
    
    Write-Host "`n$Summary" -ForegroundColor Cyan
    Write-Log "`nAzure Network Discovery completed successfully!" -Level Success
    
    # Final reminder about topology generation
    if ($GenerateTopology -and $Global:NetworkData.VirtualNetworks.Count -gt 0) {
        Write-Host "`nTopology files have been generated in: $(Join-Path $OutputPath 'Topology')" -ForegroundColor Green
        Write-Host "- Interactive HTML visualization (no dependencies required)" -ForegroundColor Green
        Write-Host "- DOT file for further processing" -ForegroundColor Green
        
        if (Test-GraphvizInstalled) {
            Write-Host "- PNG, SVG, and other formats as specified" -ForegroundColor Green
        } else {
            Write-Host "`nNote: Install Graphviz to generate PNG/PDF/SVG diagrams:" -ForegroundColor Yellow
            Write-Host "  choco install graphviz" -ForegroundColor Yellow
            Write-Host "  OR" -ForegroundColor Yellow
            Write-Host "  winget install graphviz" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Log "Critical error in main execution: $_" -Level Error
    Write-Error $_
}