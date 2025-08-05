# Azure Network Discovery Script

A comprehensive PowerShell script for discovering, documenting, and visualizing Azure network resources across subscriptions. This tool generates detailed reports, interactive topology maps, and structured JSON data exports for all your Azure networking components.

## Features

- 🔍 **Comprehensive Discovery**: Discovers 20+ types of Azure network resources
- 🌐 **Multi-Subscription Support**: Scans across multiple subscriptions and tenants
- 📊 **Interactive Visualization**: Generates interactive HTML network topology maps
- 📄 **Detailed Reports**: Creates comprehensive HTML reports with all resource details
- 💾 **Structured Data Export**: Exports individual JSON files for each resource type
- 🎨 **Multiple Diagram Formats**: Supports DOT, SVG, PNG, and PDF (with Graphviz)
- 🔒 **Security Focused**: Includes detailed NSG rules and security configurations
- 📝 **Extensive Logging**: Detailed logging for troubleshooting and audit trails

## Prerequisites

- **PowerShell 7.0** or later
- **Azure PowerShell Modules**:
  - Az.Accounts
  - Az.Network
  - Az.Resources
  - Az.Compute
- **Azure Permissions**: Reader access to the subscriptions you want to scan
- **Optional**: Graphviz (for PNG/PDF/SVG diagram generation)

## Installation

1. **Install PowerShell 7+ (if needed)**:
   ```powershell
   winget install Microsoft.PowerShell
   ```

2. **Install Required Azure Modules**:
   ```powershell
   Install-Module -Name Az.Accounts -Force -AllowClobber
   Install-Module -Name Az.Network -Force -AllowClobber
   Install-Module -Name Az.Resources -Force -AllowClobber
   Install-Module -Name Az.Compute -Force -AllowClobber
   ```

3. **Install Graphviz (Optional - for diagram generation)**:
   ```powershell
   # Using Chocolatey
   choco install graphviz
   
   # Or using Winget
   winget install graphviz
   ```

## Usage

### Basic Usage

```powershell
# Run with default settings (discovers all subscriptions)
.\AzureNetworkDiscovery.ps1

# Specify custom output directory
.\AzureNetworkDiscovery.ps1 -OutputPath "C:\NetworkAudit"

# Filter specific subscriptions
.\AzureNetworkDiscovery.ps1 -SubscriptionFilter @("Subscription1", "Subscription2")

# Filter specific resource groups
.\AzureNetworkDiscovery.ps1 -ResourceGroupFilter @("RG1", "RG2")
```

### Advanced Options

```powershell
# Skip topology generation
.\AzureNetworkDiscovery.ps1 -GenerateTopology:$false

# Skip HTML report generation
.\AzureNetworkDiscovery.ps1 -GenerateHTMLReport:$false

# Exclude VMs from discovery (faster for large environments)
.\AzureNetworkDiscovery.ps1 -OnlyCoreNetwork

# Sanitize resource names in diagrams
.\AzureNetworkDiscovery.ps1 -Sanitize -Prefix "PROD_"

# Specify diagram output formats
.\AzureNetworkDiscovery.ps1 -DiagramFormats @("PNG", "SVG", "PDF")
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | String | `.\AzureNetworkDiscovery` | Output directory for all files |
| `-GenerateTopology` | Switch | `$true` | Generate network topology diagrams |
| `-GenerateHTMLReport` | Switch | `$true` | Generate HTML report |
| `-SubscriptionFilter` | String[] | All subscriptions | Filter specific subscriptions |
| `-ResourceGroupFilter` | String[] | All resource groups | Filter specific resource groups |
| `-ExportNSGRules` | Switch | `$true` | Include NSG rules in export |
| `-IncludeDiagnostics` | Switch | `$true` | Include diagnostic information |
| `-OnlyCoreNetwork` | Switch | `$false` | Exclude VMs from discovery |
| `-Sanitize` | Switch | `$false` | Sanitize resource names for DOT |
| `-Prefix` | String | Empty | Prefix for sanitized names |
| `-DiagramFormats` | String[] | `@("SVG", "PNG", "DOT")` | Diagram output formats |

## Resources Discovered

The script discovers and documents the following Azure resources:

- **Virtual Networks** (VNets) with address spaces and DNS settings
- **Subnets** with delegations and service endpoints
- **Network Security Groups** (NSGs) with all rules
- **Public IP Addresses** with allocation details
- **Load Balancers** with frontend/backend configurations
- **Application Gateways** with SKU and capacity info
- **VPN Gateways** with connection details
- **ExpressRoute Circuits** with provider information
- **Network Interfaces** with IP configurations
- **Route Tables** and custom routes
- **VNet Peerings** with peering state
- **Private Endpoints** with private link connections
- **NAT Gateways** with associated resources
- **Azure Firewalls** with policies
- **Bastion Hosts** with SKU details
- **Virtual Machines** (optional) with network associations

## Output Structure

```
.\AzureNetworkDiscovery\
├── JSON\                           # Individual JSON files for each resource type
│   ├── VirtualNetworks_[timestamp].json
│   ├── Subnets_[timestamp].json
│   ├── NetworkSecurityGroups_[timestamp].json
│   ├── NSGRules_[timestamp].json
│   └── ... (other resource types)
├── Topology\                       # Network topology diagrams
│   ├── NetworkMap_Interactive_[timestamp].html
│   ├── NetworkTopology_[timestamp].dot
│   ├── NetworkTopology_[timestamp].png
│   └── NetworkTopology_[timestamp].svg
└── Reports\                        # Generated reports
    ├── NetworkDiscovery_Report_[timestamp].html
    └── NetworkSummary_[timestamp].txt
```

## Output Files Explained

### JSON Files
- **Individual Resource Files**: Each resource type gets its own JSON file with complete data
- **Metadata.json**: Contains execution statistics and timestamps
- **Subscriptions.json**: Summary of all subscriptions processed

### Topology Files
- **NetworkMap_Interactive_*.html**: Self-contained interactive HTML visualization (no dependencies)
- **NetworkTopology_*.dot**: Graphviz DOT file for custom processing
- **NetworkTopology_*.png/svg**: Visual diagrams (requires Graphviz)

### Reports
- **NetworkDiscovery_Report_*.html**: Comprehensive HTML report with tables and summaries
- **NetworkSummary_*.txt**: Quick text summary of discovered resources

## Interactive Topology Features

The interactive HTML topology includes:
- 🖱️ **Drag and Pan**: Click and drag to move around the diagram
- 🔍 **Zoom**: Mouse wheel to zoom in/out
- 🎯 **Select Nodes**: Click nodes to see detailed information
- 🔎 **Search**: Find specific resources by name
- 🔄 **Force Layout**: Automatic node positioning with physics simulation
- 🎨 **Color Coding**: Different colors for different resource types

## Authentication

The script uses your current Azure PowerShell context. If not authenticated:

```powershell
# Login to Azure
Connect-AzAccount

# Select specific tenant (if needed)
Connect-AzAccount -TenantId "your-tenant-id"

# Select specific subscription
Set-AzContext -SubscriptionId "your-subscription-id"
```

## Troubleshooting

### Common Issues

1. **"This script requires PowerShell 7 or later"**
   - Install PowerShell 7: `winget install Microsoft.PowerShell`

2. **"Cannot find module Az.Network"**
   - Install required modules: `Install-Module -Name Az.Network -Force`

3. **"No accessible subscriptions found"**
   - Login to Azure: `Connect-AzAccount`
   - Check permissions: Ensure you have Reader access

4. **Topology files not generating**
   - Check the logs in the output directory
   - Ensure you have at least one VNet discovered
   - For PNG/PDF: Install Graphviz

5. **Large environments timeout**
   - Use `-SubscriptionFilter` to process specific subscriptions
   - Use `-ResourceGroupFilter` to limit scope
   - Use `-OnlyCoreNetwork` to exclude VMs

### Log Files

Detailed logs are saved to: `[OutputPath]\NetworkDiscovery_[date].log`

## Performance Tips

- **Large Environments**: Use filters to limit scope
- **Faster Execution**: Use `-OnlyCoreNetwork` to skip VM discovery
- **Parallel Processing**: The script processes subscriptions sequentially; consider running multiple instances with different filters

## Security Considerations

- The script requires only **Reader** permissions
- No modifications are made to any resources
- Sensitive information (like NSG rules) is included in exports - secure the output files appropriately
- Consider using `-Sanitize` flag when sharing diagrams externally

## Examples

### Example 1: Full Discovery with Custom Path
```powershell
.\AzureNetworkDiscovery.ps1 -OutputPath "D:\AzureAudit\Network" -DiagramFormats @("PNG", "SVG")
```

### Example 2: Production Environment Only
```powershell
.\AzureNetworkDiscovery.ps1 -SubscriptionFilter @("Production") -ResourceGroupFilter @("PROD-*")
```

### Example 3: Quick Core Network Overview
```powershell
.\AzureNetworkDiscovery.ps1 -OnlyCoreNetwork -GenerateHTMLReport:$false
```

### Example 4: Sanitized Output for Documentation
```powershell
.\AzureNetworkDiscovery.ps1 -Sanitize -Prefix "CORP_" -DiagramFormats @("SVG")
```

## License

This script is provided as-is for network discovery and documentation purposes.

## Contributing

Feel free to submit issues, fork, and create pull requests for any improvements.

## Version History

- **v1.0**: Initial release with comprehensive network discovery
- **v1.1**: Added interactive HTML topology
- **v1.2**: Switched from CSV to individual JSON exports
- **v1.3**: Enhanced topology generation with force-directed layout