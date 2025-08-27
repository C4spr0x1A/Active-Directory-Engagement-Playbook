# 🌐 Network Enumeration - Foundation for Active Directory Discovery

> **🎯 PURPOSE**: This is your **network discovery foundation** for Active Directory enumeration. Every AD technique starts here - mapping networks, discovering services, and identifying the attack surface before diving into specific AD enumeration.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🛠️ Previous: Tool Arsenal](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup) | [Next: DNS Enumeration](./03_DNS_Enumeration.md)

---

## 🔗 **RELATED ACTIVE DIRECTORY COMPONENTS**

### **🏗️ Infrastructure Discovery Targets**
- **[Domain Controllers](../02_Active_Directory_Components/02_Domain_Controllers.md)**: Primary targets for network discovery and service enumeration
- **[Sites and Subnets](../02_Active_Directory_Components/06_Sites_and_Subnets.md)**: Network topology and physical location mapping
- **[LDAP and Ports](../02_Active_Directory_Components/13_LDAP_and_Ports.md)**: Communication protocols and port configurations

### **🌐 Architecture Understanding**
- **[Domain](../02_Active_Directory_Components/03_Domain.md)**: Security boundaries and administrative units discovered through network mapping
- **[Forest](../02_Active_Directory_Components/04_Forest.md)**: Multi-domain architecture revealed through network topology
- **[Replication Service](../02_Active_Directory_Components/15_Replication_Service.md)**: Network traffic patterns and synchronization paths

### **🔐 Security and Policy Discovery**
- **[Group Policy Objects](../02_Active_Directory_Components/09_Group_Policy_Objects.md)**: Network security policies and restrictions
- **[Trusts](../02_Active_Directory_Components/07_Trusts.md)**: Cross-domain network relationships
- **[FSMO Roles](../02_Active_Directory_Components/08_FSMO_Roles.md)**: Critical infrastructure placement

---

## 🚀 **NETWORK DISCOVERY OVERVIEW**

### **🎭 What This Foundation Provides**
Network enumeration is the **first step** in any AD engagement. Before you can enumerate users, groups, or Kerberos tickets, you need to know:
- **What networks exist** and which hosts are alive
- **What services are running** on key infrastructure
- **How to reach** domain controllers and critical services
- **Where to pivot** for deeper enumeration

> **Note on OPSEC**: In production, favor Microsoft-signed/native tooling and low-noise collection. If offensive tooling is permitted by ROE, consider stealth wrappers (e.g., Invisi-Shell). See [Tool Arsenal](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup).

### **🎯 Discovery Categories**
- **Network Topology**: Subnets, routing, and network boundaries
- **Host Discovery**: Alive hosts and their roles
- **Service Mapping**: Ports, protocols, and running services
- **Pivot Planning**: Strategic next steps for AD enumeration

### **🛠️ Mandatory Tools**
- **Invisi-Shell**: Optional stealth wrapper (use only if permitted by ROE)
- **Native Windows Tools**: Built-in commands for minimal footprint
- **PowerShell Modules**: For advanced enumeration capabilities

---

## 📋 **QUICK START NETWORK DISCOVERY**

### **⚡ Immediate Discovery Commands**
| **What You Need** | **Quick Command** | **Full Setup** |
|-------------------|-------------------|----------------|
| **Basic Connectivity** | `Test-Connection -ComputerName "dc01.corp.local"` | [Basic Network Discovery](#basic-network-discovery) |
| **Service Ports** | `Test-NetConnection -ComputerName "dc01.corp.local" -Port 88,389,445` | [Service Port Discovery](#service-port-discovery) |
| **Subnet Scanning** | `1..254 \| % { Test-Connection "192.168.1.$_" -Quiet }` | [Subnet Enumeration](#subnet-enumeration) |
| **DNS Resolution** | `Resolve-DnsName "corp.local" -Type SRV` | [DNS Service Discovery](#dns-service-discovery) |
| **Network Topology** | `netstat -an \| findstr LISTENING` | [Network Topology Mapping](#network-topology-mapping) |

### **🎯 Environment-Specific Discovery**
```powershell
# Production Environment (Stealth Mode)
if($env:COMPUTERNAME -like "*PROD*" -or $env:USERDOMAIN -like "*PROD*") {
    Write-Host "Production environment detected - using stealth profile" -ForegroundColor Yellow
    $discoveryProfile = "Stealth"
    $delayRange = @(5, 10)
    $maxConcurrent = 1
    
    # Optional: load a stealth wrapper if approved by ROE
    . .\RunWithPathAsAdmin.bat
    $env:INVISI_SHELL_ACTIVE = $true
} else {
    Write-Host "Lab environment detected - using balanced profile" -ForegroundColor Green
    $discoveryProfile = "Balanced"
    $delayRange = @(3, 7)
    $maxConcurrent = 3
}

Write-Host "Discovery Profile: $discoveryProfile" -ForegroundColor Cyan
Write-Host "Delay Range: $($delayRange[0])-$($delayRange[1]) seconds" -ForegroundColor Cyan
Write-Host "Max Concurrent: $maxConcurrent" -ForegroundColor Cyan
```

---

## 🛠️ **ENUMERATION TOOLS OVERVIEW**

> **OPSEC Guidance**: Prefer signed/native tooling. If you must use offensive tooling, apply stealth controls appropriate to your environment and authorization.

### **🔧 Tool Categories and Capabilities**

#### **Stealth Tools (Production Required)**
- **Invisi-Shell**: Optional stealth wrapper when authorized
- **Native Windows Commands**: Built-in tools for minimal footprint
- **PowerShell Stealth Mode**: Reduced logging and detection

#### **Enumeration Tools**
- **Network Discovery**: ICMP, TCP, and service enumeration
- **Port Scanning**: Service identification and mapping
- **Topology Mapping**: Network structure and relationship discovery

#### **Analysis Tools**
- **Data Processing**: Results analysis and pivot planning
- **Reporting**: Enumeration findings and next steps
- **Integration**: Connection to subsequent AD enumeration techniques

---

## 🔍 **BASIC NETWORK DISCOVERY**

### **🌐 ICMP Discovery (Ping Sweeps)**

#### **What is ICMP Discovery?**
**ICMP Discovery** uses ping requests to determine which hosts are alive on the network. This is the foundation for all subsequent enumeration.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
**What it provides**: Built-in Windows tools for basic network discovery
**CLM Status**: ✅ Native Windows (trusted)
**Use Case**: Minimal footprint, basic discovery, fallback option

```powershell
# Basic ping sweep
1..254 | ForEach-Object { 
    $ip = "192.168.1.$_"
    if(Test-Connection -ComputerName $ip -Quiet -Count 1) {
        Write-Host "✓ $ip" -ForegroundColor Green
    }
}

# Ping sweep with timeout
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    if(Test-Connection -ComputerName $ip -Quiet -Count 1 -TimeoutSeconds 2) {
        Write-Host "✓ $ip" -ForegroundColor Green
    }
}

# Ping sweep with progress
$total = 254
$current = 0
1..254 | ForEach-Object { 
    $current++
    $percent = [math]::Round(($current / $total) * 100, 1)
    Write-Progress -Activity "Ping Sweep" -Status "Scanning 192.168.1.$_" -PercentComplete $percent
    
    $ip = "192.168.1.$_"
    if(Test-Connection -ComputerName $ip -Quiet -Count 1) {
        Write-Host "✓ $ip" -ForegroundColor Green
    }
}
```

**Tool Advantages**:
- ✅ Built into Windows
- ✅ No additional installation
- ✅ Minimal security footprint
- ✅ Always available
- ✅ Basic discovery capabilities

**Tool Limitations**:
- ❌ Limited functionality
- ❌ Basic output format
- ❌ No rich object properties
- ❌ Limited filtering options

#### **Tool 2: PowerView Suite (Comprehensive Enumeration)**
**What it provides**: PowerShell framework for comprehensive network enumeration
**CLM Status**: ❌ Not signed (offensive tool)
**Use Case**: Lab environments, penetration testing, offensive operations

```powershell
# Load PowerView
. .\PowerView.ps1

# Network discovery via AD
$computers = Get-DomainComputer -Properties name,ipaddress,operatingsystem
$computers | ForEach-Object {
    if($_.ipaddress) {
        Write-Host "✓ $($_.name) - $($_.ipaddress) - $($_.operatingsystem)" -ForegroundColor Green
    }
}

# Site-based network discovery
$sites = Get-DomainSite
foreach($site in $sites) {
    Write-Host "Site: $($site.Name)" -ForegroundColor Cyan
    $siteComputers = Get-DomainComputer -Site $site.Name
    $siteComputers | ForEach-Object {
        Write-Host "  $($_.name)" -ForegroundColor White
    }
}

# Subnet discovery via AD
$subnets = Get-DomainSubnet
foreach($subnet in $subnets) {
    Write-Host "Subnet: $($subnet.Name) - $($subnet.Location)" -ForegroundColor Cyan
}
```

**Tool Advantages**:
- ✅ Comprehensive network enumeration
- ✅ Rich object properties and methods
- ✅ Built-in filtering and search
- ✅ Offensive-focused functions
- ✅ Extensive customization options

**Tool Limitations**:
- ❌ Not Microsoft-signed
- ❌ May trigger security alerts
- ❌ Not CLM-compliant
- ❌ Requires careful deployment

#### **Tool 3: Microsoft AD Module (Stealth Operations)**
**What it provides**: Official Microsoft module for AD-based network discovery
**CLM Status**: ✅ Fully signed and CLM-friendly
**Use Case**: Production environments, compliance requirements

```powershell
# Load the module
Import-Module ActiveDirectory

# Network discovery via AD computers
$computers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site
$computers | ForEach-Object {
    if($_.IPv4Address) {
        Write-Host "✓ $($_.Name) - $($_.IPv4Address) - $($_.OperatingSystem)" -ForegroundColor Green
    }
}

# Site-based network discovery
$sites = Get-ADReplicationSite -Filter *
foreach($site in $sites) {
    Write-Host "Site: $($site.Name)" -ForegroundColor Cyan
    $siteComputers = Get-ADComputer -Filter * -SearchBase $site.DistinguishedName
    $siteComputers | ForEach-Object {
        Write-Host "  $($_.Name)" -ForegroundColor White
    }
}

# Subnet discovery via AD
$subnets = Get-ADReplicationSubnet -Filter *
foreach($subnet in $subnets) {
    Write-Host "Subnet: $($subnet.Name) - $($subnet.Location)" -ForegroundColor Cyan
}
```

**Tool Advantages**:
- ✅ Microsoft-signed and trusted
- ✅ CLM-compliant
- ✅ Rich object properties
- ✅ Built-in filtering and selection
- ✅ Production environment safe

**Tool Limitations**:
- ❌ Requires AD module installation
- ❌ Some properties may be restricted
- ❌ Limited to standard AD objects

---

## 🔌 **SERVICE PORT DISCOVERY**

### **🌐 Port Scanning and Service Identification**

#### **What is Service Port Discovery?**
**Service Port Discovery** identifies which services are running on discovered hosts, revealing the attack surface and potential pivot points.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
```powershell
# Single host, single port
Test-NetConnection -ComputerName "dc01.corp.local" -Port 445

# Single host, multiple ports
$ports = @(88, 389, 445, 5985)
foreach($port in $ports) {
    $result = Test-NetConnection -ComputerName "dc01.corp.local" -Port $port -InformationLevel Quiet
    $status = if($result.TcpTestSucceeded) {"Open"}else{"Closed"}
    Write-Host "Port $port`: $status" -ForegroundColor $(if($result.TcpTestSucceeded){"Green"}else{"Red"})
}

# Multiple hosts, multiple ports
$hosts = @("dc01.corp.local", "dc02.corp.local")
$ports = @(88, 389, 445, 5985)

foreach($host in $hosts) {
    Write-Host "`nScanning $host`:" -ForegroundColor Cyan
    foreach($port in $ports) {
        $result = Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet
        $status = if($result.TcpTestSucceeded) {"Open"}else{"Closed"}
        Write-Host "  Port $port`: $status" -ForegroundColor $(if($result.TcpTestSucceeded){"Green"}else{"Red"})
    }
}
```

#### **Tool 2: PowerView Suite (Comprehensive Service Discovery)**
```powershell
# Service discovery via AD
$computers = Get-DomainComputer -Properties name,ipaddress,operatingsystem
foreach($computer in $computers) {
    if($computer.ipaddress) {
        Write-Host "`nAnalyzing $($computer.name) ($($computer.ipaddress)):" -ForegroundColor Cyan
        
        # Test common AD ports
        $adPorts = @(88, 389, 445, 5985, 3389)
        foreach($port in $adPorts) {
            try {
                $result = Test-NetConnection -ComputerName $computer.ipaddress -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                if($result.TcpTestSucceeded) {
                    $service = switch($port) {
                        88 { "Kerberos" }
                        389 { "LDAP" }
                        445 { "SMB" }
                        5985 { "WinRM" }
                        3389 { "RDP" }
                        default { "Unknown" }
                    }
                    Write-Host "  ✓ Port $port ($service) is OPEN" -ForegroundColor Green
                }
            } catch {
                Write-Host "  ✗ Port $port test failed" -ForegroundColor Red
            }
        }
    }
}

# Service discovery via SPNs
$spnComputers = Get-DomainComputer -SPN -Properties name,ipaddress,serviceprincipalname
foreach($computer in $spnComputers) {
    Write-Host "`nService Host: $($computer.name) ($($computer.ipaddress))" -ForegroundColor Yellow
    $computer.serviceprincipalname | ForEach-Object {
        Write-Host "  SPN: $_" -ForegroundColor White
    }
}
```

#### **Tool 3: Microsoft AD Module (Stealth Service Discovery)**
```powershell
# Service discovery via AD computers
$computers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, ServicePrincipalName
foreach($computer in $computers) {
    if($computer.IPv4Address) {
        Write-Host "`nAnalyzing $($computer.Name) ($($computer.IPv4Address)):" -ForegroundColor Cyan
        
        # Test common AD ports
        $adPorts = @(88, 389, 445, 5985, 3389)
        foreach($port in $adPorts) {
            try {
                $result = Test-NetConnection -ComputerName $computer.IPv4Address -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                if($result.TcpTestSucceeded) {
                    $service = switch($port) {
                        88 { "Kerberos" }
                        389 { "LDAP" }
                        445 { "SMB" }
                        5985 { "WinRM" }
                        3389 { "RDP" }
                        default { "Unknown" }
                    }
                    Write-Host "  ✓ Port $port ($service) is OPEN" -ForegroundColor Green
                }
            } catch {
                Write-Host "  ✗ Port $port test failed" -ForegroundColor Red
            }
        }
        
        # Check for SPNs
        if($computer.ServicePrincipalName) {
            Write-Host "  Service Principal Names:" -ForegroundColor Yellow
            $computer.ServicePrincipalName | ForEach-Object {
                Write-Host "    $_" -ForegroundColor White
            }
        }
    }
}
```

#### **Advanced Port Scanning Techniques**
```powershell
# Port range scanning
$portRange = 80..90
$host = "dc01.corp.local"

Write-Host "Scanning ports $($portRange[0])-$($portRange[-1]) on $host`:" -ForegroundColor Cyan

foreach($port in $portRange) {
    $result = Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet
    if($result.TcpTestSucceeded) {
        Write-Host "  ✓ Port $port is OPEN" -ForegroundColor Green
    }
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)  # Stealth delay
}

# Service identification
$commonServices = @{
    21 = "FTP"
    22 = "SSH"
    23 = "Telnet"
    25 = "SMTP"
    53 = "DNS"
    80 = "HTTP"
    88 = "Kerberos"
    110 = "POP3"
    143 = "IMAP"
    389 = "LDAP"
    443 = "HTTPS"
    445 = "SMB"
    1433 = "MSSQL"
    1521 = "Oracle"
    3306 = "MySQL"
    3389 = "RDP"
    5432 = "PostgreSQL"
    5985 = "WinRM"
    5986 = "WinRM-SSL"
    8080 = "HTTP-Alt"
}

# Scan and identify services
$host = "dc01.corp.local"
$ports = @(80, 88, 389, 445, 5985, 3389)

Write-Host "Service identification for $host`:" -ForegroundColor Cyan
foreach($port in $ports) {
    $result = Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet
    if($result.TcpTestSucceeded) {
        $service = if($commonServices.ContainsKey($port)){$commonServices[$port]}else{"Unknown"}
        Write-Host "  ✓ Port $port ($service) is OPEN" -ForegroundColor Green
    }
}
```

---

## 🗺️ **SUBNET ENUMERATION**

### **🌍 Subnet Discovery and Mapping**

#### **What is Subnet Enumeration?**
**Subnet Enumeration** systematically discovers all hosts within network ranges to build a complete picture of the network topology.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
```powershell
# Single subnet scan
$subnet = "192.168.1"
$start = 1
$end = 254

Write-Host "Scanning subnet $subnet.0/24..." -ForegroundColor Cyan
$aliveHosts = @()

for($i = $start; $i -le $end; $i++) {
    $ip = "$subnet.$i"
    $percent = [math]::Round((($i - $start + 1) / ($end - $start + 1)) * 100, 1)
    Write-Progress -Activity "Subnet Scan" -Status "Scanning $ip" -PercentComplete $percent
    
    if(Test-Connection -ComputerName $ip -Quiet -Count 1) {
        $aliveHosts += $ip
        Write-Host "  ✓ $ip" -ForegroundColor Green
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}

Write-Host "`nSubnet scan complete. Found $($aliveHosts.Count) alive hosts." -ForegroundColor Cyan
$aliveHosts | Sort-Object {[System.Version]$_}
```

#### **Tool 2: PowerView Suite (Comprehensive Subnet Discovery)**
```powershell
# Load PowerView
. .\PowerView.ps1

# Subnet discovery via AD sites and subnets
$sites = Get-DomainSite
foreach($site in $sites) {
    Write-Host "`nSite: $($site.Name)" -ForegroundColor Cyan
    
    # Get subnets for this site
    $siteSubnets = Get-DomainSubnet | Where-Object { $_.Site -eq $site.Name }
    foreach($subnet in $siteSubnets) {
        Write-Host "  Subnet: $($subnet.Name) - $($subnet.Location)" -ForegroundColor Yellow
        
        # Get computers in this subnet
        $subnetComputers = Get-DomainComputer -Properties name,ipaddress,operatingsystem | Where-Object {
            $_.ipaddress -and $_.ipaddress -like "$($subnet.Name)*"
        }
        
        foreach($computer in $subnetComputers) {
            Write-Host "    ✓ $($computer.name) - $($computer.ipaddress) - $($computer.operatingsystem)" -ForegroundColor Green
        }
    }
}

# Cross-subnet analysis
$allSubnets = Get-DomainSubnet
$allComputers = Get-DomainComputer -Properties name,ipaddress,operatingsystem,site

$subnetAnalysis = @{}
foreach($subnet in $allSubnets) {
    $subnetComputers = $allComputers | Where-Object {
        $_.ipaddress -and $_.ipaddress -like "$($subnet.Name)*"
    }
    
    $subnetAnalysis[$subnet.Name] = @{
        Location = $subnet.Location
        ComputerCount = $subnetComputers.Count
        Computers = $subnetComputers
        OperatingSystems = $subnetComputers | Group-Object OperatingSystem
    }
}

# Generate subnet analysis report
Write-Host "`n=== SUBNET ANALYSIS REPORT ===" -ForegroundColor Magenta
foreach($subnet in $subnetAnalysis.Keys) {
    $info = $subnetAnalysis[$subnet]
    Write-Host "`nSubnet: $subnet" -ForegroundColor Cyan
    Write-Host "  Location: $($info.Location)" -ForegroundColor White
    Write-Host "  Computers: $($info.ComputerCount)" -ForegroundColor Green
    
    if($info.OperatingSystems) {
        Write-Host "  Operating Systems:" -ForegroundColor Yellow
        $info.OperatingSystems | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor White
        }
    }
}
```

#### **Tool 3: Microsoft AD Module (Stealth Subnet Discovery)**
```powershell
# Load the module
Import-Module ActiveDirectory

# Subnet discovery via AD replication sites and subnets
$sites = Get-ADReplicationSite -Filter *
foreach($site in $sites) {
    Write-Host "`nSite: $($site.Name)" -ForegroundColor Cyan
    
    # Get subnets for this site
    $siteSubnets = Get-ADReplicationSubnet -Filter * | Where-Object { $_.Site -eq $site.Name }
    foreach($subnet in $siteSubnets) {
        Write-Host "  Subnet: $($subnet.Name) - $($subnet.Location)" -ForegroundColor Yellow
        
        # Get computers in this subnet
        $subnetComputers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site | Where-Object {
            $_.IPv4Address -and $_.IPv4Address -like "$($subnet.Name)*"
        }
        
        foreach($computer in $subnetComputers) {
            Write-Host "    ✓ $($computer.Name) - $($computer.IPv4Address) - $($computer.OperatingSystem)" -ForegroundColor Green
        }
    }
}

# Cross-subnet analysis via AD
$allSubnets = Get-ADReplicationSubnet -Filter *
$allComputers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site

$adSubnetAnalysis = @{}
foreach($subnet in $allSubnets) {
    $subnetComputers = $allComputers | Where-Object {
        $_.IPv4Address -and $_.IPv4Address -like "$($subnet.Name)*"
    }
    
    $adSubnetAnalysis[$subnet.Name] = @{
        Location = $subnet.Location
        ComputerCount = $subnetComputers.Count
        Computers = $subnetComputers
        OperatingSystems = $subnetComputers | Group-Object OperatingSystem
    }
}

# Generate AD subnet analysis report
Write-Host "`n=== AD SUBNET ANALYSIS REPORT ===" -ForegroundColor Magenta
foreach($subnet in $adSubnetAnalysis.Keys) {
    $info = $adSubnetAnalysis[$subnet]
    Write-Host "`nSubnet: $subnet" -ForegroundColor Cyan
    Write-Host "  Location: $($info.Location)" -ForegroundColor White
    Write-Host "  Computers: $($info.ComputerCount)" -ForegroundColor Green
    
    if($info.OperatingSystems) {
        Write-Host "  Operating Systems:" -ForegroundColor Yellow
        $info.OperatingSystems | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor White
        }
    }
}
```

#### **Multi-Subnet Enumeration**
```powershell
# Define multiple subnets
$subnets = @(
    @{Network = "192.168.1"; Start = 1; End = 254; Description = "HQ Network"}
    @{Network = "10.10.0"; Start = 1; End = 254; Description = "US Network"}
    @{Network = "172.16.20"; Start = 1; End = 254; Description = "EU Network"}
)

$allAliveHosts = @{}

foreach($subnet in $subnets) {
    Write-Host "`nScanning $($subnet.Description) ($($subnet.Network).0/24)..." -ForegroundColor Cyan
    $aliveHosts = @()
    
    for($i = $subnet.Start; $i -le $subnet.End; $i++) {
        $ip = "$($subnet.Network).$i"
        $percent = [math]::Round((($i - $subnet.Start + 1) / ($subnet.End - $subnet.Start + 1)) * 100, 1)
        Write-Progress -Activity "Multi-Subnet Scan" -Status "Scanning $ip" -PercentComplete $percent
        
        if(Test-Connection -ComputerName $ip -Quiet -Count 1) {
            $aliveHosts += $ip
            Write-Host "  ✓ $ip" -ForegroundColor Green
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    $allAliveHosts[$subnet.Description] = $aliveHosts
    Write-Host "  Found $($aliveHosts.Count) alive hosts" -ForegroundColor Yellow
}

# Summary report
Write-Host "`n=== MULTI-SUBNET SCAN SUMMARY ===" -ForegroundColor Magenta
$totalHosts = 0
foreach($subnet in $subnets) {
    $count = $allAliveHosts[$subnet.Description].Count
    $totalHosts += $count
    Write-Host "$($subnet.Description): $count hosts" -ForegroundColor White
}
Write-Host "Total alive hosts: $totalHosts" -ForegroundColor Green
```

#### **Subnet Enumeration Error Handling**
```powershell
# Handle network errors gracefully
function Test-SubnetConnectivity {
    param(
        [string]$Subnet,
        [int]$Start = 1,
        [int]$End = 254,
        [int]$Timeout = 3
    )
    
    $aliveHosts = @()
    $errors = @()
    
    for($i = $Start; $i -le $End; $i++) {
        $ip = "$Subnet.$i"
        
        try {
            $result = Test-Connection -ComputerName $ip -Quiet -Count 1 -TimeoutSeconds $Timeout
            if($result) {
                $aliveHosts += $ip
                Write-Host "  ✓ $ip" -ForegroundColor Green
            }
        } catch {
            $errorMsg = "Error scanning $ip`: $($_.Exception.Message)"
            $errors += $errorMsg
            Write-Host "  ✗ $ip (Error)" -ForegroundColor Red
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    return @{
        AliveHosts = $aliveHosts
        Errors = $errors
        TotalScanned = ($End - $Start + 1)
        SuccessRate = [math]::Round(($aliveHosts.Count / ($End - $Start + 1)) * 100, 1)
    }
}

# Use the function
$subnetResults = Test-SubnetConnectivity -Subnet "192.168.1" -Start 1 -End 254

Write-Host "`nSubnet scan results:" -ForegroundColor Cyan
Write-Host "  Alive hosts: $($subnetResults.AliveHosts.Count)" -ForegroundColor Green
Write-Host "  Errors: $($subnetResults.Errors.Count)" -ForegroundColor Red
Write-Host "  Success rate: $($subnetResults.SuccessRate)%" -ForegroundColor Yellow
```

---

## 🔍 **SERVICE PORT DISCOVERY**

### **🎯 AD Service Port Mapping**

#### **What is Service Port Discovery?**
**Service Port Discovery** identifies which Active Directory services are running on discovered hosts. This is crucial for planning enumeration strategies.

#### **Critical AD Service Discovery**
```powershell
# Define AD service ports with descriptions
$adServices = @{
    88 = @{Name = "Kerberos"; Description = "Authentication service"; Enumeration = "Kerberos attacks"}
    389 = @{Name = "LDAP"; Description = "Directory services"; Enumeration = "User/Group enumeration"}
    636 = @{Name = "LDAPS"; Description = "Secure LDAP"; Enumeration = "Encrypted directory access"}
    445 = @{Name = "SMB"; Description = "File sharing"; Enumeration = "Share enumeration"}
    139 = @{Name = "NetBIOS"; Description = "NetBIOS over TCP"; Enumeration = "Service enumeration"}
    53 = @{Name = "DNS"; Description = "Domain name resolution"; Enumeration = "DNS enumeration"}
    5985 = @{Name = "WinRM"; Description = "Windows Remote Management"; Enumeration = "PowerShell remoting"}
    5986 = @{Name = "WinRM-SSL"; Description = "Secure WinRM"; Enumeration = "Encrypted remoting"}
    3389 = @{Name = "RDP"; Description = "Remote Desktop"; Enumeration = "Session enumeration"}
    1433 = @{Name = "MSSQL"; Description = "SQL Server"; Enumeration = "Database enumeration"}
    1521 = @{Name = "Oracle"; Description = "Oracle Database"; Enumeration = "Database enumeration"}
}

Write-Host "Active Directory Service Ports:" -ForegroundColor Cyan
$adServices.GetEnumerator() | Sort-Object Key | ForEach-Object {
    Write-Host "  Port $($_.Key): $($_.Value.Name) - $($_.Value.Description)" -ForegroundColor White
    Write-Host "    → Enumeration: $($_.Value.Enumeration)" -ForegroundColor Gray
}
```

#### **Comprehensive Service Discovery**
```powershell
# Service discovery function
function Test-ADServices {
    param(
        [string[]]$Hosts,
        [int[]]$Ports = @(88, 389, 445, 5985, 3389),
        [int]$Timeout = 3
    )
    
    $results = @()
    
    foreach($host in $Hosts) {
        Write-Host "`nScanning $host for AD services..." -ForegroundColor Cyan
        
        $hostResult = [PSCustomObject]@{
            Host = $host
            Services = @()
            OpenPorts = 0
            TotalPorts = $Ports.Count
        }
        
        foreach($port in $Ports) {
            try {
                $result = Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                
                if($result.TcpTestSucceeded) {
                    $serviceName = if($adServices.ContainsKey($port)){$adServices[$port].Name}else{"Unknown"}
                    $serviceDesc = if($adServices.ContainsKey($port)){$adServices[$port].Description}else{"Unknown service"}
                    
                    $serviceInfo = [PSCustomObject]@{
                        Port = $port
                        Service = $serviceName
                        Description = $serviceDesc
                        Status = "Open"
                        Enumeration = if($adServices.ContainsKey($port)){$adServices[$port].Enumeration}else{"Unknown"}
                    }
                    
                    $hostResult.Services += $serviceInfo
                    $hostResult.OpenPorts++
                    
                    Write-Host "  ✓ Port $port ($serviceName) - $serviceDesc" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ Port $port - Closed" -ForegroundColor Red
                }
            } catch {
                Write-Host "  ✗ Port $port - Error: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            # Stealth delay
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
        }
        
        $results += $hostResult
        
        # Host summary
        $successRate = [math]::Round(($hostResult.OpenPorts / $hostResult.TotalPorts) * 100, 1)
        Write-Host "  Summary: $($hostResult.OpenPorts)/$($hostResult.TotalPorts) ports open ($successRate%)" -ForegroundColor Yellow
    }
    
    return $results
}

# Use the function
$targets = @("dc01.corp.local", "dc02.corp.local", "192.168.1.10")
$adPorts = @(88, 389, 445, 5985, 3389)

$serviceResults = Test-ADServices -Hosts $targets -Ports $adPorts

# Generate report
Write-Host "`n=== AD SERVICE DISCOVERY REPORT ===" -ForegroundColor Magenta
foreach($result in $serviceResults) {
    Write-Host "`nHost: $($result.Host)" -ForegroundColor Cyan
    Write-Host "  Open ports: $($result.OpenPorts)/$($result.TotalPorts)" -ForegroundColor White
    
    foreach($service in $result.Services) {
        Write-Host "    Port $($service.Port) ($($service.Service)): $($service.Description)" -ForegroundColor Green
        Write-Host "      → Next: $($service.Enumeration)" -ForegroundColor Gray
    }
}
```

---

## 🌐 **DNS SERVICE DISCOVERY**

### **🌐 Active Directory Service Location via DNS**

#### **What is DNS Service Discovery?**
**DNS Service Discovery** uses DNS SRV records to locate Active Directory services like domain controllers, global catalogs, and Kerberos distribution centers.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
```powershell
# Basic DNS resolution
Resolve-DnsName "corp.local"
Resolve-DnsName "dc01.corp.local"

# SRV record discovery for AD services
Resolve-DnsName "_ldap._tcp.dc._msdcs.corp.local" -Type SRV
Resolve-DnsName "_kerberos._tcp.corp.local" -Type SRV
Resolve-DnsName "_ldap._tcp.gc._msdcs.corp.local" -Type SRV

# DNS service enumeration function
function Discover-DNSServices {
    param(
        [string]$Domain = "corp.local"
    )
    
    $services = @{
        "Domain Controllers" = "_ldap._tcp.dc._msdcs.$Domain"
        "Kerberos KDCs" = "_kerberos._tcp.$Domain"
        "Global Catalogs" = "_ldap._tcp.gc._msdcs.$Domain"
        "Password Change" = "_kpasswd._tcp.$Domain"
        "PDC Emulator" = "_ldap._tcp.pdc._msdcs.$Domain"
    }
    
    $results = @{}
    
    foreach($service in $services.Keys) {
        $srvRecord = $services[$service]
        Write-Host "`nDiscovering $service..." -ForegroundColor Cyan
        
        try {
            $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
            $results[$service] = $records
            
            foreach($record in $records) {
                Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
                Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  ✗ No $service records found" -ForegroundColor Red
            $results[$service] = @()
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    return $results
}

# Use the function
$dnsResults = Discover-DNSServices -Domain "corp.local"

# Generate DNS discovery report
Write-Host "`n=== DNS SERVICE DISCOVERY REPORT ===" -ForegroundColor Magenta
foreach($service in $dnsResults.Keys) {
    $records = $dnsResults[$service]
    Write-Host "`n$service Services:" -ForegroundColor Cyan
    if($records.Count -gt 0) {
        foreach($record in $records) {
            Write-Host "  $($record.Target):$($record.Port)" -ForegroundColor Green
        }
    } else {
        Write-Host "  No services found" -ForegroundColor Red
    }
}
```

#### **Tool 2: PowerView Suite (Comprehensive DNS Discovery)**
```powershell
# Load PowerView
. .\PowerView.ps1

# DNS discovery via AD domain information
$domain = Get-Domain
Write-Host "Domain: $($domain.Name)" -ForegroundColor Cyan
Write-Host "Domain SID: $($domain.DomainSID)" -ForegroundColor Cyan

# DNS-based service discovery
$dnsServices = @{
    "Domain Controllers" = "_ldap._tcp.dc._msdcs.$($domain.Name)"
    "Kerberos KDCs" = "_kerberos._tcp.$($domain.Name)"
    "Global Catalogs" = "_ldap._tcp.gc._msdcs.$($domain.Name)"
    "Password Change" = "_kpasswd._tcp.$($domain.Name)"
    "PDC Emulator" = "_ldap._tcp.pdc._msdcs.$($domain.Name)"
}

$powerViewDnsResults = @{}
foreach($service in $dnsServices.Keys) {
    $srvRecord = $dnsServices[$service]
    Write-Host "`nDiscovering $service via PowerView..." -ForegroundColor Cyan
    
    try {
        $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
        $powerViewDnsResults[$service] = $records
        
        foreach($record in $records) {
            Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
            Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
            
            # Additional PowerView analysis
            $computer = Get-DomainComputer -Identity $record.NameTarget -Properties name,ipaddress,operatingsystem,site
            if($computer) {
                Write-Host "    Computer: $($computer.name) - $($computer.ipaddress) - $($computer.operatingsystem)" -ForegroundColor Yellow
                Write-Host "    Site: $($computer.site)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  ✗ No $service records found" -ForegroundColor Red
        $powerViewDnsResults[$service] = @()
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}

# Cross-reference DNS services with AD computers
$allComputers = Get-DomainComputer -Properties name,ipaddress,operatingsystem,site,serviceprincipalname
$dnsComputerMapping = @{}

foreach($service in $powerViewDnsResults.Keys) {
    $records = $powerViewDnsResults[$service]
    $dnsComputerMapping[$service] = @()
    
    foreach($record in $records) {
        $computer = $allComputers | Where-Object { $_.name -eq $record.NameTarget }
        if($computer) {
            $dnsComputerMapping[$service] += @{
                DNSRecord = $record
                Computer = $computer
                Services = $computer.serviceprincipalname
            }
        }
    }
}

# Generate comprehensive DNS-AD mapping report
Write-Host "`n=== DNS-AD COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
foreach($service in $dnsComputerMapping.Keys) {
    $mappings = $dnsComputerMapping[$service]
    Write-Host "`n$service Mappings:" -ForegroundColor Cyan
    
    if($mappings.Count -gt 0) {
        foreach($mapping in $mappings) {
            $dns = $mapping.DNSRecord
            $computer = $mapping.Computer
            Write-Host "  DNS: $($dns.NameTarget):$($dns.Port)" -ForegroundColor Green
            Write-Host "    Computer: $($computer.name) - $($computer.ipaddress)" -ForegroundColor White
            Write-Host "    OS: $($computer.operatingsystem)" -ForegroundColor White
            Write-Host "    Site: $($computer.site)" -ForegroundColor White
            
            if($mapping.Services) {
                Write-Host "    SPNs:" -ForegroundColor Yellow
                $mapping.Services | ForEach-Object {
                    Write-Host "      $_" -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host "  No computer mappings found" -ForegroundColor Red
    }
}
```

#### **Tool 3: Microsoft AD Module (Stealth DNS Discovery)**
```powershell
# Load the module
Import-Module ActiveDirectory

# DNS discovery via AD domain information
$domain = Get-ADDomain
Write-Host "Domain: $($domain.Name)" -ForegroundColor Cyan
Write-Host "Domain SID: $($domain.DomainSID)" -ForegroundColor Cyan

# DNS-based service discovery via AD
$adDnsServices = @{
    "Domain Controllers" = "_ldap._tcp.dc._msdcs.$($domain.Name)"
    "Kerberos KDCs" = "_kerberos._tcp.$($domain.Name)"
    "Global Catalogs" = "_ldap._tcp.gc._msdcs.$($domain.Name)"
    "Password Change" = "_kpasswd._tcp.$($domain.Name)"
    "PDC Emulator" = "_ldap._tcp.pdc._msdcs.$($domain.Name)"
}

$adDnsResults = @{}
foreach($service in $adDnsServices.Keys) {
    $srvRecord = $adDnsServices[$service]
    Write-Host "`nDiscovering $service via Microsoft AD Module..." -ForegroundColor Cyan
    
    try {
        $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
        $adDnsResults[$service] = $records
        
        foreach($record in $records) {
            Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
            Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
            
            # Additional AD analysis
            $computer = Get-ADComputer -Identity $record.NameTarget -Properties Name, IPv4Address, OperatingSystem, Site, ServicePrincipalName
            if($computer) {
                Write-Host "    Computer: $($computer.Name) - $($computer.IPv4Address) - $($computer.OperatingSystem)" -ForegroundColor Yellow
                Write-Host "    Site: $($computer.Site)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  ✗ No $service records found" -ForegroundColor Red
        $adDnsResults[$service] = @()
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}

# Cross-reference DNS services with AD computers via Microsoft module
$allAdComputers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site, ServicePrincipalName
$adDnsComputerMapping = @{}

foreach($service in $adDnsResults.Keys) {
    $records = $adDnsResults[$service]
    $adDnsComputerMapping[$service] = @()
    
    foreach($record in $records) {
        $computer = $allAdComputers | Where-Object { $_.Name -eq $record.NameTarget }
        if($computer) {
            $adDnsComputerMapping[$service] += @{
                DNSRecord = $record
                Computer = $computer
                Services = $computer.ServicePrincipalName
            }
        }
    }
}

# Generate comprehensive AD DNS mapping report
Write-Host "`n=== AD DNS COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
foreach($service in $adDnsComputerMapping.Keys) {
    $mappings = $adDnsComputerMapping[$service]
    Write-Host "`n$service Mappings:" -ForegroundColor Cyan
    
    if($mappings.Count -gt 0) {
        foreach($mapping in $mappings) {
            $dns = $mapping.DNSRecord
            $computer = $mapping.Computer
            Write-Host "  DNS: $($dns.NameTarget):$($dns.Port)" -ForegroundColor Green
            Write-Host "    Computer: $($computer.Name) - $($computer.IPv4Address)" -ForegroundColor White
            Write-Host "    OS: $($computer.OperatingSystem)" -ForegroundColor White
            Write-Host "    Site: $($computer.Site)" -ForegroundColor White
            
            if($mapping.Services) {
                Write-Host "    SPNs:" -ForegroundColor Yellow
                $mapping.Services | ForEach-Object {
                    Write-Host "      $_" -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host "  No computer mappings found" -ForegroundColor Red
    }
}
```

#### **DNS Service Discovery Error Handling**
```powershell
# Handle DNS discovery errors gracefully
function Test-DNSConnectivity {
    param(
        [string]$Domain = "corp.local",
        [int]$Timeout = 5
    )
    
    $results = @{
        Domain = $Domain
        Services = @{}
        Errors = @()
        SuccessRate = 0
    }
    
    $services = @{
        "Domain Controllers" = "_ldap._tcp.dc._msdcs.$Domain"
        "Kerberos KDCs" = "_kerberos._tcp.$Domain"
        "Global Catalogs" = "_ldap._tcp.gc._msdcs.$Domain"
    }
    
    $totalServices = $services.Count
    $successfulServices = 0
    
    foreach($service in $services.Keys) {
        $srvRecord = $services[$service]
        
        try {
            $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop -Timeout $Timeout
            $results.Services[$service] = $records
            $successfulServices++
            Write-Host "✓ $service discovery successful" -ForegroundColor Green
        } catch {
            $errorMsg = "Failed to discover $service`: $($_.Exception.Message)"
            $results.Errors += $errorMsg
            Write-Host "✗ $service discovery failed" -ForegroundColor Red
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    $results.SuccessRate = [math]::Round(($successfulServices / $totalServices) * 100, 1)
    return $results
}

# Use the function
$dnsConnectivityResults = Test-DNSConnectivity -Domain "corp.local"

Write-Host "`nDNS connectivity test results:" -ForegroundColor Cyan
Write-Host "  Domain: $($dnsConnectivityResults.Domain)" -ForegroundColor White
Write-Host "  Successful services: $($dnsConnectivityResults.Services.Count)" -ForegroundColor Green
Write-Host "  Errors: $($dnsConnectivityResults.Errors.Count)" -ForegroundColor Red
Write-Host "  Success rate: $($dnsConnectivityResults.SuccessRate)%" -ForegroundColor Yellow
```

---

## 🗺️ **NETWORK TOPOLOGY MAPPING**

### **🌍 Network Structure Visualization**

#### **What is Network Topology Mapping?**
**Network Topology Mapping** creates a visual representation of the network structure, showing relationships between hosts, subnets, and services.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
```powershell
# Network topology discovery function
function Discover-NetworkTopology {
    param(
        [string[]]$Subnets = @("192.168.1", "10.10.0", "172.16.20"),
        [int[]]$Ports = @(88, 389, 445, 5985)
    )
    
    $topology = @{
        Subnets = @{}
        Services = @{}
        Summary = @{}
    }
    
    foreach($subnet in $Subnets) {
        Write-Host "`nMapping subnet $subnet.0/24..." -ForegroundColor Cyan
        
        $subnetInfo = @{
            Network = $subnet
            AliveHosts = @()
            Services = @{}
        }
        
        # Discover alive hosts
        for($i = 1; $i -le 254; $i++) {
            $ip = "$subnet.$i"
            if(Test-Connection -ComputerName $ip -Quiet -Count 1) {
                $subnetInfo.AliveHosts += $ip
                
                # Discover services on alive hosts
                $subnetInfo.Services[$ip] = @{}
                foreach($port in $Ports) {
                    $result = Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                    $subnetInfo.Services[$ip][$port] = $result.TcpTestSucceeded
                }
                
                Write-Host "  ✓ $ip" -ForegroundColor Green
            }
            
            # Stealth delay
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
        }
        
        $topology.Subnets[$subnet] = $subnetInfo
        
        # Subnet summary
        $topology.Summary[$subnet] = @{
            TotalHosts = 254
            AliveHosts = $subnetInfo.AliveHosts.Count
            SuccessRate = [math]::Round(($subnetInfo.AliveHosts.Count / 254) * 100, 1)
        }
    }
    
    return $topology
}

# Use the function
$networkTopology = Discover-NetworkTopology

# Generate topology report
Write-Host "`n=== NETWORK TOPOLOGY REPORT ===" -ForegroundColor Magenta
foreach($subnet in $networkTopology.Subnets.Keys) {
    $info = $networkTopology.Subnets[$subnet]
    $summary = $networkTopology.Summary[$subnet]
    
    Write-Host "`nSubnet: $($info.Network).0/24" -ForegroundColor Cyan
    Write-Host "  Alive hosts: $($summary.AliveHosts)/$($summary.TotalHosts) ($($summary.SuccessRate)%)" -ForegroundColor White
    
    foreach($host in $info.AliveHosts) {
        $services = $info.Services[$host]
        $openPorts = ($services.Values | Where-Object {$_ -eq $true}).Count
        Write-Host "    $host - $openPorts services open" -ForegroundColor Green
    }
}
```

#### **Tool 2: PowerView Suite (Comprehensive Topology Discovery)**
```powershell
# Load PowerView
. .\PowerView.ps1

# Network topology discovery via AD
function Discover-ADNetworkTopology {
    param(
        [string]$Domain = "corp.local"
    )
    
    $topology = @{
        Sites = @{}
        Subnets = @{}
        Computers = @{}
        Services = @{}
        Summary = @{}
    }
    
    # Discover AD sites
    Write-Host "Discovering AD sites..." -ForegroundColor Cyan
    $sites = Get-DomainSite
    foreach($site in $sites) {
        $topology.Sites[$site.Name] = @{
            Name = $site.Name
            Description = $site.Description
            Subnets = @()
            Computers = @()
        }
    }
    
    # Discover AD subnets
    Write-Host "Discovering AD subnets..." -ForegroundColor Cyan
    $subnets = Get-DomainSubnet
    foreach($subnet in $subnets) {
        $topology.Subnets[$subnet.Name] = @{
            Name = $subnet.Name
            Site = $subnet.Site
            Location = $subnet.Location
            Computers = @()
        }
        
        # Add subnet to site
        if($topology.Sites.ContainsKey($subnet.Site)) {
            $topology.Sites[$subnet.Site].Subnets += $subnet.Name
        }
    }
    
    # Discover AD computers
    Write-Host "Discovering AD computers..." -ForegroundColor Cyan
    $computers = Get-DomainComputer -Properties name,ipaddress,operatingsystem,site,serviceprincipalname
    foreach($computer in $computers) {
        if($computer.ipaddress) {
            $topology.Computers[$computer.name] = @{
                Name = $computer.name
                IPAddress = $computer.ipaddress
                OperatingSystem = $computer.operatingsystem
                Site = $computer.site
                SPNs = $computer.serviceprincipalname
                Subnet = $null
            }
            
            # Determine subnet for computer
            foreach($subnet in $topology.Subnets.Keys) {
                if($computer.ipaddress -like "$subnet*") {
                    $topology.Computers[$computer.name].Subnet = $subnet
                    $topology.Subnets[$subnet].Computers += $computer.name
                    break
                }
            }
            
            # Add computer to site
            if($computer.site -and $topology.Sites.ContainsKey($computer.site)) {
                $topology.Sites[$computer.site].Computers += $computer.name
            }
        }
    }
    
    # Discover services
    Write-Host "Discovering network services..." -ForegroundColor Cyan
    $topology.Services = @{
        "Domain Controllers" = @()
        "Global Catalogs" = @()
        "SQL Servers" = @()
        "Web Servers" = @()
        "File Servers" = @()
    }
    
    foreach($computer in $topology.Computers.Values) {
        # Test common ports
        $ports = @{88 = "Kerberos"; 389 = "LDAP"; 445 = "SMB"; 1433 = "SQL"; 80 = "HTTP"; 443 = "HTTPS"}
        $computerServices = @()
        
        foreach($port in $ports.Keys) {
            try {
                $result = Test-NetConnection -ComputerName $computer.IPAddress -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                if($result.TcpTestSucceeded) {
                    $computerServices += $ports[$port]
                }
            } catch {
                # Port test failed
            }
        }
        
        $topology.Computers[$computer.Name].Services = $computerServices
        
        # Categorize by service type
        if($computer.SPNs) {
            foreach($spn in $computer.SPNs) {
                if($spn -like "*SQL*") {
                    $topology.Services["SQL Servers"] += $computer.Name
                } elseif($spn -like "*HTTP*" -or $spn -like "*WWW*") {
                    $topology.Services["Web Servers"] += $computer.Name
                } elseif($spn -like "*CIFS*" -or $spn -like "*SMB*") {
                    $topology.Services["File Servers"] += $computer.Name
                }
            }
        }
    }
    
    # Generate summary
    $topology.Summary = @{
        TotalSites = $topology.Sites.Count
        TotalSubnets = $topology.Subnets.Count
        TotalComputers = $topology.Computers.Count
        TotalServices = ($topology.Services.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    }
    
    return $topology
}

# Use the function
$adTopology = Discover-ADNetworkTopology

# Generate comprehensive AD topology report
Write-Host "`n=== AD NETWORK TOPOLOGY REPORT ===" -ForegroundColor Magenta
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Sites: $($adTopology.Summary.TotalSites)" -ForegroundColor White
Write-Host "  Subnets: $($adTopology.Summary.TotalSubnets)" -ForegroundColor White
Write-Host "  Computers: $($adTopology.Summary.TotalComputers)" -ForegroundColor White
Write-Host "  Services: $($adTopology.Summary.TotalServices)" -ForegroundColor White

# Site details
Write-Host "`nSite Details:" -ForegroundColor Cyan
foreach($site in $adTopology.Sites.Keys) {
    $siteInfo = $adTopology.Sites[$site]
    Write-Host "`nSite: $($siteInfo.Name)" -ForegroundColor Yellow
    Write-Host "  Description: $($siteInfo.Description)" -ForegroundColor White
    Write-Host "  Subnets: $($siteInfo.Subnets.Count)" -ForegroundColor White
    Write-Host "  Computers: $($siteInfo.Computers.Count)" -ForegroundColor White
    
    foreach($subnet in $siteInfo.Subnets) {
        $subnetInfo = $adTopology.Subnets[$subnet]
        Write-Host "    Subnet: $($subnetInfo.Name) - $($subnetInfo.Location)" -ForegroundColor Gray
        Write-Host "      Computers: $($subnetInfo.Computers.Count)" -ForegroundColor Gray
    }
}

# Service details
Write-Host "`nService Details:" -ForegroundColor Cyan
foreach($service in $adTopology.Services.Keys) {
    $hosts = $adTopology.Services[$service]
    if($hosts.Count -gt 0) {
        Write-Host "`n$service:" -ForegroundColor Yellow
        foreach($host in $hosts) {
            Write-Host "  $host" -ForegroundColor White
        }
    }
}
```

#### **Tool 3: Microsoft AD Module (Stealth Topology Discovery)**
```powershell
# Load the module
Import-Module ActiveDirectory

# Network topology discovery via Microsoft AD Module
function Discover-MSADNetworkTopology {
    param(
        [string]$Domain = "corp.local"
    )
    
    $topology = @{
        Sites = @{}
        Subnets = @{}
        Computers = @{}
        Services = @{}
        Summary = @{}
    }
    
    # Discover AD sites
    Write-Host "Discovering AD sites via Microsoft AD Module..." -ForegroundColor Cyan
    $sites = Get-ADReplicationSite -Filter *
    foreach($site in $sites) {
        $topology.Sites[$site.Name] = @{
            Name = $site.Name
            Description = $site.Description
            Subnets = @()
            Computers = @()
        }
    }
    
    # Discover AD subnets
    Write-Host "Discovering AD subnets via Microsoft AD Module..." -ForegroundColor Cyan
    $subnets = Get-ADReplicationSubnet -Filter *
    foreach($subnet in $subnets) {
        $topology.Subnets[$subnet.Name] = @{
            Name = $subnet.Name
            Site = $subnet.Site
            Location = $subnet.Location
            Computers = @()
        }
        
        # Add subnet to site
        if($topology.Sites.ContainsKey($subnet.Site)) {
            $topology.Sites[$subnet.Site].Subnets += $subnet.Name
        }
    }
    
    # Discover AD computers
    Write-Host "Discovering AD computers via Microsoft AD Module..." -ForegroundColor Cyan
    $computers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site, ServicePrincipalName
    foreach($computer in $computers) {
        if($computer.IPv4Address) {
            $topology.Computers[$computer.Name] = @{
                Name = $computer.Name
                IPAddress = $computer.IPv4Address
                OperatingSystem = $computer.OperatingSystem
                Site = $computer.Site
                SPNs = $computer.ServicePrincipalName
                Subnet = $null
            }
            
            # Determine subnet for computer
            foreach($subnet in $topology.Subnets.Keys) {
                if($computer.IPv4Address -like "$subnet*") {
                    $topology.Computers[$computer.Name].Subnet = $subnet
                    $topology.Subnets[$subnet].Computers += $computer.Name
                    break
                }
            }
            
            # Add computer to site
            if($computer.Site -and $topology.Sites.ContainsKey($computer.Site)) {
                $topology.Sites[$computer.Site].Computers += $computer.Name
            }
        }
    }
    
    # Discover services via Microsoft AD Module
    Write-Host "Discovering network services via Microsoft AD Module..." -ForegroundColor Cyan
    $topology.Services = @{
        "Domain Controllers" = @()
        "Global Catalogs" = @()
        "SQL Servers" = @()
        "Web Servers" = @()
        "File Servers" = @()
    }
    
    foreach($computer in $topology.Computers.Values) {
        # Test common ports
        $ports = @{88 = "Kerberos"; 389 = "LDAP"; 445 = "SMB"; 1433 = "SQL"; 80 = "HTTP"; 443 = "HTTPS"}
        $computerServices = @()
        
        foreach($port in $ports.Keys) {
            try {
                $result = Test-NetConnection -ComputerName $computer.IPAddress -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                if($result.TcpTestSucceeded) {
                    $computerServices += $ports[$port]
                }
            } catch {
                # Port test failed
            }
        }
        
        $topology.Computers[$computer.Name].Services = $computerServices
        
        # Categorize by service type
        if($computer.SPNs) {
            foreach($spn in $computer.SPNs) {
                if($spn -like "*SQL*") {
                    $topology.Services["SQL Servers"] += $computer.Name
                } elseif($spn -like "*HTTP*" -or $spn -like "*WWW*") {
                    $topology.Services["Web Servers"] += $computer.Name
                } elseif($spn -like "*CIFS*" -or $spn -like "*SMB*") {
                    $topology.Services["File Servers"] += $computer.Name
                }
            }
        }
    }
    
    # Generate summary
    $topology.Summary = @{
        TotalSites = $topology.Sites.Count
        TotalSubnets = $topology.Subnets.Count
        TotalComputers = $topology.Computers.Count
        TotalServices = ($topology.Services.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    }
    
    return $topology
}

# Use the function
$msadTopology = Discover-MSADNetworkTopology

# Generate comprehensive Microsoft AD topology report
Write-Host "`n=== MICROSOFT AD NETWORK TOPOLOGY REPORT ===" -ForegroundColor Magenta
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Sites: $($msadTopology.Summary.TotalSites)" -ForegroundColor White
Write-Host "  Subnets: $($msadTopology.Summary.TotalSubnets)" -ForegroundColor White
Write-Host "  Computers: $($msadTopology.Summary.TotalComputers)" -ForegroundColor White
Write-Host "  Services: $($msadTopology.Summary.TotalServices)" -ForegroundColor White

# Site details
Write-Host "`nSite Details:" -ForegroundColor Cyan
foreach($site in $msadTopology.Sites.Keys) {
    $siteInfo = $msadTopology.Sites[$site]
    Write-Host "`nSite: $($siteInfo.Name)" -ForegroundColor Yellow
    Write-Host "  Description: $($siteInfo.Description)" -ForegroundColor White
    Write-Host "  Subnets: $($siteInfo.Subnets.Count)" -ForegroundColor White
    Write-Host "  Computers: $($siteInfo.Computers.Count)" -ForegroundColor White
    
    foreach($subnet in $siteInfo.Subnets) {
        $subnetInfo = $msadTopology.Subnets[$subnet]
        Write-Host "    Subnet: $($subnetInfo.Name) - $($subnetInfo.Location)" -ForegroundColor Gray
        Write-Host "      Computers: $($subnetInfo.Computers.Count)" -ForegroundColor Gray
    }
}

# Service details
Write-Host "`nService Details:" -ForegroundColor Cyan
foreach($service in $msadTopology.Services.Keys) {
    $hosts = $msadTopology.Services[$service]
    if($hosts.Count -gt 0) {
        Write-Host "`n$service:" -ForegroundColor Yellow
        foreach($host in $hosts) {
            Write-Host "  $host" -ForegroundColor White
        }
    }
}
```

---

## 🔄 **FINDINGS → PIVOTS (NETWORK DISCOVERY FLOW)**

### **🎯 Strategic Pivot Planning**

#### **What are Network Pivots?**
**Network Pivots** are strategic next steps based on network discovery findings. Each open port or service leads to specific enumeration techniques.

#### **Tool 1: Native Windows Commands (Stealth Pivot Planning)**
```powershell
# Define pivot matrix
$pivotMatrix = @{
    88 = @{
        Service = "Kerberos"
        PivotTo = "23_Kerberos_Basic_Enumeration.md"
        Technique = "Kerberos enumeration and attacks"
        Commands = @("Get-DomainUser -SPN", "Invoke-Kerberoast")
    }
    389 = @{
        Service = "LDAP"
        PivotTo = "04_Domain_Enumeration.md"
        Technique = "Domain object enumeration"
        Commands = @("Get-Domain", "Get-DomainUser")
    }
    445 = @{
        Service = "SMB"
        PivotTo = "17_File_Share_Enumeration.md"
        Technique = "File share enumeration"
        Commands = @("Get-SmbShare", "Get-SmbSession")
    }
    5985 = @{
        Service = "WinRM"
        PivotTo = "19_PowerShell_Remoting_Enumeration.md"
        Technique = "PowerShell remoting"
        Commands = @("Test-WSMan", "Enter-PSSession")
    }
    3389 = @{
        Service = "RDP"
        PivotTo = "14_RDP_Session_Enumeration.md"
        Technique = "RDP session enumeration"
        Commands = @("quser", "qwinsta")
    }
}

# Generate pivot recommendations
function Get-PivotRecommendations {
    param(
        [hashtable]$ServiceResults
    )
    
    Write-Host "`n=== PIVOT RECOMMENDATIONS ===" -ForegroundColor Magenta
    
    foreach($host in $ServiceResults.Keys) {
        Write-Host "`nHost: $host" -ForegroundColor Cyan
        
        foreach($port in $ServiceResults[$host].Keys) {
            if($ServiceResults[$host][$port] -and $pivotMatrix.ContainsKey($port)) {
                $pivot = $pivotMatrix[$port]
                Write-Host "  Port $port ($($pivot.Service)):" -ForegroundColor Green
                Write-Host "    → Pivot to: $($pivot.PivotTo)" -ForegroundColor Yellow
                Write-Host "    → Technique: $($pivot.Technique)" -ForegroundColor White
                Write-Host "    → Commands: $($pivot.Commands -join ', ')" -ForegroundColor Gray
            }
        }
    }
}

# Example usage
$exampleResults = @{
    "dc01.corp.local" = @{88 = $true; 389 = $true; 445 = $false; 5985 = $true}
    "192.168.1.10" = @{88 = $false; 389 = $false; 445 = $true; 5985 = $false}
}

Get-PivotRecommendations -ServiceResults $exampleResults
```

#### **Tool 2: PowerView Suite (Comprehensive Pivot Planning)**
```powershell
# Load PowerView
. .\PowerView.ps1

# Advanced pivot planning via AD analysis
function Get-ADBasedPivotRecommendations {
    param(
        [string]$Domain = "corp.local"
    )
    
    $pivotRecommendations = @{
        "High-Value Targets" = @()
        "Service Accounts" = @()
        "Delegation Targets" = @()
        "Trust Relationships" = @()
        "GPO Targets" = @()
    }
    
    # Discover high-value targets
    Write-Host "Analyzing high-value targets for pivots..." -ForegroundColor Cyan
    $adminUsers = Get-DomainUser -Properties admincount,memberof | Where-Object { $_.admincount -eq 1 }
    foreach($user in $adminUsers) {
        $pivotRecommendations["High-Value Targets"] += @{
            Type = "Admin User"
            Name = $user.samaccountname
            PivotTo = "05_User_Enumeration.md"
            Technique = "User privilege analysis"
            Commands = @("Get-DomainUser -Identity '$($user.samaccountname)' -Properties *", "Get-DomainGroupMember -Identity 'Domain Admins'")
        }
    }
    
    # Discover service accounts
    Write-Host "Analyzing service accounts for pivots..." -ForegroundColor Cyan
    $spnUsers = Get-DomainUser -SPN -Properties serviceprincipalname
    foreach($user in $spnUsers) {
        $pivotRecommendations["Service Accounts"] += @{
            Type = "Service Account"
            Name = $user.samaccountname
            PivotTo = "24_SPN_Enumeration_Techniques.md"
            Technique = "Kerberoasting and service exploitation"
            Commands = @("Get-DomainUser -Identity '$($user.samaccountname)' -Properties *", "Invoke-Kerberoast -UserIdentity '$($user.samaccountname)'")
        }
    }
    
    # Discover delegation targets
    Write-Host "Analyzing delegation targets for pivots..." -ForegroundColor Cyan
    $unconstrainedComputers = Get-DomainComputer -Unconstrained -Properties name,ipaddress
    foreach($computer in $unconstrainedComputers) {
        $pivotRecommendations["Delegation Targets"] += @{
            Type = "Unconstrained Delegation"
            Name = $computer.name
            IPAddress = $computer.ipaddress
            PivotTo = "25_Kerberos_Delegation_Abuse.md"
            Technique = "Delegation abuse and ticket harvesting"
            Commands = @("Get-DomainComputer -Identity '$($computer.name)' -Properties *", "Invoke-Mimikatz -Command 'sekurlsa::tickets /export'")
        }
    }
    
    # Discover trust relationships
    Write-Host "Analyzing trust relationships for pivots..." -ForegroundColor Cyan
    $trusts = Get-DomainTrust -Properties trustdirection,trusttype
    foreach($trust in $trusts) {
        $pivotRecommendations["Trust Relationships"] += @{
            Type = "Domain Trust"
            Name = $trust.Name
            Direction = $trust.trustdirection
            PivotTo = "30_Forest_Enumeration.md"
            Technique = "Cross-domain enumeration and trust abuse"
            Commands = @("Get-DomainTrust -Identity '$($trust.Name)' -Properties *", "Get-DomainUser -Domain '$($trust.Name)'")
        }
    }
    
    # Discover GPO targets
    Write-Host "Analyzing GPO targets for pivots..." -ForegroundColor Cyan
    $gpos = Get-DomainGPO -Properties displayname,id,owner
    foreach($gpo in $gpos) {
        $pivotRecommendations["GPO Targets"] += @{
            Type = "Group Policy Object"
            Name = $gpo.displayname
            ID = $gpo.id
            PivotTo = "08_GPO_Enumeration.md"
            Technique = "GPO analysis and abuse"
            Commands = @("Get-DomainGPO -Identity '$($gpo.id)' -Properties *", "Get-DomainGPOLocalGroup -GPOIdentity '$($gpo.id)'")
        }
    }
    
    return $pivotRecommendations
}

# Use the function
$adPivotRecommendations = Get-ADBasedPivotRecommendations

# Generate comprehensive AD-based pivot report
Write-Host "`n=== AD-BASED PIVOT RECOMMENDATIONS ===" -ForegroundColor Magenta
foreach($category in $adPivotRecommendations.Keys) {
    $recommendations = $adPivotRecommendations[$category]
    if($recommendations.Count -gt 0) {
        Write-Host "`n$category:" -ForegroundColor Cyan
        foreach($rec in $recommendations) {
            Write-Host "  $($rec.Type): $($rec.Name)" -ForegroundColor Yellow
            Write-Host "    → Pivot to: $($rec.PivotTo)" -ForegroundColor White
            Write-Host "    → Technique: $($rec.Technique)" -ForegroundColor Gray
            Write-Host "    → Commands: $($rec.Commands -join ', ')" -ForegroundColor DarkGray
        }
    }
}
```

#### **Tool 3: Microsoft AD Module (Stealth Pivot Planning)**
```powershell
# Load the module
Import-Module ActiveDirectory

# Stealth pivot planning via Microsoft AD Module
function Get-MSADBasedPivotRecommendations {
    param(
        [string]$Domain = "corp.local"
    )
    
    $pivotRecommendations = @{
        "High-Value Targets" = @()
        "Service Accounts" = @()
        "Delegation Targets" = @()
        "Trust Relationships" = @()
        "GPO Targets" = @()
    }
    
    # Discover high-value targets via Microsoft AD Module
    Write-Host "Analyzing high-value targets via Microsoft AD Module..." -ForegroundColor Cyan
    $adminUsers = Get-ADUser -Filter "adminCount -eq 1" -Properties admincount,memberof
    foreach($user in $adminUsers) {
        $pivotRecommendations["High-Value Targets"] += @{
            Type = "Admin User"
            Name = $user.SamAccountName
            PivotTo = "05_User_Enumeration.md"
            Technique = "User privilege analysis"
            Commands = @("Get-ADUser -Identity '$($user.SamAccountName)' -Properties *", "Get-ADGroupMember -Identity 'Domain Admins'")
        }
    }
    
    # Discover service accounts via Microsoft AD Module
    Write-Host "Analyzing service accounts via Microsoft AD Module..." -ForegroundColor Cyan
    $spnUsers = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName
    foreach($user in $spnUsers) {
        $pivotRecommendations["Service Accounts"] += @{
            Type = "Service Account"
            Name = $user.SamAccountName
            PivotTo = "24_SPN_Enumeration_Techniques.md"
            Technique = "Kerberoasting and service exploitation"
            Commands = @("Get-ADUser -Identity '$($user.SamAccountName)' -Properties *", "Get-ADUser -Filter 'ServicePrincipalName -like \"*\"'")
        }
    }
    
    # Discover delegation targets via Microsoft AD Module
    Write-Host "Analyzing delegation targets via Microsoft AD Module..." -ForegroundColor Cyan
    $unconstrainedComputers = Get-ADComputer -Filter "TrustedForDelegation -eq $true" -Properties Name, IPv4Address, TrustedForDelegation
    foreach($computer in $unconstrainedComputers) {
        $pivotRecommendations["Delegation Targets"] += @{
            Type = "Unconstrained Delegation"
            Name = $computer.Name
            IPAddress = $computer.IPv4Address
            PivotTo = "25_Kerberos_Delegation_Abuse.md"
            Technique = "Delegation abuse and ticket harvesting"
            Commands = @("Get-ADComputer -Identity '$($computer.Name)' -Properties *", "Get-ADComputer -Filter 'TrustedForDelegation -eq $true'")
        }
    }
    
    # Discover trust relationships via Microsoft AD Module
    Write-Host "Analyzing trust relationships via Microsoft AD Module..." -ForegroundColor Cyan
    $trusts = Get-ADTrust -Filter * -Properties TrustDirection, TrustType
    foreach($trust in $trusts) {
        $pivotRecommendations["Trust Relationships"] += @{
            Type = "Domain Trust"
            Name = $trust.Name
            Direction = $trust.TrustDirection
            PivotTo = "30_Forest_Enumeration.md"
            Technique = "Cross-domain enumeration and trust abuse"
            Commands = @("Get-ADTrust -Identity '$($trust.Name)' -Properties *", "Get-ADUser -Filter * -SearchBase $($trust.DistinguishedName)")
        }
    }
    
    # Discover GPO targets via Microsoft AD Module
    Write-Host "Analyzing GPO targets via Microsoft AD Module..." -ForegroundColor Cyan
    $gpos = Get-GPO -All -Properties DisplayName, ID, Owner
    foreach($gpo in $gpos) {
        $pivotRecommendations["GPO Targets"] += @{
            Type = "Group Policy Object"
            Name = $gpo.DisplayName
            ID = $gpo.ID
            PivotTo = "08_GPO_Enumeration.md"
            Technique = "GPO analysis and abuse"
            Commands = @("Get-GPO -Identity '$($gpo.ID)' -Properties *", "Get-GPOReport -Identity '$($gpo.ID)' -ReportType XML")
        }
    }
    
    return $pivotRecommendations
}

# Use the function
$msadPivotRecommendations = Get-MSADBasedPivotRecommendations

# Generate comprehensive Microsoft AD-based pivot report
Write-Host "`n=== MICROSOFT AD-BASED PIVOT RECOMMENDATIONS ===" -ForegroundColor Magenta
foreach($category in $msadPivotRecommendations.Keys) {
    $recommendations = $msadPivotRecommendations[$category]
    if($recommendations.Count -gt 0) {
        Write-Host "`n$category:" -ForegroundColor Cyan
        foreach($rec in $recommendations) {
            Write-Host "  $($rec.Type): $($rec.Name)" -ForegroundColor Yellow
            Write-Host "    → Pivot to: $($rec.PivotTo)" -ForegroundColor White
            Write-Host "    → Technique: $($rec.Technique)" -ForegroundColor Gray
            Write-Host "    → Commands: $($rec.Commands -join ', ')" -ForegroundColor DarkGray
        }
    }
}
```

#### **Advanced Pivot Integration**
```powershell
# Cross-tool pivot analysis
function Get-CrossToolPivotAnalysis {
    param(
        [hashtable]$NativeResults,
        [hashtable]$PowerViewResults,
        [hashtable]$MSADResults
    )
    
    $crossToolAnalysis = @{
        "Common Targets" = @()
        "Unique PowerView Findings" = @()
        "Unique MSAD Findings" = @()
        "Recommended Next Steps" = @()
    }
    
    # Analyze common targets across tools
    Write-Host "Analyzing common targets across tools..." -ForegroundColor Cyan
    
    # Find common high-value targets
    $nativeAdmins = $NativeResults["High-Value Targets"] | ForEach-Object { $_.Name }
    $powerviewAdmins = $PowerViewResults["High-Value Targets"] | ForEach-Object { $_.Name }
    $msadAdmins = $MSADResults["High-Value Targets"] | ForEach-Object { $_.Name }
    
    $commonAdmins = $nativeAdmins | Where-Object { $_ -in $powerviewAdmins -and $_ -in $msadAdmins }
    foreach($admin in $commonAdmins) {
        $crossToolAnalysis["Common Targets"] += @{
            Type = "High-Value Admin"
            Name = $admin
            Confidence = "High (confirmed by all tools)"
            Priority = "Critical"
            PivotTo = "05_User_Enumeration.md"
        }
    }
    
    # Find unique PowerView findings
    $uniquePowerView = $PowerViewResults.Values | ForEach-Object { $_ } | Where-Object { 
        $_.Name -notin ($NativeResults.Values | ForEach-Object { $_.Name })
    }
    foreach($finding in $uniquePowerView) {
        $crossToolAnalysis["Unique PowerView Findings"] += @{
            Type = $finding.Type
            Name = $finding.Name
            Tool = "PowerView"
            PivotTo = $finding.PivotTo
        }
    }
    
    # Find unique MSAD findings
    $uniqueMSAD = $MSADResults.Values | ForEach-Object { $_ } | Where-Object { 
        $_.Name -notin ($NativeResults.Values | ForEach-Object { $_.Name })
    }
    foreach($finding in $uniqueMSAD) {
        $crossToolAnalysis["Unique MSAD Findings"] += @{
            Type = $finding.Type
            Name = $finding.Name
            Tool = "Microsoft AD Module"
            PivotTo = $finding.PivotTo
        }
    }
    
    # Generate recommended next steps
    $crossToolAnalysis["Recommended Next Steps"] = @(
        @{
            Priority = "Immediate"
            Action = "Target common high-value accounts"
            Technique = "User enumeration and privilege analysis"
            Tools = @("PowerView", "Microsoft AD Module")
        },
        @{
            Priority = "High"
            Action = "Investigate unique PowerView findings"
            Technique = "Offensive enumeration and attack path mapping"
            Tools = @("PowerView", "BloodHound")
        },
        @{
            Priority = "Medium"
            Action = "Validate unique MSAD findings"
            Technique = "Compliance-focused enumeration"
            Tools = @("Microsoft AD Module", "Native Windows")
        }
    )
    
    return $crossToolAnalysis
}

# Use the cross-tool analysis
$crossToolAnalysis = Get-CrossToolPivotAnalysis -NativeResults $exampleResults -PowerViewResults $adPivotRecommendations -MSADResults $msadPivotRecommendations

# Generate cross-tool pivot analysis report
Write-Host "`n=== CROSS-TOOL PIVOT ANALYSIS ===" -ForegroundColor Magenta
foreach($category in $crossToolAnalysis.Keys) {
    $items = $crossToolAnalysis[$category]
    if($items.Count -gt 0) {
        Write-Host "`n$category:" -ForegroundColor Cyan
        foreach($item in $items) {
            if($item.Priority) {
                Write-Host "  [$($item.Priority)] $($item.Action)" -ForegroundColor Yellow
                Write-Host "    Technique: $($item.Technique)" -ForegroundColor White
                Write-Host "    Tools: $($item.Tools -join ', ')" -ForegroundColor Gray
            } else {
                Write-Host "  $($item.Type): $($item.Name)" -ForegroundColor Yellow
                if($item.Confidence) {
                    Write-Host "    Confidence: $($item.Confidence)" -ForegroundColor White
                }
                if($item.PivotTo) {
                    Write-Host "    Pivot to: $($item.PivotTo)" -ForegroundColor White
                }
            }
        }
    }
}
```

---

## 🚨 **DETECTION & OPSEC**

### **👁️ Network Discovery Detection Vectors**
```powershell
# Event IDs to monitor for network discovery
$detectionEvents = @(
    "4624",  # Logon (successful authentication)
    "4625",  # Logon (failed authentication)
    "4688",  # Process creation
    "5140",  # Network share access
    "5145",  # Network share access (detailed)
    "5156",  # Filtering platform connection
    "5157",  # Filtering platform bind
    "5158"   # Filtering platform connection dropped
)

Write-Host "Monitor these Event IDs for network discovery detection:" -ForegroundColor Red
$detectionEvents | ForEach-Object { Write-Host "  Event ID: $_" -ForegroundColor White }
```

### **🕵️ OPSEC Best Practices for Network Discovery**

> **OPSEC Reminder**: Use low-noise queries and signed tooling in production. Apply stealth controls only when authorized.

#### **Tool 1: Native Windows Commands (Maximum Stealth)**
```powershell
# OPSEC Profile 1: Stealth (Production)
$stealthProfile = @{
    UseNativeTools = $true
    UseInvisiShell = $true
    DelayRange = @(5, 10)
    JitterPattern = "Random"
    MaxConcurrentScans = 1
    PortSelection = "Critical AD ports only"
    SubnetScope = "Targeted subnets only"
    ToolPreference = "Native Windows Commands"
}

# Stealth network discovery techniques
function Invoke-StealthNetworkDiscovery {
    param(
        [string[]]$Targets = @("dc01.corp.local", "dc02.corp.local"),
        [int[]]$Ports = @(88, 389, 445, 5985)
    )
    
    Write-Host "Executing stealth network discovery..." -ForegroundColor Cyan
    
    foreach($target in $Targets) {
        Write-Host "`nAnalyzing $target..." -ForegroundColor Yellow
        
        # Test connectivity first
        if(Test-Connection -ComputerName $target -Quiet -Count 1) {
            Write-Host "  ✓ Host is alive" -ForegroundColor Green
            
            # Test critical ports with stealth delays
            foreach($port in $Ports) {
                try {
                    $result = Test-NetConnection -ComputerName $target -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                    if($result.TcpTestSucceeded) {
                        $service = switch($port) {
                            88 { "Kerberos" }
                            389 { "LDAP" }
                            445 { "SMB" }
                            5985 { "WinRM" }
                            default { "Unknown" }
                        }
                        Write-Host "    ✓ Port $port ($service) is OPEN" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "    ✗ Port $port test failed" -ForegroundColor Red
                }
                
                # Stealth delay between port tests
                Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
            }
        } else {
            Write-Host "  ✗ Host is not responding" -ForegroundColor Red
        }
        
        # Stealth delay between hosts
        Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 20)
    }
}

# Use stealth discovery
Invoke-StealthNetworkDiscovery
```

#### **Tool 2: PowerView Suite (Balanced Stealth)**
```powershell
# Load PowerView
. .\PowerView.ps1

# OPSEC Profile 2: Balanced (Lab)
$balancedProfile = @{
    UseNativeTools = $false
    UsePowerView = $true
    UseInvisiShell = $true
    DelayRange = @(3, 7)
    JitterPattern = "Random"
    MaxConcurrentScans = 3
    PortSelection = "Standard AD ports"
    SubnetScope = "Multiple subnets"
    ToolPreference = "PowerView + Native Windows"
}

# Balanced network discovery via PowerView
function Invoke-BalancedNetworkDiscovery {
    param(
        [string]$Domain = "corp.local"
    )
    
    Write-Host "Executing balanced network discovery via PowerView..." -ForegroundColor Cyan
    
    # Get domain computers via PowerView
    $computers = Get-DomainComputer -Properties name,ipaddress,operatingsystem,site | Select-Object -First 10
    
    foreach($computer in $computers) {
        if($computer.ipaddress) {
            Write-Host "`nAnalyzing $($computer.name) ($($computer.ipaddress))..." -ForegroundColor Yellow
            
            # Test critical ports
            $ports = @{88 = "Kerberos"; 389 = "LDAP"; 445 = "SMB"; 5985 = "WinRM"}
            foreach($port in $ports.Keys) {
                try {
                    $result = Test-NetConnection -ComputerName $computer.ipaddress -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                    if($result.TcpTestSucceeded) {
                        Write-Host "  ✓ Port $port ($($ports[$port])) is OPEN" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "  ✗ Port $port test failed" -ForegroundColor Red
                }
                
                # Balanced delay between port tests
                Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
            }
            
            # Get additional PowerView information
            $computerDetails = Get-DomainComputer -Identity $computer.name -Properties serviceprincipalname,trustedfordelegation
            if($computerDetails.serviceprincipalname) {
                Write-Host "  Service Principal Names:" -ForegroundColor Yellow
                $computerDetails.serviceprincipalname | ForEach-Object {
                    Write-Host "    $_" -ForegroundColor White
                }
            }
            
            if($computerDetails.trustedfordelegation) {
                Write-Host "  ⚠️ Unconstrained delegation enabled" -ForegroundColor Red
            }
        }
        
        # Balanced delay between computers
        Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
    }
}

# Use balanced discovery
Invoke-BalancedNetworkDiscovery
```

#### **Tool 3: Microsoft AD Module (Stealth Operations)**
```powershell
# Load the module
Import-Module ActiveDirectory

# OPSEC Profile 3: Stealth (Production)
$msadStealthProfile = @{
    UseMSADModule = $true
    UseInvisiShell = $true
    DelayRange = @(2, 5)
    JitterPattern = "Random"
    MaxConcurrentScans = 2
    PortSelection = "Essential AD ports only"
    SubnetScope = "Targeted subnets only"
    ToolPreference = "Microsoft AD Module + Native Windows"
}

# Stealth network discovery via Microsoft AD Module
function Invoke-MSADStealthDiscovery {
    param(
        [string]$Domain = "corp.local"
    )
    
    Write-Host "Executing stealth network discovery via Microsoft AD Module..." -ForegroundColor Cyan
    
    # Get domain computers via Microsoft AD Module
    $computers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site | Select-Object -First 5
    
    foreach($computer in $computers) {
        if($computer.IPv4Address) {
            Write-Host "`nAnalyzing $($computer.Name) ($($computer.IPv4Address))..." -ForegroundColor Yellow
            
            # Test essential ports only
            $essentialPorts = @{88 = "Kerberos"; 389 = "LDAP"; 445 = "SMB"}
            foreach($port in $essentialPorts.Keys) {
                try {
                    $result = Test-NetConnection -ComputerName $computer.IPv4Address -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
                    if($result.TcpTestSucceeded) {
                        Write-Host "  ✓ Port $port ($($essentialPorts[$port])) is OPEN" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "  ✗ Port $port test failed" -ForegroundColor Red
                }
                
                # Stealth delay between port tests
                Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)
            }
            
            # Get additional Microsoft AD Module information
            $computerDetails = Get-ADComputer -Identity $computer.Name -Properties ServicePrincipalName, TrustedForDelegation
            if($computerDetails.ServicePrincipalName) {
                Write-Host "  Service Principal Names:" -ForegroundColor Yellow
                $computerDetails.ServicePrincipalName | ForEach-Object {
                    Write-Host "    $_" -ForegroundColor White
                }
            }
            
            if($computerDetails.TrustedForDelegation) {
                Write-Host "  ⚠️ Unconstrained delegation enabled" -ForegroundColor Red
            }
        }
        
        # Stealth delay between computers
        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)
    }
}

# Use Microsoft AD Module stealth discovery
Invoke-MSADStealthDiscovery
```

#### **Advanced OPSEC Techniques**
```powershell
# Cross-tool OPSEC analysis
function Get-CrossToolOPSECAnalysis {
    param(
        [hashtable]$NativeProfile,
        [hashtable]$PowerViewProfile,
        [hashtable]$MSADProfile
    )
    
    $opsecAnalysis = @{
        "Detection Risk" = @{}
        "Stealth Recommendations" = @()
        "Tool Selection Strategy" = @()
        "Timing Optimization" = @()
    }
    
    # Analyze detection risk across tools
    $opsecAnalysis["Detection Risk"] = @{
        "Native Windows" = "Low (built-in tools, minimal logging)"
        "PowerView" = "Medium (offensive tool, may trigger alerts)"
        "Microsoft AD Module" = "Low (signed tool, expected behavior)"
    }
    
    # Generate stealth recommendations
    $opsecAnalysis["Stealth Recommendations"] = @(
        @{
            Priority = "Critical"
            Recommendation = "Always use Invisi-Shell in production"
            Rationale = "Bypasses AMSI and PowerShell logging"
            Implementation = "Load before any enumeration"
        },
        @{
            Priority = "High"
            Recommendation = "Use native Windows commands when possible"
            Rationale = "Minimal detection footprint"
            Implementation = "Prefer Test-Connection over custom scripts"
        },
        @{
            Priority = "Medium"
            Recommendation = "Implement random delays with jitter"
            Rationale = "Avoids pattern detection"
            Implementation = "Start-Sleep with Get-Random"
        }
    )
    
    # Generate tool selection strategy
    $opsecAnalysis["Tool Selection Strategy"] = @(
        @{
            Environment = "Production"
            PrimaryTool = "Microsoft AD Module"
            SecondaryTool = "Native Windows Commands"
            AvoidTool = "PowerView"
            Rationale = "Maximum stealth, minimal detection"
        },
        @{
            Environment = "Lab"
            PrimaryTool = "PowerView"
            SecondaryTool = "Microsoft AD Module"
            AvoidTool = "None"
            Rationale = "Comprehensive enumeration, detection acceptable"
        },
        @{
            Environment = "Assessment"
            PrimaryTool = "Balanced approach"
            SecondaryTool = "All tools"
            AvoidTool = "None"
            Rationale = "Flexible based on requirements"
        }
    )
    
    # Generate timing optimization
    $opsecAnalysis["Timing Optimization"] = @(
        @{
            Phase = "Initial Discovery"
            Delay = "5-10 seconds"
            Rationale = "Establish baseline without detection"
            Tool = "Native Windows + Microsoft AD Module"
        },
        @{
            Phase = "Detailed Enumeration"
            Delay = "3-7 seconds"
            Rationale = "Balanced speed and stealth"
            Tool = "PowerView + Microsoft AD Module"
        },
        @{
            Phase = "Final Analysis"
            Delay = "2-5 seconds"
            Rationale = "Complete enumeration efficiently"
            Tool = "All tools"
        }
    )
    
    return $opsecAnalysis
}

# Use cross-tool OPSEC analysis
$opsecAnalysis = Get-CrossToolOPSECAnalysis -NativeProfile $stealthProfile -PowerViewProfile $balancedProfile -MSADProfile $msadStealthProfile

# Generate comprehensive OPSEC analysis report
Write-Host "`n=== CROSS-TOOL OPSEC ANALYSIS ===" -ForegroundColor Magenta

# Detection Risk Analysis
Write-Host "`nDetection Risk Analysis:" -ForegroundColor Cyan
foreach($tool in $opsecAnalysis["Detection Risk"].Keys) {
    $risk = $opsecAnalysis["Detection Risk"][$tool]
    Write-Host "  $tool`: $risk" -ForegroundColor White
}

# Stealth Recommendations
Write-Host "`nStealth Recommendations:" -ForegroundColor Cyan
foreach($rec in $opsecAnalysis["Stealth Recommendations"]) {
    Write-Host "  [$($rec.Priority)] $($rec.Recommendation)" -ForegroundColor Yellow
    Write-Host "    Rationale: $($rec.Rationale)" -ForegroundColor White
    Write-Host "    Implementation: $($rec.Implementation)" -ForegroundColor Gray
}

# Tool Selection Strategy
Write-Host "`nTool Selection Strategy:" -ForegroundColor Cyan
foreach($strategy in $opsecAnalysis["Tool Selection Strategy"]) {
    Write-Host "  Environment: $($strategy.Environment)" -ForegroundColor Yellow
    Write-Host "    Primary: $($strategy.PrimaryTool)" -ForegroundColor White
    Write-Host "    Secondary: $($strategy.SecondaryTool)" -ForegroundColor White
    Write-Host "    Avoid: $($strategy.AvoidTool)" -ForegroundColor Red
    Write-Host "    Rationale: $($strategy.Rationale)" -ForegroundColor Gray
}

# Timing Optimization
Write-Host "`nTiming Optimization:" -ForegroundColor Cyan
foreach($timing in $opsecAnalysis["Timing Optimization"]) {
    Write-Host "  Phase: $($timing.Phase)" -ForegroundColor Yellow
    Write-Host "    Delay: $($timing.Delay)" -ForegroundColor White
    Write-Host "    Rationale: $($timing.Rationale)" -ForegroundColor White
    Write-Host "    Tool: $($timing.Tool)" -ForegroundColor Gray
}
```

#### **OPSEC Profile Application**
```powershell
# Apply OPSEC profile based on environment
$currentProfile = if($env:COMPUTERNAME -like "*PROD*") {$stealthProfile} elseif($env:COMPUTERNAME -like "*LAB*") {$balancedProfile} else {$msadStealthProfile}

Write-Host "Current OPSEC Profile:" -ForegroundColor Cyan
$currentProfile.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor White
}

# Apply profile settings
$env:NETWORK_DISCOVERY_DELAY_MIN = $currentProfile.DelayRange[0]
$env:NETWORK_DISCOVERY_DELAY_MAX = $currentProfile.DelayRange[1]
$env:NETWORK_DISCOVERY_MAX_CONCURRENT = $currentProfile.MaxConcurrentScans
$env:NETWORK_DISCOVERY_TOOL_PREFERENCE = $currentProfile.ToolPreference

Write-Host "`nApplied OPSEC Profile Settings:" -ForegroundColor Green
Write-Host "  Delay Range: $($env:NETWORK_DISCOVERY_DELAY_MIN)-$($env:NETWORK_DISCOVERY_DELAY_MAX) seconds" -ForegroundColor White
Write-Host "  Max Concurrent: $($env:NETWORK_DISCOVERY_MAX_CONCURRENT)" -ForegroundColor White
Write-Host "  Tool Preference: $($env:NETWORK_DISCOVERY_TOOL_PREFERENCE)" -ForegroundColor White
```

---

## 🧹 **CLEANUP & MAINTENANCE**

### **🗑️ Network Discovery Cleanup**
```powershell
# Clear network discovery artifacts
Write-Host "Cleaning up network discovery artifacts..." -ForegroundColor Cyan

# Clear DNS cache
Clear-DnsClientCache
Write-Host "  ✓ DNS cache cleared" -ForegroundColor Green

# Clear ARP cache
arp -d *
Write-Host "  ✓ ARP cache cleared" -ForegroundColor Green

# Clear network connections (if any)
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(80, 443, 8080)} | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Write-Host "  ✓ Network connections cleared" -ForegroundColor Green

# Clear temporary files
Remove-Item "$env:TEMP\network_scan_*" -Force -ErrorAction SilentlyContinue
Write-Host "  ✓ Temporary files cleared" -ForegroundColor Green

# Clear Invisi-Shell artifacts (if used)
if($env:INVISI_SHELL_ACTIVE -eq $true) {
    Write-Host "Cleaning up Invisi-Shell artifacts..." -ForegroundColor Cyan
    Remove-Item "$env:TEMP\InvisiShell*" -Force -ErrorAction SilentlyContinue
    $env:INVISI_SHELL_ACTIVE = $false
    Write-Host "  ✓ Invisi-Shell artifacts cleared" -ForegroundColor Green
}

Write-Host "Network discovery cleanup completed." -ForegroundColor Green
```

#### **Tool 1: Native Windows Commands (Stealth Cleanup)**
```powershell
# Native Windows cleanup function
function Invoke-NativeCleanup {
    Write-Host "Executing native Windows cleanup..." -ForegroundColor Cyan
    
    # Clear command history
    Clear-History
    Write-Host "  ✓ Command history cleared" -ForegroundColor Green
    
    # Clear PowerShell history file
    $historyPath = (Get-PSReadLineOption).HistorySavePath
    if(Test-Path $historyPath) {
        Remove-Item $historyPath -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ PowerShell history file cleared" -ForegroundColor Green
    }
    
    # Clear environment variables
    $envVarsToClear = @(
        "NETWORK_DISCOVERY_DELAY_MIN",
        "NETWORK_DISCOVERY_DELAY_MAX", 
        "NETWORK_DISCOVERY_MAX_CONCURRENT",
        "NETWORK_DISCOVERY_TOOL_PREFERENCE",
        "INVISI_SHELL_ACTIVE"
    )
    
    foreach($var in $envVarsToClear) {
        if(Get-Variable -Name $var -ErrorAction SilentlyContinue) {
            Remove-Variable -Name $var -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ Environment variable $var cleared" -ForegroundColor Green
        }
    }
    
    # Clear network-related registry keys (if elevated)
    if([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains "S-1-5-32-544") {
        try {
            # Clear network discovery registry artifacts
            $regKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden\SSID",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden\SSID\ShowHidden"
            )
            
            foreach($key in $regKeys) {
                if(Test-Path $key) {
                    Remove-ItemProperty -Path $key -Name "*" -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  ✓ Network registry artifacts cleared" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️ Registry cleanup failed (may not be elevated)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "Native Windows cleanup completed." -ForegroundColor Green
}

# Use native cleanup
Invoke-NativeCleanup
```

#### **Tool 2: PowerView Suite (Comprehensive Cleanup)**
```powershell
# Load PowerView
. .\PowerView.ps1

# PowerView cleanup function
function Invoke-PowerViewCleanup {
    Write-Host "Executing PowerView cleanup..." -ForegroundColor Cyan
    
    # Clear PowerView variables and functions
    $powerViewFunctions = Get-Command -Name "Get-Domain*", "Find-Domain*", "Invoke-Domain*" -ErrorAction SilentlyContinue
    foreach($func in $powerViewFunctions) {
        try {
            Remove-Item "function:$($func.Name)" -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ PowerView function $($func.Name) removed" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️ Failed to remove function $($func.Name)" -ForegroundColor Yellow
        }
    }
    
    # Clear PowerView-related variables
    $powerViewVars = Get-Variable | Where-Object { 
        $_.Name -like "*domain*" -or 
        $_.Name -like "*computer*" -or 
        $_.Name -like "*user*" -or 
        $_.Name -like "*group*" -or
        $_.Name -like "*gpo*" -or
        $_.Name -like "*acl*" -or
        $_.Name -like "*trust*" -or
        $_.Name -like "*site*" -or
        $_.Name -like "*subnet*"
    }
    
    foreach($var in $powerViewVars) {
        try {
            Remove-Variable -Name $var.Name -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ PowerView variable $($var.Name) cleared" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️ Failed to clear variable $($var.Name)" -ForegroundColor Yellow
        }
    }
    
    # Clear PowerView module
    try {
        Remove-Module PowerView -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ PowerView module removed" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ Failed to remove PowerView module" -ForegroundColor Yellow
    }
    
    # Clear PowerView script
    if(Test-Path "PowerView.ps1") {
        Remove-Item "PowerView.ps1" -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ PowerView script removed" -ForegroundColor Green
    }
    
    Write-Host "PowerView cleanup completed." -ForegroundColor Green
}

# Use PowerView cleanup
Invoke-PowerViewCleanup
```

#### **Tool 3: Microsoft AD Module (Stealth Cleanup)**
```powershell
# Load the module
Import-Module ActiveDirectory

# Microsoft AD Module cleanup function
function Invoke-MSADCleanup {
    Write-Host "Executing Microsoft AD Module cleanup..." -ForegroundColor Cyan
    
    # Clear Microsoft AD Module variables
    $msadVars = Get-Variable | Where-Object { 
        $_.Name -like "*AD*" -or 
        $_.Name -like "*Domain*" -or 
        $_.Name -like "*Computer*" -or 
        $_.Name -like "*User*" -or 
        $_.Name -like "*Group*" -or
        $_.Name -like "*GPO*" -or
        $_.Name -like "*Trust*" -or
        $_.Name -like "*Site*" -or
        $_.Name -like "*Subnet*"
    }
    
    foreach($var in $msadVars) {
        try {
            Remove-Variable -Name $var.Name -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ Microsoft AD variable $($var.Name) cleared" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️ Failed to clear variable $($var.Name)" -ForegroundColor Yellow
        }
    }
    
    # Clear Microsoft AD Module
    try {
        Remove-Module ActiveDirectory -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ Microsoft AD Module removed" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ Failed to remove Microsoft AD Module" -ForegroundColor Yellow
    }
    
    # Clear Microsoft GroupPolicy Module if loaded
    try {
        Remove-Module GroupPolicy -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ Microsoft GroupPolicy Module removed" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ GroupPolicy Module not loaded or failed to remove" -ForegroundColor Yellow
    }
    
    Write-Host "Microsoft AD Module cleanup completed." -ForegroundColor Green
}

# Use Microsoft AD Module cleanup
Invoke-MSADCleanup
```

#### **Advanced Cleanup Integration**
```powershell
# Cross-tool cleanup analysis and execution
function Invoke-CrossToolCleanup {
    param(
        [switch]$Force,
        [string[]]$ToolsToClean = @("Native", "PowerView", "MSAD")
    )
    
    $cleanupResults = @{
        "Native Windows" = @{Status = "Pending"; Details = @()}
        "PowerView" = @{Status = "Pending"; Details = @()}
        "Microsoft AD Module" = @{Status = "Pending"; Details = @()}
        "Summary" = @{TotalTools = 0; Successful = 0; Failed = 0}
    }
    
    Write-Host "Executing cross-tool cleanup..." -ForegroundColor Cyan
    
    # Native Windows cleanup
    if("Native" -in $ToolsToClean) {
        try {
            Invoke-NativeCleanup
            $cleanupResults["Native Windows"].Status = "Completed"
            $cleanupResults["Native Windows"].Details += "All native Windows artifacts cleared"
            $cleanupResults.Summary.Successful++
        } catch {
            $cleanupResults["Native Windows"].Status = "Failed"
            $cleanupResults["Native Windows"].Details += "Error: $($_.Exception.Message)"
            $cleanupResults.Summary.Failed++
        }
        $cleanupResults.Summary.TotalTools++
    }
    
    # PowerView cleanup
    if("PowerView" -in $ToolsToClean) {
        try {
            Invoke-PowerViewCleanup
            $cleanupResults["PowerView"].Status = "Completed"
            $cleanupResults["PowerView"].Details += "All PowerView artifacts cleared"
            $cleanupResults.Summary.Successful++
        } catch {
            $cleanupResults["PowerView"].Status = "Failed"
            $cleanupResults["PowerView"].Details += "Error: $($_.Exception.Message)"
            $cleanupResults.Summary.Failed++
        }
        $cleanupResults.Summary.TotalTools++
    }
    
    # Microsoft AD Module cleanup
    if("MSAD" -in $ToolsToClean) {
        try {
            Invoke-MSADCleanup
            $cleanupResults["Microsoft AD Module"].Status = "Completed"
            $cleanupResults["Microsoft AD Module"].Details += "All Microsoft AD Module artifacts cleared"
            $cleanupResults.Summary.Successful++
        } catch {
            $cleanupResults["Microsoft AD Module"].Status = "Failed"
            $cleanupResults["Microsoft AD Module"].Details += "Error: $($_.Exception.Message)"
            $cleanupResults.Summary.Failed++
        }
        $cleanupResults.Summary.TotalTools++
    }
    
    # Generate cleanup summary
    Write-Host "`n=== CROSS-TOOL CLEANUP SUMMARY ===" -ForegroundColor Magenta
    foreach($tool in $cleanupResults.Keys) {
        if($tool -ne "Summary") {
            $status = $cleanupResults[$tool].Status
            $color = if($status -eq "Completed") {"Green"} elseif($status -eq "Failed") {"Red"} else {"Yellow"}
            Write-Host "`n$tool`: $status" -ForegroundColor $color
            
            foreach($detail in $cleanupResults[$tool].Details) {
                Write-Host "  $detail" -ForegroundColor White
            }
        }
    }
    
    # Summary statistics
    Write-Host "`nCleanup Summary:" -ForegroundColor Cyan
    Write-Host "  Total Tools: $($cleanupResults.Summary.TotalTools)" -ForegroundColor White
    Write-Host "  Successful: $($cleanupResults.Summary.Successful)" -ForegroundColor Green
    Write-Host "  Failed: $($cleanupResults.Summary.Failed)" -ForegroundColor Red
    
    return $cleanupResults
}

# Use cross-tool cleanup
$cleanupResults = Invoke-CrossToolCleanup -ToolsToClean @("Native", "PowerView", "MSAD")

# Final cleanup verification
function Test-CleanupVerification {
    Write-Host "`nVerifying cleanup completion..." -ForegroundColor Cyan
    
    $verificationResults = @{
        "PowerView Functions" = $false
        "PowerView Variables" = $false
        "Microsoft AD Module" = $false
        "Environment Variables" = $false
        "Temporary Files" = $false
    }
    
    # Check PowerView functions
    $powerViewFunctions = Get-Command -Name "Get-Domain*", "Find-Domain*", "Invoke-Domain*" -ErrorAction SilentlyContinue
    if($powerViewFunctions.Count -eq 0) {
        $verificationResults["PowerView Functions"] = $true
        Write-Host "  ✓ PowerView functions verified as removed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ PowerView functions still present: $($powerViewFunctions.Count)" -ForegroundColor Red
    }
    
    # Check PowerView variables
    $powerViewVars = Get-Variable | Where-Object { 
        $_.Name -like "*domain*" -or 
        $_.Name -like "*computer*" -or 
        $_.Name -like "*user*" -or 
        $_.Name -like "*group*"
    }
    if($powerViewVars.Count -eq 0) {
        $verificationResults["PowerView Variables"] = $true
        Write-Host "  ✓ PowerView variables verified as removed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ PowerView variables still present: $($powerViewVars.Count)" -ForegroundColor Red
    }
    
    # Check Microsoft AD Module
    $msadModule = Get-Module -Name "ActiveDirectory" -ErrorAction SilentlyContinue
    if(-not $msadModule) {
        $verificationResults["Microsoft AD Module"] = $true
        Write-Host "  ✓ Microsoft AD Module verified as removed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Microsoft AD Module still loaded" -ForegroundColor Red
    }
    
    # Check environment variables
    $envVars = @("NETWORK_DISCOVERY_DELAY_MIN", "NETWORK_DISCOVERY_DELAY_MAX", "INVISI_SHELL_ACTIVE")
    $envVarsPresent = $envVars | Where-Object { Get-Variable -Name $_ -ErrorAction SilentlyContinue }
    if($envVarsPresent.Count -eq 0) {
        $verificationResults["Environment Variables"] = $true
        Write-Host "  ✓ Environment variables verified as cleared" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Environment variables still present: $($envVarsPresent.Count)" -ForegroundColor Red
    }
    
    # Check temporary files
    $tempFiles = Get-ChildItem -Path "$env:TEMP" -Name "*network*", "*PowerView*", "*AD*" -ErrorAction SilentlyContinue
    if($tempFiles.Count -eq 0) {
        $verificationResults["Temporary Files"] = $true
        Write-Host "  ✓ Temporary files verified as cleared" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Temporary files still present: $($tempFiles.Count)" -ForegroundColor Red
    }
    
    # Generate verification summary
    $successCount = ($verificationResults.Values | Where-Object {$_ -eq $true}).Count
    $totalCount = $verificationResults.Count
    
    Write-Host "`nCleanup Verification Summary:" -ForegroundColor Cyan
    Write-Host "  Successful: $successCount/$totalCount" -ForegroundColor $(if($successCount -eq $totalCount){"Green"}else{"Yellow"})
    
    if($successCount -eq $totalCount) {
        Write-Host "  ✓ All cleanup operations verified successfully" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️ Some cleanup operations may need manual attention" -ForegroundColor Yellow
    }
    
    return $verificationResults
}

# Use cleanup verification
$verificationResults = Test-CleanupVerification
```

#### **Maintenance Procedures**
```powershell
# Post-cleanup maintenance
function Invoke-PostCleanupMaintenance {
    Write-Host "`nExecuting post-cleanup maintenance..." -ForegroundColor Cyan
    
    # Reset PowerShell execution policy (if changed)
    try {
        $currentPolicy = Get-ExecutionPolicy
        if($currentPolicy -ne "Restricted") {
            Set-ExecutionPolicy -ExecutionPolicy Restricted -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ PowerShell execution policy reset to Restricted" -ForegroundColor Green
        } else {
            Write-Host "  ✓ PowerShell execution policy already Restricted" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ⚠️ Failed to reset execution policy (may not be elevated)" -ForegroundColor Yellow
    }
    
    # Clear PowerShell session
    try {
        Clear-Host
        Write-Host "  ✓ PowerShell session cleared" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ Failed to clear PowerShell session" -ForegroundColor Yellow
    }
    
    # Final garbage collection
    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Write-Host "  ✓ Garbage collection completed" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ Garbage collection failed" -ForegroundColor Yellow
    }
    
    Write-Host "Post-cleanup maintenance completed." -ForegroundColor Green
}

# Use post-cleanup maintenance
Invoke-PostCleanupMaintenance

Write-Host "`n=== NETWORK ENUMERATION CLEANUP COMPLETED ===" -ForegroundColor Green
Write-Host "All tools have been cleaned up and the system is ready for normal operations." -ForegroundColor White
```



## 🔗 **COMPREHENSIVE CROSS-REFERENCES**

### **📋 TECHNIQUE REFERENCES**
- **DNS Enumeration**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md) - Next step after network discovery
- **Domain Enumeration**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md) - Uses network findings for AD enumeration
- **File Share Enumeration**: [17_File_Share_Enumeration.md](./17_File_Share_Enumeration.md) - After discovering SMB services
- **PowerShell Remoting**: [19_PowerShell_Remoting_Enumeration.md](./19_PowerShell_Remoting_Enumeration.md) - After discovering WinRM services
- **Kerberos Enumeration**: [23_Kerberos_Basic_Enumeration.md](./23_Kerberos_Basic_Enumeration.md) - After discovering Kerberos services

### **🛠️ TOOL REFERENCES**
- **Tool Arsenal**: [01_Tool_Setup_Loading.md#invisi-shell-complete-setup](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup) - Tools used for network discovery
- **Invisi-Shell Setup**: [01_Tool_Setup_Loading.md#invisi-shell-complete-setup](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup) - Critical for stealth operations
- **PowerView Setup**: [01_Tool_Setup_Loading.md#powerview-complete-setup](./01_Tool_Setup_Loading.md#powerview-complete-setup) - Comprehensive AD enumeration
- **Microsoft AD Module**: [01_Tool_Setup_Loading.md#core-enumeration-tools](./01_Tool_Setup_Loading.md#core-enumeration-tools) - Stealth operations
- **Methodology Hub**: [00_Methodology_Hub.md](./00_Methodology_Hub.md) - Overall enumeration strategy

### **🎯 TOOL INTEGRATION MATRIX**
| **Network Discovery Phase** | **Primary Tool** | **Secondary Tool** | **Fallback Tool** | **Use Case** |
|------------------------------|------------------|-------------------|-------------------|--------------|
| **Initial Connectivity** | Native Windows | Microsoft AD Module | PowerView | Stealth baseline |
| **Port Scanning** | Native Windows | Microsoft AD Module | PowerView | Service discovery |
| **Subnet Enumeration** | Native Windows | Microsoft AD Module | PowerView | Network mapping |
| **DNS Service Discovery** | Native Windows | Microsoft AD Module | PowerView | AD service location |
| **Topology Mapping** | Microsoft AD Module | PowerView | Native Windows | Comprehensive mapping |
| **Pivot Planning** | PowerView | Microsoft AD Module | Native Windows | Strategic next steps |

### **🔧 TOOL-SPECIFIC WORKFLOWS**
- **Native Windows Workflow**: Stealth operations → Minimal detection → Basic discovery
- **PowerView Workflow**: Comprehensive enumeration → Attack path mapping → Offensive operations
- **Microsoft AD Module Workflow**: Compliance operations → Stealth enumeration → Production environments

---

## 🎯 **NAVIGATION & NEXT STEPS**

**🔄 [Back to Master Index](./00_Enumeration_Index.md)** | **🛠️ [Previous: Tool Arsenal](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup)** | **🔍 [Next: DNS Enumeration](./03_DNS_Enumeration.md)** | **🔐 [Kerberos Master Index](./22_Kerberos_Master_Index.md)**

---

**🎯 Network enumeration is the foundation for all AD techniques. Discover networks, map services, and plan your enumeration strategy before diving into specific AD enumeration techniques. Use the appropriate tool combination based on your environment and OPSEC requirements.**

