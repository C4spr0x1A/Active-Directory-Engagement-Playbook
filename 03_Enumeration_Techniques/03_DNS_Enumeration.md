# 🔍 DNS Enumeration - Service Discovery for Active Directory

> **🎯 PURPOSE**: This is your **DNS service discovery foundation** for Active Directory enumeration. After network discovery, DNS enumeration reveals domain controllers, global catalogs, and service locations that guide all subsequent AD enumeration techniques.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🌐 Previous: Network Enumeration](./02_Network_Enumeration.md) | [Next: Domain Enumeration](./04_Domain_Enumeration.md)

---

## 🔗 **RELATED ACTIVE DIRECTORY COMPONENTS**

### **🌐 DNS Infrastructure Components**
- **[Domain Controllers](../02_Active_Directory_Components/02_Domain_Controllers.md)**: Discovered through SRV records and serve as DNS servers
- **[Global Catalog](../02_Active_Directory_Components/12_Global_Catalog.md)**: Located via DNS SRV records for forest-wide searches
- **[LDAP and Ports](../02_Active_Directory_Components/13_LDAP_and_Ports.md)**: Service locations revealed through DNS enumeration

### **🏗️ Domain Architecture Components**
- **[Domain](../02_Active_Directory_Components/03_Domain.md)**: DNS zones and domain boundaries discovered through enumeration
- **[Forest](../02_Active_Directory_Components/04_Forest.md)**: Multi-domain DNS structure and trust relationships
- **[Sites and Subnets](../02_Active_Directory_Components/06_Sites_and_Subnets.md)**: Network topology revealed through DNS zone information

### **🔐 Authentication and Service Components**
- **[Kerberos](../02_Active_Directory_Components/16_Kerberos.md)**: KDC service locations discovered via DNS SRV records
- **[Replication Service](../02_Active_Directory_Components/15_Replication_Service.md)**: Replication partners located through DNS
- **[Schema](../02_Active_Directory_Components/11_Schema.md)**: Schema master location discovered via DNS

---

## 🚀 **DNS SERVICE DISCOVERY OVERVIEW**

### **🎭 What This Foundation Provides**
DNS enumeration is the **second step** in AD engagement after network discovery. It reveals:
- **Domain Controllers** and their locations via SRV records
- **Global Catalogs** for cross-domain queries
- **Service Locations** for Kerberos, LDAP, and other AD services
- **Network Topology** through DNS zone information
- **Service Discovery** for planning enumeration strategies

> **Note on OPSEC**: In production environments, prefer Microsoft-signed/native tooling and low-noise queries. If you must run offensive tooling, consider stealth wrappers (e.g., Invisi-Shell) per your rules of engagement. See [Tool Arsenal](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup).

### **🎯 DNS Discovery Categories**
- **SRV Record Discovery**: Domain controllers, global catalogs, service locations
- **Zone Information**: DNS structure and network topology
- **Service Mapping**: Active Directory service locations
- **Pivot Planning**: Strategic next steps for AD enumeration

### **🛠️ Mandatory Tools**
- **Invisi-Shell**: Required for all production operations to ensure stealth
- **Native DNS Tools**: Built-in commands for minimal footprint
- **PowerShell DNS Cmdlets**: For advanced DNS enumeration capabilities

---

## 📋 **QUICK START DNS DISCOVERY**

### **⚡ Immediate DNS Discovery Commands**
| **What You Need** | **Quick Command** | **Full Setup** |
|-------------------|-------------------|----------------|
| **Domain Resolution** | `Resolve-DnsName "corp.local"` | [Basic DNS Discovery](#basic-dns-discovery) |
| **DC Discovery** | `Resolve-DnsName _ldap._tcp.dc._msdcs.corp.local -Type SRV` | [SRV Record Discovery](#srv-record-discovery) |
| **KDC Discovery** | `Resolve-DnsName _kerberos._tcp.corp.local -Type SRV` | [Kerberos Service Discovery](#kerberos-service-discovery) |
| **GC Discovery** | `Resolve-DnsName _ldap._tcp.gc._msdcs.corp.local -Type SRV` | [Global Catalog Discovery](#global-catalog-discovery) |
| **Zone Transfer (authorized)** | `dig @ns1.corp.local corp.local AXFR` | [Zone Information Discovery](#zone-information-discovery) |

### **🎯 Environment-Specific DNS Discovery**
```powershell
# Production Environment (Stealth Mode)
if($env:COMPUTERNAME -like "*PROD*" -or $env:USERDOMAIN -like "*PROD*") {
    Write-Host "Production environment detected - using stealth DNS profile" -ForegroundColor Yellow
    $dnsProfile = "Stealth"
    $delayRange = @(2, 5)
    $resolver = "Local DC only"
    $queryTypes = @("SRV only")
    
    # Stealth wrappers (optional, per ROE) can be loaded here if approved
    # . .\RunWithPathAsAdmin.bat
} else {
    Write-Host "Lab environment detected - using balanced DNS profile" -ForegroundColor Green
    $dnsProfile = "Balanced"
    $delayRange = @(1, 2)
    $resolver = "DC + secondary"
    $queryTypes = @("SRV", "A", "CNAME")
}

Write-Host "DNS Profile: $dnsProfile" -ForegroundColor Cyan
Write-Host "Delay Range: $($delayRange[0])-$($delayRange[1]) seconds" -ForegroundColor Cyan
Write-Host "Resolver: $resolver" -ForegroundColor Cyan
Write-Host "Query Types: $($queryTypes -join ', ')" -ForegroundColor Cyan
```

---

## 🛠️ **ENUMERATION TOOLS OVERVIEW**

> **🔒 CRITICAL TOOL REQUIREMENT**: **Invisi-Shell** is mandatory for all production DNS enumeration operations. It provides AMSI bypass, logging evasion, and stealth capabilities that are essential for operational security.

### **🔧 Tool Categories and Capabilities**

#### **Stealth Tools (Production Required)**
- **Invisi-Shell**: AMSI bypass, logging evasion, stealth operations
- **Native DNS Commands**: Built-in tools for minimal footprint
- **PowerShell DNS Cmdlets**: For advanced DNS enumeration capabilities

#### **DNS Discovery Tools**
- **SRV Record Enumeration**: Service location discovery
- **Zone Information**: DNS structure and topology
- **Service Mapping**: Active Directory service locations

#### **Analysis Tools**
- **Data Processing**: DNS results analysis and pivot planning
- **Reporting**: DNS findings and next steps
- **Integration**: Connection to subsequent AD enumeration techniques

---

## 🛠️ **COMPREHENSIVE ENUMERATION TOOLS**

### **🔧 Microsoft-Signed Tools**
- **Microsoft AD Module**: DNS-related domain and service analysis
- **Get-ADDomain**: Domain object enumeration for DNS analysis
- **Get-ADDomainController**: Domain controller discovery via DNS
- **Get-ADReplicationSite**: AD site topology for DNS mapping
- **Resolve-DnsName**: Native PowerShell DNS resolution
- **nslookup**: Built-in Windows DNS query tool

### **⚔️ Offensive Tools (PowerView, etc.)**
- **PowerView Suite**: Comprehensive DNS enumeration and discovery
- **Get-Domain**: PowerView domain enumeration via DNS
- **Get-DomainController**: PowerView DC discovery via DNS
- **Get-DomainSite**: PowerView site topology via DNS
- **Invoke-DNSEnumeration**: PowerView DNS enumeration capabilities

### **🔴 Red Team Enumeration Tools**

#### **🔍 DNSEnum - The DNS Enumeration Tool**
**Purpose**: Comprehensive DNS enumeration and subdomain discovery
**Setup**: Download from https://github.com/fwaeytens/dnsenum or use package manager
**Primary Commands**:
```bash
# Basic DNS enumeration
dnsenum target.com                                           # Basic enumeration
dnsenum target.com -o results.txt                            # Output to file
dnsenum target.com -n 8.8.8.8                               # Custom nameserver

# Subdomain enumeration
dnsenum target.com -w wordlist.txt                           # With wordlist
dnsenum target.com -w wordlist.txt -s 10                     # With subdomain count
dnsenum target.com -w wordlist.txt -r                        # Reverse lookup

# Zone transfer attempts
dnsenum target.com -z                                        # Zone transfer
dnsenum target.com -z -n 8.8.8.8                            # Zone transfer with custom NS
dnsenum target.com -z -o zone_results.txt                    # Zone transfer output

# Advanced options
dnsenum target.com -t 5                                      # Thread count
dnsenum target.com -T 10                                     # Timeout
dnsenum target.com -v                                        # Verbose output
```

#### **🔍 DNSRecon - The DNS Reconnaissance Tool**
**Purpose**: Advanced DNS reconnaissance and service discovery
**Setup**: `pip install dnsrecon` or download from https://github.com/darkoperator/dnsrecon
**Primary Commands**:
```bash
# Basic DNS reconnaissance
dnsrecon -d target.com                                       # Basic reconnaissance
dnsrecon -d target.com -o results.xml                        # XML output
dnsrecon -d target.com -o results.json                       # JSON output

# Subdomain enumeration
dnsrecon -d target.com -D wordlist.txt                       # With wordlist
dnsrecon -d target.com -D wordlist.txt -n 8.8.8.8           # Custom nameserver
dnsrecon -d target.com -D wordlist.txt -t brt                # Brute force

# Zone transfer attempts
dnsrecon -d target.com -a                                    # Zone transfer
dnsrecon -d target.com -a -n 8.8.8.8                        # Zone transfer with custom NS
dnsrecon -d target.com -a -o zone_results.xml                # Zone transfer output

# Service discovery
dnsrecon -d target.com -s                                    # SRV records
dnsrecon -d target.com -s -o srv_results.xml                 # SRV output
dnsrecon -d target.com -g                                    # Google enumeration
dnsrecon -d target.com -b                                    # Bing enumeration
```

#### **🦁 Fierce - The DNS Bruteforcing Tool**
**Purpose**: DNS bruteforcing and subdomain discovery
**Setup**: `pip install fierce` or download from https://github.com/mschwager/fierce
**Primary Commands**:
```bash
# Basic DNS bruteforcing
fierce --domain target.com                                   # Basic bruteforce
fierce --domain target.com --wordlist wordlist.txt           # With wordlist
fierce --domain target.com --subdomains 100                  # Subdomain count

# DNS server specification
fierce --domain target.com --dns-servers 8.8.8.8             # Custom DNS server
fierce --domain target.com --dns-servers 8.8.8.8,1.1.1.1    # Multiple DNS servers
fierce --domain target.com --dns-servers 8.8.8.8 --range 192.168.1.0/24  # IP range

# Output options
fierce --domain target.com --output results.txt              # Output to file
fierce --domain target.com --output results.csv              # CSV output
fierce --domain target.com --output results.json             # JSON output

# Advanced options
fierce --domain target.com --threads 10                      # Thread count
fierce --domain target.com --timeout 5                       # Timeout
fierce --domain target.com --wide                            # Wide scan
```

#### **🔍 Sublist3r - The Subdomain Enumeration Tool**
**Purpose**: Subdomain enumeration via search engines
**Setup**: `pip install sublist3r` or download from https://github.com/aboul3la/Sublist3r
**Primary Commands**:
```bash
# Basic subdomain enumeration
sublist3r -d target.com                                      # Basic enumeration
sublist3r -d target.com -o results.txt                       # Output to file
sublist3r -d target.com -n 8.8.8.8                          # Custom nameserver

# Search engine enumeration
sublist3r -d target.com -e google                            # Google only
sublist3r -d target.com -e bing                              # Bing only
sublist3r -d target.com -e google,bing                       # Multiple engines
sublist3r -d target.com -e google,bing,virustotal            # With VirusTotal

# Brute force options
sublist3r -d target.com -b                                   # Brute force
sublist3r -d target.com -b -w wordlist.txt                   # With wordlist
sublist3r -d target.com -b -t 10                             # Thread count

# Advanced options
sublist3r -d target.com -v                                   # Verbose output
sublist3r -d target.com -t 20                                # Thread count
sublist3r -d target.com -o results.txt -n 8.8.8.8           # Combined options
```

#### **🔍 Gobuster - The Directory and DNS Bruteforcing Tool**
**Purpose**: DNS bruteforcing and subdomain discovery
**Setup**: Download from https://github.com/OJ/gobuster/releases
**Primary Commands**:
```bash
# DNS bruteforcing
gobuster dns -d target.com -w wordlist.txt                   # Basic DNS bruteforce
gobuster dns -d target.com -w wordlist.txt -r 8.8.8.8       # Custom resolver
gobuster dns -d target.com -w wordlist.txt -o results.txt    # Output to file

# Subdomain enumeration
gobuster dns -d target.com -w wordlist.txt -s                # Show IP addresses
gobuster dns -d target.com -w wordlist.txt -s -r 8.8.8.8    # With custom resolver
gobuster dns -d target.com -w wordlist.txt -s -o results.txt # With output

# Advanced DNS options
gobuster dns -d target.com -w wordlist.txt -t 50             # Thread count
gobuster dns -d target.com -w wordlist.txt -v                # Verbose output
gobuster dns -d target.com -w wordlist.txt --wildcard        # Wildcard detection

# Output formats
gobuster dns -d target.com -w wordlist.txt -o results.txt    # Text output
gobuster dns -d target.com -w wordlist.txt -o results.csv    # CSV output
gobuster dns -d target.com -w wordlist.txt -o results.json   # JSON output
```

#### **🔍 Amass - The In-Depth DNS Enumeration Tool**
**Purpose**: Comprehensive DNS enumeration and subdomain discovery
**Setup**: Download from https://github.com/owasp-amass/amass/releases
**Primary Commands**:
```bash
# Basic DNS enumeration
amass enum -d target.com                                     # Basic enumeration
amass enum -d target.com -o results.txt                      # Output to file
amass enum -d target.com -o results.txt -json                # JSON output

# Subdomain enumeration
amass enum -d target.com -w wordlist.txt                     # With wordlist
amass enum -d target.com -w wordlist.txt -brute              # Brute force
amass enum -d target.com -w wordlist.txt -passive            # Passive only

# Active enumeration
amass enum -d target.com -active                             # Active enumeration
amass enum -d target.com -active -brute                      # Active + brute force
amass enum -d target.com -active -w wordlist.txt             # Active + wordlist

# Output and options
amass enum -d target.com -o results.txt -json                # JSON output
amass enum -d target.com -o results.txt -csv                 # CSV output
amass enum -d target.com -o results.txt -oamass              # Amass format
```

### **🛠️ Alternative Enumeration Tools**

#### **🔍 Native Windows DNS Tools**
**Purpose**: Built-in Windows DNS enumeration capabilities
**Setup**: Built into Windows
**Primary Commands**:
```cmd
# nslookup commands
nslookup target.com                                           # Basic lookup
nslookup -type=SRV _ldap._tcp.dc._msdcs.target.com          # SRV record lookup
nslookup -type=MX target.com                                 # MX record lookup
nslookup -type=NS target.com                                 # NS record lookup

# PowerShell DNS commands
Resolve-DnsName target.com                                   # Basic resolution
Resolve-DnsName target.com -Type SRV                         # SRV record resolution
Resolve-DnsName target.com -Type MX                          # MX record resolution
Resolve-DnsName target.com -Type NS                          # NS record resolution

# DNS server specification
Resolve-DnsName target.com -Server 8.8.8.8                  # Custom DNS server
nslookup target.com 8.8.8.8                                 # Custom DNS server
```

#### **🔍 Online DNS Enumeration Tools**
**Purpose**: Web-based DNS enumeration and reconnaissance
**Setup**: Web browser access
**Primary Tools**:
- **SecurityTrails**: DNS history and subdomain discovery
- **ViewDNS**: DNS lookup and subdomain enumeration
- **HackerTarget**: DNS reconnaissance and subdomain discovery
- **DNSDumpster**: DNS enumeration and subdomain discovery

**Usage Examples**:
```bash
# SecurityTrails
# Visit https://securitytrails.com/app/dns
# Enter target domain for comprehensive DNS analysis

# ViewDNS
# Visit https://viewdns.info/
# Use DNS lookup and subdomain discovery tools

# HackerTarget
# Visit https://hackertarget.com/dns-lookup/
# Use DNS lookup and subdomain enumeration

# DNSDumpster
# Visit https://dnsdumpster.com/
# Enter target domain for DNS reconnaissance
```

### **🔍 Specialized Tools**

#### **🌐 DNS Discovery Tools**
- **DNSEnum**: Comprehensive DNS enumeration and subdomain discovery
- **DNSRecon**: Advanced DNS reconnaissance and service discovery
- **Fierce**: DNS bruteforcing and subdomain discovery
- **Custom Scripts**: Advanced DNS enumeration automation

#### **🔗 DNS Service Discovery Tools**
- **SRV Record Enumeration**: Service location discovery
- **Zone Transfer Tools**: DNS zone information extraction
- **PowerView**: DNS enumeration via AD integration
- **Custom Scripts**: Advanced DNS service discovery

#### **📋 DNS Data Export Tools**
- **PowerView**: CSV export capabilities
- **Native Tools**: Text and structured output
- **Custom Scripts**: Advanced export format automation
- **Data conversion tools**: DNS data format conversion

#### **🎯 DNS Attack Vector Tools**
- **DNS enumeration tools**: DNS-based attacks
- **Custom Scripts**: Advanced DNS exploitation
- **Attack planning tools**: DNS-based attack path planning
- **Exploitation tools**: DNS-based privilege escalation tools

---

## 🔍 **BASIC DNS DISCOVERY**

### **🌐 Domain Resolution and Validation**

#### **What is Domain Resolution?**
**Domain Resolution** validates that a domain exists and can be resolved, establishing the foundation for all subsequent DNS enumeration.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
**What it provides**: Built-in Windows tools for basic DNS discovery
**CLM Status**: ✅ Native Windows (trusted)
**Use Case**: Minimal footprint, basic discovery, fallback option

```powershell
# Basic domain resolution
Resolve-DnsName "corp.local"
Resolve-DnsName "dc01.corp.local"

# DNS resolution with error handling
try {
    $domainInfo = Resolve-DnsName "corp.local" -ErrorAction Stop
    Write-Host "✓ Domain resolved successfully" -ForegroundColor Green
    Write-Host "  Name: $($domainInfo.Name)" -ForegroundColor White
    Write-Host "  Type: $($domainInfo.Type)" -ForegroundColor White
    Write-Host "  TTL: $($domainInfo.TTL)" -ForegroundColor White
} catch {
    Write-Host "✗ Domain resolution failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Multiple domain resolution
$domains = @("corp.local", "us.corp.local", "eu.corp.local")
foreach($domain in $domains) {
    try {
        $result = Resolve-DnsName $domain -ErrorAction Stop
        Write-Host "✓ $domain resolved successfully" -ForegroundColor Green
    } catch {
        Write-Host "✗ $domain resolution failed" -ForegroundColor Red
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
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

#### **Tool 2: PowerView Suite (Comprehensive DNS Discovery)**
**What it provides**: PowerShell framework for comprehensive DNS-based AD discovery
**CLM Status**: ❌ Not signed (offensive tool)
**Use Case**: Lab environments, penetration testing, offensive operations

```powershell
# Load PowerView
. .\PowerView.ps1

# DNS discovery via AD domain information
$domain = Get-Domain
Write-Host "Domain: $($domain.Name)" -ForegroundColor Cyan
Write-Host "Domain SID: $($domain.DomainSID)" -ForegroundColor Cyan

# DNS-based service discovery via PowerView
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

# Cross-reference DNS services with AD computers via PowerView
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

# Generate comprehensive DNS-AD mapping report via PowerView
Write-Host "`n=== POWERVIEW DNS-AD COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
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

**Tool Advantages**:
- ✅ Comprehensive DNS enumeration
- ✅ Rich object properties and methods
- ✅ Built-in filtering and search
- ✅ Offensive-focused functions
- ✅ Extensive customization options

**Tool Limitations**:
- ❌ Not Microsoft-signed
- ❌ May trigger security alerts
- ❌ Not CLM-compliant
- ❌ Requires careful deployment

#### **Tool 3: Microsoft AD Module (Stealth DNS Discovery)**
**What it provides**: Official Microsoft module for AD-based DNS discovery
**CLM Status**: ✅ Fully signed and CLM-friendly
**Use Case**: Production environments, compliance requirements

```powershell
# Load the module
Import-Module ActiveDirectory

# DNS discovery via Microsoft AD Module
$domain = Get-ADDomain
Write-Host "Domain: $($domain.Name)" -ForegroundColor Cyan
Write-Host "Domain SID: $($domain.DomainSID)" -ForegroundColor Cyan

# DNS-based service discovery via Microsoft AD Module
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
            
            # Additional AD analysis via Microsoft AD Module
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

# Cross-reference DNS services with AD computers via Microsoft AD Module
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

# Generate comprehensive AD DNS mapping report via Microsoft AD Module
Write-Host "`n=== MICROSOFT AD DNS-AD COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
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

## 🎯 **SRV RECORD DISCOVERY**

### **🔍 Active Directory Service Location Records**

#### **What are SRV Records?**
**SRV Records** (Service Location Records) are DNS records that specify the location of services like domain controllers, global catalogs, and Kerberos distribution centers. They're crucial for AD enumeration.

#### **Tool 1: Native Windows Commands (Stealth Operations)**
```powershell
# Critical AD SRV record types
$adSrvTypes = @{
    "_ldap._tcp.dc._msdcs" = @{
        Name = "Domain Controllers"
        Description = "LDAP services for domain controllers"
        Purpose = "DC discovery and LDAP enumeration"
        Priority = "High"
    }
    "_kerberos._tcp" = @{
        Name = "Kerberos Distribution Centers"
        Description = "Kerberos authentication services"
        Purpose = "KDC discovery for Kerberos attacks"
        Priority = "High"
    }
    "_ldap._tcp.gc._msdcs" = @{
        Name = "Global Catalogs"
        Description = "Global catalog services"
        Purpose = "Cross-domain query capabilities"
        Priority = "Medium"
    }
    "_kpasswd._tcp" = @{
        Name = "Password Change Services"
        Description = "Kerberos password change services"
        Purpose = "Password policy enumeration"
        Priority = "Low"
    }
    "_ldap._tcp.pdc._msdcs" = @{
        Name = "Primary Domain Controllers"
        Description = "PDC emulator services"
        Purpose = "PDC discovery for time sync"
        Priority = "Medium"
    }
}

Write-Host "Critical AD SRV Record Types:" -ForegroundColor Cyan
$adSrvTypes.GetEnumerator() | Sort-Object {$_.Value.Priority} | ForEach-Object {
    $priority = $_.Value.Priority
    $color = switch($priority) {
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
        default { "White" }
    }
    
    Write-Host "  $($_.Key) ($priority priority):" -ForegroundColor $color
    Write-Host "    → $($_.Value.Name) - $($_.Value.Description)" -ForegroundColor White
    Write-Host "    → Purpose: $($_.Value.Purpose)" -ForegroundColor Gray
}

# Basic SRV record discovery
$domain = "corp.local"
Write-Host "`nDiscovering Domain Controllers for $domain..." -ForegroundColor Cyan

try {
    $dcRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$domain" -Type SRV -ErrorAction Stop
    
    Write-Host "`nDomain Controllers Found:" -ForegroundColor Green
    foreach($record in $dcRecords) {
        Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
        Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight), TTL: $($record.TTL)" -ForegroundColor Gray
    }
    
    # Extract DC hostnames
    $dcHostnames = $dcRecords | Select-Object -ExpandProperty NameTarget | Sort-Object -Unique
    Write-Host "`nUnique DC Hostnames:" -ForegroundColor Cyan
    $dcHostnames | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    
} catch {
    Write-Host "✗ Failed to discover domain controllers: $($_.Exception.Message)" -ForegroundColor Red
}

# Kerberos Distribution Center discovery
Write-Host "`nDiscovering Kerberos Distribution Centers..." -ForegroundColor Cyan
try {
    $kdcRecords = Resolve-DnsName -Name "_kerberos._tcp.$domain" -Type SRV -ErrorAction Stop
    
    Write-Host "KDCs Found:" -ForegroundColor Green
    foreach($record in $kdcRecords) {
        Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
        Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ Failed to discover KDCs: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### **Tool 2: PowerView Suite (Comprehensive SRV Discovery)**
```powershell
# Load PowerView
. .\PowerView.ps1

# Comprehensive SRV discovery via PowerView
function Discover-ADServicesViaPowerView {
    param(
        [string]$Domain = "corp.local"
    )
    
    $discoveryResults = @{}
    
    # Get domain information via PowerView
    $domainInfo = Get-Domain
    Write-Host "Domain: $($domainInfo.Name)" -ForegroundColor Cyan
    Write-Host "Domain SID: $($domainInfo.DomainSID)" -ForegroundColor Cyan
    
    # Define SRV services to discover
    $srvServices = @{
        "Domain Controllers" = "_ldap._tcp.dc._msdcs.$Domain"
        "Kerberos KDCs" = "_kerberos._tcp.$Domain"
        "Global Catalogs" = "_ldap._tcp.gc._msdcs.$Domain"
        "Password Change" = "_kpasswd._tcp.$Domain"
        "PDC Emulator" = "_ldap._tcp.pdc._msdcs.$Domain"
        "LDAP Services" = "_ldap._tcp.$Domain"
        "Kerberos Services" = "_kerberos._tcp.$Domain"
    }
    
    foreach($service in $srvServices.Keys) {
        $srvRecord = $srvServices[$service]
        Write-Host "`nDiscovering $service via PowerView..." -ForegroundColor Cyan
        
        try {
            $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
            
            $serviceResults = @()
            foreach($record in $records) {
                $serviceInfo = [PSCustomObject]@{
                    Service = $service
                    Target = $record.NameTarget
                    Port = $record.Port
                    Priority = $record.Priority
                    Weight = $record.Weight
                    TTL = $record.TTL
                    FullRecord = $record
                }
                $serviceResults += $serviceInfo
                
                Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
                Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
                
                # Additional PowerView analysis
                $computer = Get-DomainComputer -Identity $record.NameTarget -Properties name,ipaddress,operatingsystem,site,serviceprincipalname
                if($computer) {
                    Write-Host "    Computer: $($computer.name) - $($computer.ipaddress) - $($computer.operatingsystem)" -ForegroundColor Yellow
                    Write-Host "    Site: $($computer.site)" -ForegroundColor Yellow
                    
                    if($computer.serviceprincipalname) {
                        Write-Host "    SPNs:" -ForegroundColor Yellow
                        $computer.serviceprincipalname | ForEach-Object {
                            Write-Host "      $_" -ForegroundColor Gray
                        }
                    }
                }
            }
            
            $discoveryResults[$service] = $serviceResults
            
        } catch {
            Write-Host "  ✗ No $service records found" -ForegroundColor Red
            $discoveryResults[$service] = @()
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    return $discoveryResults
}

# Use the PowerView SRV discovery function
$powerViewSrvResults = Discover-ADServicesViaPowerView -Domain "corp.local"

# Generate comprehensive PowerView SRV report
Write-Host "`n=== POWERVIEW SRV DISCOVERY REPORT ===" -ForegroundColor Magenta
foreach($service in $powerViewSrvResults.Keys) {
    $records = $powerViewSrvResults[$service]
    Write-Host "`n$service Services:" -ForegroundColor Cyan
    if($records.Count -gt 0) {
        foreach($record in $records) {
            Write-Host "  $($record.Target):$($record.Port)" -ForegroundColor Green
        }
    } else {
        Write-Host "  No services found" -ForegroundColor Red
    }
}

# Cross-reference SRV services with AD computers via PowerView
$allComputers = Get-DomainComputer -Properties name,ipaddress,operatingsystem,site,serviceprincipalname
$srvComputerMapping = @{}

foreach($service in $powerViewSrvResults.Keys) {
    $records = $powerViewSrvResults[$service]
    $srvComputerMapping[$service] = @()
    
    foreach($record in $records) {
        $computer = $allComputers | Where-Object { $_.name -eq $record.Target }
        if($computer) {
            $srvComputerMapping[$service] += @{
                SRVRecord = $record
                Computer = $computer
                Services = $computer.serviceprincipalname
            }
        }
    }
}

# Generate comprehensive SRV-AD mapping report via PowerView
Write-Host "`n=== POWERVIEW SRV-AD COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
foreach($service in $srvComputerMapping.Keys) {
    $mappings = $srvComputerMapping[$service]
    Write-Host "`n$service Mappings:" -ForegroundColor Cyan
    
    if($mappings.Count -gt 0) {
        foreach($mapping in $mappings) {
            $srv = $mapping.SRVRecord
            $computer = $mapping.Computer
            Write-Host "  SRV: $($srv.Target):$($srv.Port)" -ForegroundColor Green
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

#### **Tool 3: Microsoft AD Module (Stealth SRV Discovery)**
```powershell
# Load the module
Import-Module ActiveDirectory

# Comprehensive SRV discovery via Microsoft AD Module
function Discover-ADServicesViaMSAD {
    param(
        [string]$Domain = "corp.local"
    )
    
    $discoveryResults = @{}
    
    # Get domain information via Microsoft AD Module
    $domainInfo = Get-ADDomain
    Write-Host "Domain: $($domainInfo.Name)" -ForegroundColor Cyan
    Write-Host "Domain SID: $($domainInfo.DomainSID)" -ForegroundColor Cyan
    
    # Define SRV services to discover
    $srvServices = @{
        "Domain Controllers" = "_ldap._tcp.dc._msdcs.$Domain"
        "Kerberos KDCs" = "_kerberos._tcp.$Domain"
        "Global Catalogs" = "_ldap._tcp.gc._msdcs.$Domain"
        "Password Change" = "_kpasswd._tcp.$Domain"
        "PDC Emulator" = "_ldap._tcp.pdc._msdcs.$Domain"
        "LDAP Services" = "_ldap._tcp.$Domain"
        "Kerberos Services" = "_kerberos._tcp.$Domain"
    }
    
    foreach($service in $srvServices.Keys) {
        $srvRecord = $srvServices[$service]
        Write-Host "`nDiscovering $service via Microsoft AD Module..." -ForegroundColor Cyan
        
        try {
            $records = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
            
            $serviceResults = @()
            foreach($record in $records) {
                $serviceInfo = [PSCustomObject]@{
                    Service = $service
                    Target = $record.NameTarget
                    Port = $record.Port
                    Priority = $record.Priority
                    Weight = $record.Weight
                    TTL = $record.TTL
                    FullRecord = $record
                }
                $serviceResults += $serviceInfo
                
                Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
                Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
                
                # Additional Microsoft AD Module analysis
                $computer = Get-ADComputer -Identity $record.NameTarget -Properties Name, IPv4Address, OperatingSystem, Site, ServicePrincipalName
                if($computer) {
                    Write-Host "    Computer: $($computer.Name) - $($computer.IPv4Address) - $($computer.OperatingSystem)" -ForegroundColor Yellow
                    Write-Host "    Site: $($computer.Site)" -ForegroundColor Yellow
                    
                    if($computer.ServicePrincipalName) {
                        Write-Host "    SPNs:" -ForegroundColor Yellow
                        $computer.ServicePrincipalName | ForEach-Object {
                            Write-Host "      $_" -ForegroundColor Gray
                        }
                    }
                }
            }
            
            $discoveryResults[$service] = $serviceResults
            
        } catch {
            Write-Host "  ✗ No $service records found" -ForegroundColor Red
            $discoveryResults[$service] = @()
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    return $discoveryResults
}

# Use the Microsoft AD Module SRV discovery function
$msadSrvResults = Discover-ADServicesViaMSAD -Domain "corp.local"

# Generate comprehensive Microsoft AD Module SRV report
Write-Host "`n=== MICROSOFT AD MODULE SRV DISCOVERY REPORT ===" -ForegroundColor Magenta
foreach($service in $msadSrvResults.Keys) {
    $records = $msadSrvResults[$service]
    Write-Host "`n$service Services:" -ForegroundColor Cyan
    if($records.Count -gt 0) {
        foreach($record in $records) {
            Write-Host "  $($record.Target):$($record.Port)" -ForegroundColor Green
        }
    } else {
        Write-Host "  No services found" -ForegroundColor Red
    }
}

# Cross-reference SRV services with AD computers via Microsoft AD Module
$allAdComputers = Get-ADComputer -Filter * -Properties Name, IPv4Address, OperatingSystem, Site, ServicePrincipalName
$msadSrvComputerMapping = @{}

foreach($service in $msadSrvResults.Keys) {
    $records = $msadSrvResults[$service]
    $msadSrvComputerMapping[$service] = @()
    
    foreach($record in $records) {
        $computer = $allAdComputers | Where-Object { $_.Name -eq $record.Target }
        if($computer) {
            $msadSrvComputerMapping[$service] += @{
                SRVRecord = $record
                Computer = $computer
                Services = $computer.ServicePrincipalName
            }
        }
    }
}

# Generate comprehensive SRV-AD mapping report via Microsoft AD Module
Write-Host "`n=== MICROSOFT AD MODULE SRV-AD COMPUTER MAPPING REPORT ===" -ForegroundColor Magenta
foreach($service in $msadSrvComputerMapping.Keys) {
    $mappings = $msadSrvComputerMapping[$service]
    Write-Host "`n$service Mappings:" -ForegroundColor Cyan
    
    if($mappings.Count -gt 0) {
        foreach($mapping in $mappings) {
            $srv = $mapping.SRVRecord
            $computer = $mapping.Computer
            Write-Host "  SRV: $($srv.Target):$($srv.Port)" -ForegroundColor Green
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

#### **Advanced SRV Discovery Integration**
```powershell
# Cross-tool SRV discovery analysis
function Get-CrossToolSRVAnalysis {
    param(
        [hashtable]$NativeResults,
        [hashtable]$PowerViewResults,
        [hashtable]$MSADResults
    )
    
    $crossToolAnalysis = @{
        "Common Services" = @{}
        "Unique PowerView Findings" = @()
        "Unique MSAD Findings" = @()
        "Recommended Next Steps" = @()
    }
    
    # Analyze common services across tools
    Write-Host "Analyzing common services across tools..." -ForegroundColor Cyan
    
    # Find common domain controllers
    $nativeDCs = $NativeResults["Domain Controllers"] | ForEach-Object { $_.NameTarget }
    $powerviewDCs = $PowerViewResults["Domain Controllers"] | ForEach-Object { $_.Target }
    $msadDCs = $MSADResults["Domain Controllers"] | ForEach-Object { $_.Target }
    
    $commonDCs = $nativeDCs | Where-Object { $_ -in $powerviewDCs -and $_ -in $msadDCs }
    foreach($dc in $commonDCs) {
        $crossToolAnalysis["Common Services"]["Domain Controllers"] += $dc
    }
    
    # Find common KDCs
    $nativeKDCs = $NativeResults["Kerberos KDCs"] | ForEach-Object { $_.NameTarget }
    $powerviewKDCs = $PowerViewResults["Kerberos KDCs"] | ForEach-Object { $_.Target }
    $msadKDCs = $MSADResults["Kerberos KDCs"] | ForEach-Object { $_.Target }
    
    $commonKDCs = $nativeKDCs | Where-Object { $_ -in $powerviewKDCs -and $_ -in $msadKDCs }
    foreach($kdc in $commonKDCs) {
        $crossToolAnalysis["Common Services"]["Kerberos KDCs"] += $kdc
    }
    
    # Find unique PowerView findings
    $uniquePowerView = $PowerViewResults.Values | ForEach-Object { $_ } | Where-Object { 
        $_.Target -notin ($NativeResults.Values | ForEach-Object { $_.NameTarget })
    }
    foreach($finding in $uniquePowerView) {
        $crossToolAnalysis["Unique PowerView Findings"] += @{
            Service = $finding.Service
            Target = $finding.Target
            Tool = "PowerView"
        }
    }
    
    # Find unique MSAD findings
    $uniqueMSAD = $MSADResults.Values | ForEach-Object { $_ } | Where-Object { 
        $_.Target -notin ($NativeResults.Values | ForEach-Object { $_.NameTarget })
    }
    foreach($finding in $uniqueMSAD) {
        $crossToolAnalysis["Unique MSAD Findings"] += @{
            Service = $finding.Service
            Target = $finding.Target
            Tool = "Microsoft AD Module"
        }
    }
    
    # Generate recommended next steps
    $crossToolAnalysis["Recommended Next Steps"] = @(
        @{
            Priority = "Immediate"
            Action = "Target common domain controllers"
            Technique = "DC enumeration and analysis"
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

# Use cross-tool SRV analysis
$crossToolSrvAnalysis = Get-CrossToolSRVAnalysis -NativeResults $adSrvTypes -PowerViewResults $powerViewSrvResults -MSADResults $msadSrvResults

# Generate cross-tool SRV analysis report
Write-Host "`n=== CROSS-TOOL SRV ANALYSIS ===" -ForegroundColor Magenta

# Common Services Analysis
Write-Host "`nCommon Services Analysis:" -ForegroundColor Cyan
foreach($service in $crossToolSrvAnalysis["Common Services"].Keys) {
    $targets = $crossToolSrvAnalysis["Common Services"][$service]
    if($targets.Count -gt 0) {
        Write-Host "  $service:" -ForegroundColor Yellow
        foreach($target in $targets) {
            Write-Host "    $target" -ForegroundColor White
        }
    }
}

# Unique Findings Analysis
Write-Host "`nUnique PowerView Findings:" -ForegroundColor Cyan
foreach($finding in $crossToolSrvAnalysis["Unique PowerView Findings"]) {
    Write-Host "  $($finding.Service): $($finding.Target)" -ForegroundColor Yellow
}

Write-Host "`nUnique MSAD Findings:" -ForegroundColor Cyan
foreach($finding in $crossToolSrvAnalysis["Unique MSAD Findings"]) {
    Write-Host "  $($finding.Service): $($finding.Target)" -ForegroundColor Yellow
}

# Recommended Next Steps
Write-Host "`nRecommended Next Steps:" -ForegroundColor Cyan
foreach($step in $crossToolSrvAnalysis["Recommended Next Steps"]) {
    Write-Host "  [$($step.Priority)] $($step.Action)" -ForegroundColor Yellow
    Write-Host "    Technique: $($step.Technique)" -ForegroundColor White
    Write-Host "    Tools: $($step.Tools -join ', ')" -ForegroundColor Gray
}
```

---

## 🌐 **KERBEROS SERVICE DISCOVERY**

### **🔐 Kerberos Distribution Center (KDC) Enumeration**

#### **What is KDC Discovery?**
**KDC Discovery** identifies Kerberos Distribution Centers that handle authentication requests. This is crucial for Kerberos-based attacks and enumeration.

#### **KDC Discovery Techniques**
```powershell
# Basic KDC discovery
$domain = "corp.local"
Write-Host "Discovering Kerberos Distribution Centers for $domain..." -ForegroundColor Cyan

# Method 1: SRV record discovery
try {
    $kdcRecords = Resolve-DnsName -Name "_kerberos._tcp.$domain" -Type SRV -ErrorAction Stop
    Write-Host "`nKDCs via SRV Records:" -ForegroundColor Green
    foreach($record in $kdcRecords) {
        Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
        Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ No KDC SRV records found" -ForegroundColor Red
}

# Method 2: Direct hostname resolution (common patterns)
$commonKdcNames = @("kdc", "kdc01", "kdc02", "dc", "dc01", "dc02", "auth", "auth01")
$discoveredKdcs = @()

foreach($name in $commonKdcNames) {
    $fullName = "$name.$domain"
    try {
        $result = Resolve-DnsName -Name $fullName -Type A -ErrorAction Stop
        $discoveredKdcs += [PSCustomObject]@{
            Name = $name
            FullName = $fullName
            IPAddress = $result.IPAddress
            TTL = $result.TTL
        }
        Write-Host "  ✓ $fullName → $($result.IPAddress)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ $fullName → Not found" -ForegroundColor Gray
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}

# Method 3: Port-based KDC discovery
Write-Host "`nVerifying KDCs via port 88 (Kerberos)..." -ForegroundColor Cyan
$kdcCandidates = $discoveredKdcs | Select-Object -ExpandProperty IPAddress

foreach($ip in $kdcCandidates) {
    $kerberosOpen = Test-NetConnection -ComputerName $ip -Port 88 -InformationLevel Quiet -WarningAction SilentlyContinue
    if($kerberosOpen.TcpTestSucceeded) {
        Write-Host "  ✓ $ip - Port 88 (Kerberos) OPEN" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $ip - Port 88 (Kerberos) CLOSED" -ForegroundColor Red
    }
}
```

#### **Advanced KDC Analysis**
```powershell
# KDC load balancing analysis
function Analyze-KDCLoadBalancing {
    param(
        [string]$Domain = "corp.local"
    )
    
    try {
        $kdcRecords = Resolve-DnsName -Name "_kerberos._tcp.$Domain" -Type SRV -ErrorAction Stop
        
        Write-Host "KDC Load Balancing Analysis for $Domain:" -ForegroundColor Cyan
        
        # Sort by priority and weight
        $sortedKdcs = $kdcRecords | Sort-Object Priority, Weight -Descending
        
        foreach($kdc in $sortedKdcs) {
            $priority = $kdc.Priority
            $weight = $kdc.Weight
            $color = switch($priority) {
                0 { "Green" }    # Highest priority
                1 { "Yellow" }   # Medium priority
                default { "Red" } # Lower priority
            }
            
            Write-Host "  $($kdc.NameTarget):$($kdc.Port)" -ForegroundColor $color
            Write-Host "    Priority: $priority, Weight: $weight" -ForegroundColor Gray
            
            # Test connectivity
            try {
                $pingResult = Test-Connection -ComputerName $kdc.NameTarget -Quiet -Count 1
                $kerberosResult = Test-NetConnection -ComputerName $kdc.NameTarget -Port 88 -InformationLevel Quiet -WarningAction SilentlyContinue
                
                Write-Host "    ICMP: $(if($pingResult){'✓'}else{'✗'})" -ForegroundColor $(if($pingResult){'Green'}else{'Red'})
                Write-Host "    Kerberos: $(if($kerberosResult.TcpTestSucceeded){'✓'}else{'✗'})" -ForegroundColor $(if($kerberosResult.TcpTestSucceeded){'Green'}else{'Red'})
            } catch {
                Write-Host "    Connectivity test failed" -ForegroundColor Red
            }
        }
        
        return $sortedKdcs
        
    } catch {
        Write-Host "✗ Failed to analyze KDC load balancing: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Use the function
$kdcAnalysis = Analyze-KDCLoadBalancing -Domain "corp.local"

# Generate KDC strategy recommendations
if($kdcAnalysis.Count -gt 0) {
    Write-Host "`n=== KDC STRATEGY RECOMMENDATIONS ===" -ForegroundColor Magenta
    
    $primaryKdcs = $kdcAnalysis | Where-Object { $_.Priority -eq 0 }
    $secondaryKdcs = $kdcAnalysis | Where-Object { $_.Priority -gt 0 }
    
    if($primaryKdcs.Count -gt 0) {
        Write-Host "Primary KDCs (Priority 0):" -ForegroundColor Green
        $primaryKdcs | ForEach-Object { Write-Host "  $($_.NameTarget)" -ForegroundColor White }
    }
    
    if($secondaryKdcs.Count -gt 0) {
        Write-Host "Secondary KDCs (Priority > 0):" -ForegroundColor Yellow
        $secondaryKdcs | ForEach-Object { Write-Host "  $($_.NameTarget)" -ForegroundColor White }
    }
}
```

---

## 🌍 **GLOBAL CATALOG DISCOVERY**

### **🔍 Cross-Domain Service Discovery**

#### **What is Global Catalog Discovery?**
**Global Catalog Discovery** identifies servers that provide cross-domain query capabilities. These are crucial for multi-domain environments and forest enumeration.

#### **Global Catalog Discovery Techniques**
```powershell
# Basic Global Catalog discovery
$domain = "corp.local"
Write-Host "Discovering Global Catalogs for $domain..." -ForegroundColor Cyan

# Method 1: SRV record discovery
try {
    $gcRecords = Resolve-DnsName -Name "_ldap._tcp.gc._msdcs.$domain" -Type SRV -ErrorAction Stop
    Write-Host "`nGlobal Catalogs via SRV Records:" -ForegroundColor Green
    foreach($record in $gcRecords) {
        Write-Host "  ✓ $($record.NameTarget):$($record.Port)" -ForegroundColor Green
        Write-Host "    Priority: $($record.Priority), Weight: $($record.Weight)" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ No Global Catalog SRV records found" -ForegroundColor Red
}

# Method 2: Common GC naming patterns
$commonGcNames = @("gc", "gc01", "gc02", "global", "global01", "global02")
$discoveredGcs = @()

foreach($name in $commonGcNames) {
    $fullName = "$name.$domain"
    try {
        $result = Resolve-DnsName -Name $fullName -Type A -ErrorAction Stop
        $discoveredGcs += [PSCustomObject]@{
            Name = $name
            FullName = $fullName
            IPAddress = $result.IPAddress
            TTL = $result.TTL
        }
        Write-Host "  ✓ $fullName → $($result.IPAddress)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ $fullName → Not found" -ForegroundColor Gray
    }
    
    # Stealth delay
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}

# Method 3: Port-based GC verification
Write-Host "`nVerifying Global Catalogs via port 3268 (GC LDAP)..." -ForegroundColor Cyan
$gcCandidates = $discoveredGcs | Select-Object -ExpandProperty IPAddress

foreach($ip in $gcCandidates) {
    $gcLdapOpen = Test-NetConnection -ComputerName $ip -Port 3268 -InformationLevel Quiet -WarningAction SilentlyContinue
    if($gcLdapOpen.TcpTestSucceeded) {
        Write-Host "  ✓ $ip - Port 3268 (GC LDAP) OPEN" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $ip - Port 3268 (GC LDAP) CLOSED" -ForegroundColor Red
    }
}
```

#### **Global Catalog Load Balancing Analysis**
```powershell
# GC load balancing and failover analysis
function Analyze-GCLoadBalancing {
    param(
        [string]$Domain = "corp.local"
    )
    
    try {
        $gcRecords = Resolve-DnsName -Name "_ldap._tcp.gc._msdcs.$Domain" -Type SRV -ErrorAction Stop
        
        Write-Host "Global Catalog Load Balancing Analysis for $Domain:" -ForegroundColor Cyan
        
        # Sort by priority and weight
        $sortedGcs = $gcRecords | Sort-Object Priority, Weight -Descending
        
        foreach($gc in $sortedGcs) {
            $priority = $gc.Priority
            $weight = $gc.Weight
            $color = switch($priority) {
                0 { "Green" }    # Highest priority
                1 { "Yellow" }   # Medium priority
                default { "Red" } # Lower priority
            }
            
            Write-Host "  $($gc.NameTarget):$($gc.Port)" -ForegroundColor $color
            Write-Host "    Priority: $priority, Weight: $weight" -ForegroundColor Gray
            
            # Test connectivity
            try {
                $pingResult = Test-Connection -ComputerName $gc.NameTarget -Quiet -Count 1
                $gcLdapResult = Test-NetConnection -ComputerName $gc.NameTarget -Port 3268 -InformationLevel Quiet -WarningAction SilentlyContinue
                
                Write-Host "    ICMP: $(if($pingResult){'✓'}else{'✗'})" -ForegroundColor $(if($pingResult){'Green'}else{'Red'})
                Write-Host "    GC LDAP: $(if($gcLdapResult.TcpTestSucceeded){'✓'}else{'✗'})" -ForegroundColor $(if($gcLdapResult.TcpTestSucceeded){'Green'}else{'Red'})
            } catch {
                Write-Host "    Connectivity test failed" -ForegroundColor Red
            }
        }
        
        return $sortedGcs
        
    } catch {
        Write-Host "✗ Failed to analyze GC load balancing: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Use the function
$gcAnalysis = Analyze-GCLoadBalancing -Domain "corp.local"

# Generate GC strategy recommendations
if($gcAnalysis.Count -gt 0) {
    Write-Host "`n=== GLOBAL CATALOG STRATEGY RECOMMENDATIONS ===" -ForegroundColor Magenta
    
    $primaryGcs = $gcAnalysis | Where-Object { $_.Priority -eq 0 }
    $secondaryGcs = $gcAnalysis | Where-Object { $_.Priority -gt 0 }
    
    if($primaryGcs.Count -gt 0) {
        Write-Host "Primary Global Catalogs (Priority 0):" -ForegroundColor Green
        $primaryGcs | ForEach-Object { Write-Host "  $($_.NameTarget)" -ForegroundColor White }
    }
    
    if($secondaryGcs.Count -gt 0) {
        Write-Host "Secondary Global Catalogs (Priority > 0):" -ForegroundColor Yellow
        $secondaryGcs | ForEach-Object { Write-Host "  $($_.NameTarget)" -ForegroundColor White }
    }
}
```

---

## 🗺️ **ZONE INFORMATION DISCOVERY**

### **🌐 DNS Zone Structure Analysis**

#### **What is Zone Information Discovery?**
**Zone Information Discovery** reveals the DNS zone structure, which can provide insights into network topology, subdomains, and organizational structure.

#### **Zone Transfer Attempts**
```powershell
# Zone transfer attempt (high visibility - use only when authorized)
$domain = "corp.local"
Write-Host "Attempting zone transfer for $domain (AUTHORIZED TESTING ONLY)..." -ForegroundColor Red

# Method 1: nslookup zone transfer
try {
    Write-Host "`nZone transfer via nslookup:" -ForegroundColor Cyan
    $zoneTransfer = nslookup -type=any $domain 2>$null
    
    if($zoneTransfer -match "zone transfer failed") {
        Write-Host "  ✗ Zone transfer blocked (expected)" -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ Zone transfer successful (UNEXPECTED - investigate!)" -ForegroundColor Red
        $zoneTransfer | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    }
} catch {
    Write-Host "  ✗ Zone transfer failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 2: dig zone transfer (if available)
try {
    Write-Host "`nZone transfer via dig:" -ForegroundColor Cyan
    $digResult = dig @$domain AXFR 2>$null
    
    if($digResult -match "Transfer failed") {
        Write-Host "  ✗ Zone transfer blocked (expected)" -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ Zone transfer successful (UNEXPECTED - investigate!)" -ForegroundColor Red
        $digResult | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    }
} catch {
    Write-Host "  ✗ Zone transfer failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### **DNS Zone Enumeration**
```powershell
# DNS zone enumeration via iterative queries
function Enumerate-DNSZone {
    param(
        [string]$Domain = "corp.local",
        [string[]]$CommonSubdomains = @("www", "mail", "ftp", "admin", "dc", "dc01", "dc02", "sql", "web", "app", "test", "dev", "staging", "prod")
    )
    
    Write-Host "Enumerating DNS zone for $domain..." -ForegroundColor Cyan
    $discoveredRecords = @()
    
    foreach($sub in $CommonSubdomains) {
        $fullDomain = "$sub.$Domain"
        
        try {
            # Try A record first
            $aRecord = Resolve-DnsName -Name $fullDomain -Type A -ErrorAction Stop
            $discoveredRecords += [PSCustomObject]@{
                Subdomain = $sub
                FullDomain = $fullDomain
                RecordType = "A"
                Value = $aRecord.IPAddress
                TTL = $aRecord.TTL
            }
            Write-Host "  ✓ $fullDomain (A) → $($aRecord.IPAddress)" -ForegroundColor Green
            
        } catch {
            try {
                # Try CNAME record
                $cnameRecord = Resolve-DnsName -Name $fullDomain -Type CNAME -ErrorAction Stop
                $discoveredRecords += [PSCustomObject]@{
                    Subdomain = $sub
                    FullDomain = $fullDomain
                    RecordType = "CNAME"
                    Value = $cnameRecord.NameHost
                    TTL = $cnameRecord.TTL
                }
                Write-Host "  ✓ $fullDomain (CNAME) → $($cnameRecord.NameHost)" -ForegroundColor Green
                
            } catch {
                Write-Host "  ✗ $fullDomain → Not found" -ForegroundColor Gray
            }
        }
        
        # Stealth delay
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
    }
    
    return $discoveredRecords
}

# Use the function
$zoneRecords = Enumerate-DNSZone -Domain "corp.local"

# Generate zone enumeration report
if($zoneRecords.Count -gt 0) {
    Write-Host "`n=== DNS ZONE ENUMERATION REPORT ===" -ForegroundColor Magenta
    $zoneRecords | Format-Table -AutoSize
} else {
    Write-Host "`nNo additional DNS records discovered." -ForegroundColor Yellow
}
```

---

## 🔄 **FINDINGS → PIVOTS (DNS DISCOVERY FLOW)**

### **🎯 Strategic Pivot Planning**

#### **What are DNS Pivots?**
**DNS Pivots** are strategic next steps based on DNS discovery findings. Each discovered service or host leads to specific enumeration techniques.

#### **Service-Based Pivot Matrix**
```powershell
# Define DNS-based pivot matrix
$dnsPivotMatrix = @{
    "Domain Controllers" = @{
        PivotTo = "04_Domain_Enumeration.md"
        Technique = "Domain object enumeration"
        Commands = @("Get-Domain", "Get-DomainUser", "Get-DomainGroup")
        Priority = "High"
    }
    "Global Catalogs" = @{
        PivotTo = "30_Forest_Enumeration.md"
        Technique = "Cross-domain enumeration"
        Commands = @("Get-ForestDomain", "Get-ForestGlobalCatalog")
        Priority = "Medium"
    }
    "Kerberos Services" = @{
        PivotTo = "23_Kerberos_Basic_Enumeration.md"
        Technique = "Kerberos enumeration and attacks"
        Commands = @("Get-DomainUser -SPN", "Invoke-Kerberoast")
        Priority = "High"
    }
    "SQL Services" = @{
        PivotTo = "28_SQL_Server_Enumeration.md"
        Technique = "SQL Server enumeration"
        Commands = @("Get-SQLInstance", "Get-SQLDatabase")
        Priority = "Medium"
    }
    "Web Services" = @{
        PivotTo = "Web_Enumeration.md"
        Technique = "Web application enumeration"
        Commands = @("Test-WebConnection", "Get-WebApplication")
        Priority = "Low"
    }
}

# Generate DNS pivot recommendations
function Get-DNSPivotRecommendations {
    param(
        [hashtable]$DnsResults
    )
    
    Write-Host "`n=== DNS PIVOT RECOMMENDATIONS ===" -ForegroundColor Magenta
    
    foreach($service in $DnsResults.Keys) {
        $records = $DnsResults[$service]
        if($records.Count -gt 0) {
            $pivot = $dnsPivotMatrix[$service]
            if($pivot) {
                $priority = $pivot.Priority
                $color = switch($priority) {
                    "High" { "Red" }
                    "Medium" { "Yellow" }
                    "Low" { "Green" }
                    default { "White" }
                }
                
                Write-Host "`n$service ($priority priority):" -ForegroundColor $color
                Write-Host "  → Pivot to: $($pivot.PivotTo)" -ForegroundColor Yellow
                Write-Host "  → Technique: $($pivot.Technique)" -ForegroundColor White
                Write-Host "  → Commands: $($pivot.Commands -join ', ')" -ForegroundColor Gray
                Write-Host "  → Discovered: $($records.Count) services" -ForegroundColor Cyan
            }
        }
    }
}

# Example usage with our SRV results
Get-DNSPivotRecommendations -DnsResults $srvResults
```

---

## 🚨 **DETECTION & OPSEC**

### **👁️ DNS Discovery Detection Vectors**
```powershell
# Event IDs to monitor for DNS discovery
$dnsDetectionEvents = @(
    "8003",  # DNS query
    "8004",  # DNS response
    "8005",  # DNS query failure
    "8006",  # DNS response failure
    "4624",  # Logon (successful authentication)
    "4625",  # Logon (failed authentication)
    "4688",  # Process creation
    "5140",  # Network share access
    "5156",  # Filtering platform connection
    "5157"   # Filtering platform bind
)

Write-Host "Monitor these Event IDs for DNS discovery detection:" -ForegroundColor Red
$dnsDetectionEvents | ForEach-Object { Write-Host "  Event ID: $_" -ForegroundColor White }
```

### **🕵️ OPSEC Best Practices for DNS Discovery**

> **🔒 STEALTH REQUIREMENT**: **Invisi-Shell** must be loaded before any DNS discovery in production environments to bypass logging and AMSI detection. This is non-negotiable for operational security.

```powershell
# OPSEC Profile 1: Stealth (Production)
$dnsStealthProfile = @{
    UseNativeTools = $true
    UseInvisiShell = $true
    DelayRange = @(2, 5)
    JitterPattern = "Random"
    QueryTypes = @("SRV only")
    Resolver = "Local DC only"
    ZoneTransfer = "Never"
    SubdomainEnumeration = "Minimal"
}

# OPSEC Profile 2: Balanced (Lab)
$dnsBalancedProfile = @{
    UseNativeTools = $false
    DelayRange = @(1, 2)
    JitterPattern = "Random"
    QueryTypes = @("SRV", "A", "CNAME")
    Resolver = "DC + secondary"
    ZoneTransfer = "When authorized"
    SubdomainEnumeration = "Common patterns"
}

# OPSEC Profile 3: Noisy (Internal Lab)
$dnsNoisyProfile = @{
    UseNativeTools = $false
    DelayRange = @(200, 500)
    JitterPattern = "Fixed"
    QueryTypes = @("SRV", "A", "CNAME", "MX", "TXT", "NS")
    Resolver = "Any available"
    ZoneTransfer = "When authorized"
    SubdomainEnumeration = "Comprehensive"
}

# Apply OPSEC profile
$currentDnsProfile = if($env:COMPUTERNAME -like "*PROD*") {$dnsStealthProfile} elseif($env:COMPUTERNAME -like "*LAB*") {$dnsNoisyProfile} else {$dnsBalancedProfile}

Write-Host "Current DNS OPSEC Profile:" -ForegroundColor Cyan
$currentDnsProfile.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor White
}
```

---

## 🧹 **CLEANUP & MAINTENANCE**

### **🗑️ DNS Discovery Cleanup**
```powershell
# Clear DNS discovery artifacts
Write-Host "Cleaning up DNS discovery artifacts..." -ForegroundColor Cyan

# Clear DNS cache
Clear-DnsClientCache
Write-Host "  ✓ DNS cache cleared" -ForegroundColor Green

# Clear DNS resolver cache
ipconfig /flushdns
Write-Host "  ✓ DNS resolver cache cleared" -ForegroundColor Green

# Clear temporary files
Remove-Item "$env:TEMP\dns_scan_*" -Force -ErrorAction SilentlyContinue
Write-Host "  ✓ Temporary files cleared" -ForegroundColor Green

# Clear DNS query logs (if any)
Get-EventLog -LogName "DNS Server" -Newest 100 | Where-Object {$_.Message -like "*query*"} | ForEach-Object {
    Remove-EventLog -LogName "DNS Server" -InstanceId $_.InstanceId -ErrorAction SilentlyContinue
}
Write-Host "  ✓ DNS query logs cleared" -ForegroundColor Green

# Clear Invisi-Shell artifacts (if used)
if($env:INVISI_SHELL_ACTIVE -eq $true) {
    Write-Host "Cleaning up Invisi-Shell artifacts..." -ForegroundColor Cyan
    Remove-Item "$env:TEMP\InvisiShell*" -Force -ErrorAction SilentlyContinue
    $env:INVISI_SHELL_ACTIVE = $false
    Write-Host "  ✓ Invisi-Shell artifacts cleared" -ForegroundColor Green
}

Write-Host "DNS discovery cleanup completed." -ForegroundColor Green
```

---

## 🔗 **COMPREHENSIVE CROSS-REFERENCES**

### **📋 TECHNIQUE REFERENCES**
- **Domain Enumeration**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md) - Next step after DNS discovery
- **Kerberos Enumeration**: [23_Kerberos_Basic_Enumeration.md](./23_Kerberos_Basic_Enumeration.md) - After discovering KDC services
- **Forest Enumeration**: [30_Forest_Enumeration.md](./30_Forest_Enumeration.md) - After discovering global catalogs
- **SQL Server Enumeration**: [28_SQL_Server_Enumeration.md](./28_SQL_Server_Enumeration.md) - After discovering SQL services
- **Network Enumeration**: [02_Network_Enumeration.md](./02_Network_Enumeration.md) - Previous step for network discovery

### **🛠️ TOOL REFERENCES**
- **Tool Arsenal**: [01_Tool_Setup_Loading.md#invisi-shell-complete-setup](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup) - Tools used for DNS discovery
- **Invisi-Shell Setup**: [01_Tool_Setup_Loading.md#invisi-shell-complete-setup](./01_Tool_Setup_Loading.md#invisi-shell-complete-setup) - Critical for stealth operations
- **Methodology Hub**: [00_Methodology_Hub.md](./00_Methodology_Hub.md) - Overall enumeration strategy

---

## 🎯 **NAVIGATION & NEXT STEPS**

**🔄 [Back to Master Index](./00_Enumeration_Index.md)** | **🌐 [Previous: Network Enumeration](./02_Network_Enumeration.md)** | **🏛️ [Next: Domain Enumeration](./04_Domain_Enumeration.md)** | **🔐 [Kerberos Master Index](./22_Kerberos_Master_Index.md)**

---

**🎯 DNS enumeration reveals the service infrastructure for Active Directory. Discover domain controllers, global catalogs, and service locations to plan your AD enumeration strategy.**