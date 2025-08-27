# 🌐 Network Enumeration - Foundation for Active Directory Discovery

> **🎯 PURPOSE**: Network discovery foundation for AD enumeration. Map networks, discover services, identify attack surface.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🛠️ Previous: Tool Arsenal](./01_Tool_Setup_Loading.md) | [Next: DNS Enumeration](./03_DNS_Enumeration.md)

---

## 🔗 **RELATED AD COMPONENTS**
- **[Domain Controllers](../02_Active_Directory_Components/02_Domain_Controllers.md)**: Primary targets
- **[Sites and Subnets](../02_Active_Directory_Components/06_Sites_and_Subnets.md)**: Network topology
- **[LDAP and Ports](../02_Active_Directory_Components/13_LDAP_and_Ports.md)**: Communication protocols

---

## ⚡ **QUICK START**

### **Immediate Commands**
```powershell
# Basic connectivity
Test-Connection -ComputerName "dc01.corp.local"

# Service ports
Test-NetConnection -ComputerName "dc01.corp.local" -Port 88,389,445

# Subnet scan
1..254 | % { Test-Connection "192.168.1.$_" -Quiet }

# Network topology
netstat -an | findstr LISTENING
```

---

## 🎯 **DISCOVERY PHASES**

### **Phase 1: Network Mapping**
- **Subnet Discovery**: Identify network ranges and boundaries
- **Host Discovery**: Find alive hosts using ICMP/TCP
- **Topology Mapping**: Understand network architecture

### **Phase 2: Service Enumeration**
- **Port Scanning**: Identify open ports and services
- **Service Discovery**: Map running services and versions
- **Protocol Analysis**: Understand communication patterns

### **Phase 3: AD Infrastructure**
- **DC Discovery**: Locate domain controllers
- **Service Mapping**: Identify AD services (LDAP, Kerberos, DNS)
- **Pivot Planning**: Plan next enumeration steps

---

## 🛠️ **TOOLS & TECHNIQUES**

### **Native Windows Tools (Stealth)**
```powershell
# Host discovery
Test-Connection -ComputerName "target" -Quiet

# Port testing
Test-NetConnection -ComputerName "target" -Port 445

# Network info
Get-NetIPAddress
Get-NetRoute
```

### **PowerShell Modules (Enhanced)**
```powershell
# Microsoft AD Module
Get-ADDomainController -Discover

# Network scanning
1..254 | ForEach-Object { 
    if(Test-Connection "192.168.1.$_" -Quiet -Count 1) { 
        "192.168.1.$_ is alive" 
    } 
}
```

### **Advanced Enumeration (If Permitted)**
```powershell
# PowerView
Get-NetDomain
Get-NetDomainController

# Custom scanning
$subnets = @("192.168.1.0/24", "10.0.0.0/24")
foreach($subnet in $subnets) {
    Invoke-IPScan -Subnet $subnet
}
```

---

## 🔍 **ENUMERATION WORKFLOW**

### **Step 1: Initial Reconnaissance**
```powershell
# Environment detection
$env = if($env:COMPUTERNAME -like "*PROD*") { "Production" } else { "Lab" }
Write-Host "Environment: $env" -ForegroundColor Yellow

# Basic network info
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
```

### **Step 2: Target Discovery**
```powershell
# Find domain controllers
$domain = $env:USERDOMAIN
$dcs = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$domain" -Type SRV

# Scan DC ports
foreach($dc in $dcs) {
    Test-NetConnection -ComputerName $dc.Name -Port 389,445,88
}
```

### **Step 3: Service Mapping**
```powershell
# Common AD ports
$ports = @(53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269)

foreach($port in $ports) {
    Test-NetConnection -ComputerName "dc01.$domain" -Port $port
}
```

---

## 📊 **OUTPUT ANALYSIS**

### **Network Map Structure**
```
Network: 192.168.1.0/24
├── DC01 (192.168.1.10) - Ports: 389, 445, 88
├── DC02 (192.168.1.11) - Ports: 389, 445, 88
├── File Server (192.168.1.20) - Ports: 445, 139
└── Workstations (192.168.1.100-200)
```

### **Service Matrix**
| Host | IP | LDAP | SMB | Kerberos | DNS |
|------|----|------|-----|----------|-----|
| DC01 | 192.168.1.10 | ✅ | ✅ | ✅ | ✅ |
| DC02 | 192.168.1.11 | ✅ | ✅ | ✅ | ❌ |

---

## 🚨 **OPSEC CONSIDERATIONS**

### **Production Environment**
- Use native Windows tools only
- Implement delays between requests
- Avoid aggressive scanning
- Monitor for detection

### **Lab Environment**
- Full enumeration allowed
- Test all tools and techniques
- Document findings thoroughly

---

## 🔄 **NEXT STEPS**
- **[DNS Enumeration](./03_DNS_Enumeration.md)**: Discover AD services via DNS
- **[Domain Enumeration](./04_Domain_Enumeration.md)**: Map domain structure
- **[Tool Arsenal](./01_Tool_Setup_Loading.md)**: Load advanced tools

---

**Tags**: #NetworkEnumeration #ADDiscovery #NetworkMapping #ServiceDiscovery

