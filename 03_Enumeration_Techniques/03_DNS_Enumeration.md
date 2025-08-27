# 🔍 DNS Enumeration - Service Discovery for Active Directory

> **🎯 PURPOSE**: DNS service discovery foundation for AD enumeration. Discover DCs, Global Catalogs, and service locations.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🌐 Previous: Network Enumeration](./02_Network_Enumeration.md) | [Next: Domain Enumeration](./04_Domain_Enumeration.md)

---

## 🔗 **RELATED AD COMPONENTS**
- **[Domain Controllers](../02_Active_Directory_Components/02_Domain_Controllers.md)**: Discovered via SRV records
- **[Global Catalog](../02_Active_Directory_Components/12_Global_Catalog.md)**: Located via DNS SRV records
- **[LDAP and Ports](../02_Active_Directory_Components/13_LDAP_and_Ports.md)**: Service locations revealed

---

## ⚡ **QUICK START**

### **Immediate Commands**
```powershell
# Domain resolution
Resolve-DnsName "corp.local"

# DC discovery
Resolve-DnsName _ldap._tcp.dc._msdcs.corp.local -Type SRV

# KDC discovery
Resolve-DnsName _kerberos._tcp.corp.local -Type SRV

# GC discovery
Resolve-DnsName _ldap._tcp.gc._msdcs.corp.local -Type SRV
```

---

## 🎯 **DNS DISCOVERY TARGETS**

### **Active Directory Services**
- **Domain Controllers**: `_ldap._tcp.dc._msdcs.domain`
- **Global Catalog**: `_ldap._tcp.gc._msdcs.domain`
- **Kerberos KDC**: `_kerberos._tcp.domain`
- **LDAP Services**: `_ldap._tcp.domain`

### **Additional Services**
- **DFS**: `_dfs._tcp.domain`
- **Exchange**: `_autodiscover._tcp.domain`
- **SQL Server**: `_sql._tcp.domain`
- **File Shares**: `_smb._tcp.domain`

---

## 🛠️ **ENUMERATION TECHNIQUES**

### **Native Windows DNS Tools**
```powershell
# Basic DNS queries
nslookup corp.local
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

# PowerShell DNS cmdlets
Resolve-DnsName -Name "corp.local" -Type A
Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.corp.local" -Type SRV
```

### **Advanced DNS Enumeration**
```powershell
# Enumerate all SRV records
$srvTypes = @("_ldap", "_kerberos", "_kpasswd", "_gc", "_dfs")
foreach($type in $srvTypes) {
    try {
        Resolve-DnsName -Name "$type._tcp.corp.local" -Type SRV
    } catch {
        Write-Host "No $type records found" -ForegroundColor Yellow
    }
}

# Zone transfer (if authorized)
$dnsServers = Resolve-DnsName -Name "corp.local" -Type NS
foreach($server in $dnsServers) {
    try {
        Resolve-DnsName -Name "corp.local" -Type AXFR -Server $server.Name
    } catch {
        Write-Host "Zone transfer not allowed on $($server.Name)" -ForegroundColor Red
    }
}
```

---

## 🔍 **ENUMERATION WORKFLOW**

### **Step 1: Domain Information**
```powershell
# Get domain details
$domain = $env:USERDOMAIN
Write-Host "Current Domain: $domain" -ForegroundColor Green

# Resolve domain
$domainInfo = Resolve-DnsName -Name $domain -Type A
$domainInfo
```

### **Step 2: Service Discovery**
```powershell
# Find domain controllers
$dcs = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$domain" -Type SRV
Write-Host "Found $($dcs.Count) Domain Controllers:" -ForegroundColor Green
$dcs | Format-Table -AutoSize

# Find global catalog
$gc = Resolve-DnsName -Name "_ldap._tcp.gc._msdcs.$domain" -Type SRV
Write-Host "Global Catalog Servers:" -ForegroundColor Green
$gc | Format-Table -AutoSize
```

### **Step 3: Service Mapping**
```powershell
# Map all AD services
$services = @{
    "Domain Controllers" = "_ldap._tcp.dc._msdcs.$domain"
    "Global Catalog" = "_ldap._tcp.gc._msdcs.$domain"
    "Kerberos KDC" = "_kerberos._tcp.$domain"
    "LDAP" = "_ldap._tcp.$domain"
    "Kpasswd" = "_kpasswd._tcp.$domain"
}

foreach($service in $services.GetEnumerator()) {
    try {
        $records = Resolve-DnsName -Name $service.Value -Type SRV
        Write-Host "$($service.Key): $($records.Count) records" -ForegroundColor Green
        $records | Format-Table -AutoSize
    } catch {
        Write-Host "$($service.Key): No records found" -ForegroundColor Yellow
    }
}
```

---

## 📊 **OUTPUT ANALYSIS**

### **Service Discovery Matrix**
| Service | SRV Record | Count | Priority | Weight | Port |
|---------|------------|-------|----------|--------|------|
| Domain Controllers | `_ldap._tcp.dc._msdcs` | 2 | 0 | 100 | 389 |
| Global Catalog | `_ldap._tcp.gc._msdcs` | 1 | 0 | 100 | 3268 |
| Kerberos KDC | `_kerberos._tcp` | 2 | 0 | 100 | 88 |

### **Network Topology Insights**
```
Domain: corp.local
├── DC01.corp.local (192.168.1.10) - Priority: 0, Weight: 100
├── DC02.corp.local (192.168.1.11) - Priority: 0, Weight: 100
└── GC01.corp.local (192.168.1.10) - Priority: 0, Weight: 100
```

---

## 🚨 **OPSEC CONSIDERATIONS**

### **Stealth Operations**
- Use native DNS tools
- Implement query delays
- Avoid aggressive enumeration
- Monitor for detection

### **Production vs Lab**
- **Production**: Minimal queries, focus on essential services
- **Lab**: Comprehensive enumeration, test all techniques

---

## 🔄 **NEXT STEPS**
- **[Domain Enumeration](./04_Domain_Enumeration.md)**: Map domain structure using discovered DCs
- **[User Enumeration](./05_User_Enumeration.md)**: Enumerate users via discovered services
- **[Tool Arsenal](./01_Tool_Setup_Loading.md)**: Load advanced enumeration tools

---

**Tags**: #DNSEnumeration #ServiceDiscovery #ADInfrastructure #SRVRecords