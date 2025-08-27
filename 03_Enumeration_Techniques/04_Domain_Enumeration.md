# 🏠 Domain Enumeration - Active Directory Structure Discovery

> **🎯 PURPOSE**: Map Active Directory domain structure, discover OUs, policies, and administrative boundaries.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🔍 Previous: DNS Enumeration](./03_DNS_Enumeration.md) | [Next: User Enumeration](./05_User_Enumeration.md)

---

## 🔗 **RELATED AD COMPONENTS**
- **[Domain](../02_Active_Directory_Components/03_Domain.md)**: Primary target for structure discovery
- **[Domain Controllers](../02_Active_Directory_Components/02_Domain_Controllers.md)**: Infrastructure servers
- **[Organizational Units](../02_Active_Directory_Components/05_Organizational_Unit.md)**: OU hierarchy and structure

---

## ⚡ **QUICK START**

### **Immediate Commands**
```powershell
# Get domain info
Get-ADDomain

# Get domain controllers
Get-ADDomainController

# Get OUs
Get-ADOrganizationalUnit -Filter *

# Get domain trusts
Get-ADTrust -Filter *
```

---

## 🎯 **DOMAIN DISCOVERY TARGETS**

### **Core Domain Information**
- **Domain Name**: FQDN and NetBIOS name
- **Domain SID**: Security identifier
- **Domain Mode**: Functional level
- **Domain Controllers**: Infrastructure servers

### **Organizational Structure**
- **Organizational Units**: OU hierarchy and nesting
- **Group Policy**: Linked GPOs and inheritance
- **Administrative Delegation**: Delegated permissions

### **Trust Relationships**
- **Internal Trusts**: Parent-child domain relationships
- **External Trusts**: Cross-forest relationships
- **Trust Direction**: One-way vs two-way trusts

---

## 🛠️ **ENUMERATION TECHNIQUES**

### **Microsoft AD Module (Native)**
```powershell
# Domain information
$domain = Get-ADDomain
Write-Host "Domain: $($domain.Name)" -ForegroundColor Green
Write-Host "NetBIOS: $($domain.NetBIOSName)" -ForegroundColor Green
Write-Host "Mode: $($domain.DomainMode)" -ForegroundColor Green

# Domain controllers
$dcs = Get-ADDomainController -Filter *
Write-Host "Found $($dcs.Count) Domain Controllers:" -ForegroundColor Green
$dcs | Format-Table Name, Site, OperatingSystem -AutoSize
```

### **PowerView (Advanced)**
```powershell
# Load PowerView
. .\PowerView.ps1

# Domain enumeration
Get-NetDomain
Get-NetDomainController
Get-NetOU
Get-NetGPO
Get-NetTrust
```

### **Custom Enumeration**
```powershell
# OU structure mapping
function Get-OUStructure {
    param($SearchBase = (Get-ADDomain).DistinguishedName)
    
    $ous = Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties Description
    foreach($ou in $ous) {
        $level = ($ou.DistinguishedName.Split(',').Count - 2)
        $indent = "  " * $level
        Write-Host "$indent├─ $($ou.Name)" -ForegroundColor Green
        if($ou.Description) {
            Write-Host "$indent   Description: $($ou.Description)" -ForegroundColor Gray
        }
    }
}

Get-OUStructure
```

---

## 🔍 **ENUMERATION WORKFLOW**

### **Step 1: Domain Overview**
```powershell
# Basic domain information
$domain = Get-ADDomain
$dcs = Get-ADDomainController -Filter *

Write-Host "=== DOMAIN OVERVIEW ===" -ForegroundColor Cyan
Write-Host "Domain: $($domain.Name)" -ForegroundColor White
Write-Host "NetBIOS: $($domain.NetBIOSName)" -ForegroundColor White
Write-Host "Mode: $($domain.DomainMode)" -ForegroundColor White
Write-Host "Controllers: $($dcs.Count)" -ForegroundColor White
```

### **Step 2: OU Structure Analysis**
```powershell
# Map OU hierarchy
Write-Host "`n=== OU STRUCTURE ===" -ForegroundColor Cyan
$ous = Get-ADOrganizationalUnit -Filter * -Properties Description | Sort-Object DistinguishedName

foreach($ou in $ous) {
    $depth = ($ou.DistinguishedName.Split(',').Count - 2)
    $indent = "  " * $depth
    Write-Host "$indent├─ $($ou.Name)" -ForegroundColor Green
    
    # Get linked GPOs
    $gpos = Get-ADOrganizationalUnit -Identity $ou.DistinguishedName -Properties gPLink
    if($gpos.gPLink) {
        Write-Host "$indent   GPOs: $($gpos.gPLink)" -ForegroundColor Yellow
    }
}
```

### **Step 3: Trust Analysis**
```powershell
# Analyze trust relationships
Write-Host "`n=== TRUST RELATIONSHIPS ===" -ForegroundColor Cyan
$trusts = Get-ADTrust -Filter *

foreach($trust in $trusts) {
    Write-Host "Trust: $($trust.Name)" -ForegroundColor Green
    Write-Host "  Direction: $($trust.TrustDirection)" -ForegroundColor White
    Write-Host "  Type: $($trust.TrustType)" -ForegroundColor White
    Write-Host "  Status: $($trust.TrustStatus)" -ForegroundColor White
}
```

---

## 📊 **OUTPUT ANALYSIS**

### **Domain Structure Map**
```
Domain: corp.local
├── Users
│   ├── Administrators
│   ├── Service Accounts
│   └── Regular Users
├── Computers
│   ├── Workstations
│   └── Servers
└── Groups
    ├── Security Groups
    └── Distribution Groups
```

### **Trust Relationship Matrix**
| Trust Name | Direction | Type | Status | Target Domain |
|------------|-----------|------|--------|---------------|
| corp.local | Bidirectional | ParentChild | OK | parent.corp.local |
| external.com | Outbound | External | OK | external.com |

---

## 🚨 **OPSEC CONSIDERATIONS**

### **Stealth Operations**
- Use native AD cmdlets
- Implement query delays
- Focus on essential information
- Avoid aggressive enumeration

### **Production vs Lab**
- **Production**: Minimal queries, focus on structure
- **Lab**: Comprehensive enumeration, test all techniques

---

## 🔄 **NEXT STEPS**
- **[User Enumeration](./05_User_Enumeration.md)**: Enumerate users within discovered OUs
- **[Group Enumeration](./06_Group_Enumeration.md)**: Discover group memberships and permissions
- **[GPO Enumeration](./08_GPO_Enumeration.md)**: Analyze linked Group Policy Objects

---

**Tags**: #DomainEnumeration #ADStructure #OUHierarchy #TrustRelationships
