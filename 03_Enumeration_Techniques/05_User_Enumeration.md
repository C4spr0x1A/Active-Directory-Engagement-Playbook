# 👤 User Enumeration - Active Directory Identity Discovery

> **🎯 PURPOSE**: Discover and analyze user accounts, service accounts, and authentication principals for privilege escalation.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [🏠 Previous: Domain Enumeration](./04_Domain_Enumeration.md) | [Next: Group Enumeration](./06_Group_Enumeration.md)

---

## 🔗 **RELATED AD COMPONENTS**
- **[User Accounts](../02_Active_Directory_Components/17_User_Accounts.md)**: Primary target for enumeration
- **[Kerberos](../02_Active_Directory_Components/16_Kerberos.md)**: Authentication protocol
- **[Organizational Units](../02_Active_Directory_Components/05_Organizational_Unit.md)**: OU structure containing users

---

## ⚡ **QUICK START**

### **Immediate Commands**
```powershell
# Get all users
Get-ADUser -Filter *

# Get specific user
Get-ADUser -Identity "admin" -Properties *

# Get users by OU
Get-ADUser -SearchBase "OU=Users,DC=corp,DC=local" -Filter *

# Get service accounts
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```

---

## 🎯 **USER DISCOVERY TARGETS**

### **Account Types**
- **Regular Users**: Standard user accounts
- **Service Accounts**: Service principals with SPNs
- **Administrative Accounts**: Privileged users
- **Guest Accounts**: Guest and temporary access

### **Account Properties**
- **Authentication**: Password policies and lockout settings
- **Memberships**: Group memberships and roles
- **Permissions**: Direct and inherited permissions
- **Last Activity**: Login times and password changes

### **Security Indicators**
- **Password Age**: Last password change
- **Account Status**: Enabled/disabled, locked/unlocked
- **Logon Restrictions**: Time restrictions and allowed computers
- **Smart Card**: Smart card requirements

---

## 🛠️ **ENUMERATION TECHNIQUES**

### **Microsoft AD Module (Native)**
```powershell
# Basic user enumeration
$users = Get-ADUser -Filter * -Properties DisplayName, EmailAddress, LastLogonDate, PasswordLastSet
$users | Format-Table SamAccountName, DisplayName, EmailAddress, LastLogonDate, PasswordLastSet -AutoSize

# Service account discovery
$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
Write-Host "Found $($serviceAccounts.Count) service accounts:" -ForegroundColor Green
$serviceAccounts | Format-Table SamAccountName, ServicePrincipalName -AutoSize
```

### **PowerView (Advanced)**
```powershell
# Load PowerView
. .\PowerView.ps1

# User enumeration
Get-NetUser
Get-NetUser -SPN
Get-NetUser -AdminCount
Get-NetUser -PreauthNotRequired
```

### **Custom Enumeration**
```powershell
# Privileged user discovery
function Find-PrivilegedUsers {
    $privilegedUsers = @()
    
    # Domain Admins
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive
    $privilegedUsers += $domainAdmins | ForEach-Object { [PSCustomObject]@{Type="Domain Admin"; User=$_.SamAccountName; Group="Domain Admins"} }
    
    # Enterprise Admins
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive
    $privilegedUsers += $enterpriseAdmins | ForEach-Object { [PSCustomObject]@{Type="Enterprise Admin"; User=$_.SamAccountName; Group="Enterprise Admins"} }
    
    # Users with adminCount=1
    $adminCountUsers = Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount
    $privilegedUsers += $adminCountUsers | ForEach-Object { [PSCustomObject]@{Type="Admin Count"; User=$_.SamAccountName; Group="adminCount=1"} }
    
    return $privilegedUsers
}

$privileged = Find-PrivilegedUsers
$privileged | Format-Table -AutoSize
```

---

## 🔍 **ENUMERATION WORKFLOW**

### **Step 1: Basic User Discovery**
```powershell
Write-Host "=== USER ENUMERATION START ===" -ForegroundColor Cyan

# Get total user count
$totalUsers = (Get-ADUser -Filter *).Count
Write-Host "Total Users: $totalUsers" -ForegroundColor Green

# Get enabled vs disabled users
$enabledUsers = (Get-ADUser -Filter {Enabled -eq $true}).Count
$disabledUsers = (Get-ADUser -Filter {Enabled -eq $false}).Count
Write-Host "Enabled: $enabledUsers, Disabled: $disabledUsers" -ForegroundColor Green
```

### **Step 2: Service Account Analysis**
```powershell
Write-Host "`n=== SERVICE ACCOUNT ANALYSIS ===" -ForegroundColor Cyan

$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate

foreach($account in $serviceAccounts) {
    Write-Host "Service Account: $($account.SamAccountName)" -ForegroundColor Green
    Write-Host "  SPNs: $($account.ServicePrincipalName -join ', ')" -ForegroundColor White
    Write-Host "  Password Last Set: $($account.PasswordLastSet)" -ForegroundColor White
    Write-Host "  Last Logon: $($account.LastLogonDate)" -ForegroundColor White
}
```

### **Step 3: Privilege Analysis**
```powershell
Write-Host "`n=== PRIVILEGE ANALYSIS ===" -ForegroundColor Cyan

# Find users with adminCount=1
$adminCountUsers = Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount, DisplayName, LastLogonDate

foreach($user in $adminCountUsers) {
    Write-Host "Privileged User: $($user.SamAccountName)" -ForegroundColor Red
    Write-Host "  Display Name: $($user.DisplayName)" -ForegroundColor White
    Write-Host "  Last Logon: $($user.LastLogonDate)" -ForegroundColor White
}
```

---

## 📊 **OUTPUT ANALYSIS**

### **User Distribution Matrix**
| Account Type | Count | Percentage | Notes |
|--------------|-------|------------|-------|
| Regular Users | 150 | 75% | Standard accounts |
| Service Accounts | 25 | 12.5% | SPN-enabled accounts |
| Administrative | 15 | 7.5% | Privileged accounts |
| Guest/Temp | 10 | 5% | Temporary access |

### **Service Account SPN Map**
| Account | SPN | Service Type | Last Password Change |
|---------|-----|--------------|---------------------|
| SQLSvc | MSSQLSvc/db01.corp.local | SQL Server | 2024-01-15 |
| WebSvc | HTTP/web01.corp.local | Web Service | 2024-01-10 |
| FileSvc | cifs/files01.corp.local | File Service | 2024-01-20 |

---

## 🚨 **OPSEC CONSIDERATIONS**

### **Stealth Operations**
- Use native AD cmdlets
- Implement query delays
- Focus on essential information
- Avoid aggressive enumeration

### **Production vs Lab**
- **Production**: Minimal queries, focus on high-value targets
- **Lab**: Comprehensive enumeration, test all techniques

---

## 🔄 **NEXT STEPS**
- **[Group Enumeration](./06_Group_Enumeration.md)**: Discover group memberships and roles
- **[Kerberos Enumeration](./23_Kerberos_Basic_Enumeration.md)**: Analyze authentication tickets
- **[SPN Enumeration](./24_SPN_Enumeration_Techniques.md)**: Target service accounts for Kerberoasting

---

**Tags**: #UserEnumeration #IdentityDiscovery #ServiceAccounts #PrivilegeEscalation
