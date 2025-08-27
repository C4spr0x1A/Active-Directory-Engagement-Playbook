# 🏗️ Active Directory Knowledge Base - Master Index

## 📚 Structure & Status

Welcome to the comprehensive Active Directory knowledge base. This vault is organized and ready for use: core components and enumeration techniques are complete and fully functional.

---

## 🎯 **01_FOUNDATION** - Core Knowledge Base

### **Entry Point & Overview**
- **[Active Directory - Complete Knowledge Base](./01_Foundation/Active%20Directory.md)** 🚀
  - Master overview and navigation hub
  - Learning path guidance
  - Quick start guide for all skill levels
  - Complete knowledge base roadmap

---

## 🏛️ **02_ACTIVE_DIRECTORY_COMPONENTS** - Theoretical Foundation

### **Master Index**
- **[AD Components Index](./02_Active_Directory_Components/00_AD_Components_Index.md)** 📋
  - Master overview of all components
  - Navigation hub for component files
  - Learning path guidance

### **Core Architecture (Files 01-03)**
- **[Active Directory Overview](./02_Active_Directory_Components/01_Active_Directory.md)** 🏗️
  - Foundation concepts and architecture
  - Core components overview
  - Hierarchical structure

- **[Domain Controllers](./02_Active_Directory_Components/02_Domain_Controllers.md)** 🖥️
  - Core infrastructure servers
  - Authentication and management
  - Primary targets for compromise

- **[Domain](./02_Active_Directory_Components/03_Domain.md)** 🛡️
  - Security boundaries
  - Administrative units
  - Attack boundaries

### **Architecture & Organization (Files 04-07)**
- **[Forest](./02_Active_Directory_Components/04_Forest.md)** 🌳
  - Top-level container
  - Multi-domain architecture
  - Trust framework

- **[Organizational Units](./02_Active_Directory_Components/05_Organizational_Unit.md)** 📁
  - Organization structure
  - Group Policy application
  - Administrative delegation

- **[Sites and Subnets](./02_Active_Directory_Components/06_Sites_and_Subnets.md)** 🌐
  - Network topology
  - Replication optimization
  - Physical location mapping

- **[Trusts](./02_Active_Directory_Components/07_Trusts.md)** 🤝
  - Cross-domain relationships
  - Authentication paths
  - Lateral movement opportunities

### **Operations & Management (Files 08-11)**
- **[FSMO Roles](./02_Active_Directory_Components/08_FSMO_Roles.md)** 👑
  - Specialized operations
  - Critical server roles
  - High-value targets

- **[Group Policy Objects](./02_Active_Directory_Components/09_Group_Policy_Objects.md)** ⚙️
  - Configuration management
  - Security settings
  - Misconfiguration abuse

- **[Active Directory Partitions](./02_Active_Directory_Components/10_Active_Directory_Partitions.md)** 📊
  - Data organization
  - Replication scope
  - Forest-wide impact

- **[Schema](./02_Active_Directory_Components/11_Schema.md)** 📋
  - Data blueprint
  - Object definitions
  - Attribute structure

### **Advanced Architecture (Files 12-15)**
- **[Global Catalog](./02_Active_Directory_Components/12_Global_Catalog.md)** 🔍
  - Forest-wide search
  - Fast object location
  - Enumeration optimization

- **[LDAP and Ports](./02_Active_Directory_Components/13_LDAP_and_Ports.md)** 🌐
  - Communication protocol
  - Port configurations
  - Protocol security

- **[Query and Index Mechanism](./02_Active_Directory_Components/14_Query_and_Index_Mechanism.md)** 🔎
  - Search engine
  - Indexed attributes
  - Query optimization

- **[Replication Service](./02_Active_Directory_Components/15_Replication_Service.md)** 🔄
  - Data synchronization
  - Multi-master replication
  - DCSync attacks

---

## 🔍 **03_ENUMERATION_TECHNIQUES** - Practical Skills

### **Master Index & Learning Path**
- **[Enumeration Index](./03_Enumeration_Techniques/00_Enumeration_Index.md)** 📋
  - **Logical learning progression** with reasoning for each step
  - **Prerequisites flow** and learning objectives
  - **Study timeline** and preparation guide

### **Quick Links**
- **[AD Tools Arsenal (Setup & Loading)](./03_Enumeration_Techniques/01_Tool_Setup_Loading.md)** 🛠️

### **📚 Foundation Enumeration (01-05) - Core Concepts**
*Start here for fundamental enumeration knowledge*

- **[Network Enumeration](./03_Enumeration_Techniques/02_Network_Enumeration.md)** 🌐
  - **Why First?** Network enumeration is the foundation - understand network topology before anything else
  - Network discovery, port scanning, service identification, live host detection

- **[DNS Enumeration](./03_Enumeration_Techniques/03_DNS_Enumeration.md)** 🔍
  - **Why Second?** DNS reveals services and additional attack vectors
  - Service discovery, application server identification, infrastructure mapping

- **[Domain Enumeration](./03_Enumeration_Techniques/04_Domain_Enumeration.md)** 🏛️
  - **Why Third?** Domain enumeration reveals the AD structure - essential for understanding the environment
  - Domain-level reconnaissance, trust relationship mapping, forest architecture discovery

- **[User Enumeration](./03_Enumeration_Techniques/05_User_Enumeration.md)** 👥
  - **Why Fourth?** Users are primary targets - essential for privilege escalation
  - User account analysis, property enumeration, user hunting techniques

- **[Group Enumeration](./03_Enumeration_Techniques/06_Group_Enumeration.md)** 👥
  - **Why Fifth?** Groups define access rights - crucial for privilege escalation
  - Access control analysis, privileged group identification, permission understanding

### **🔍 Advanced Enumeration (06-10) - Infrastructure Analysis**
*Build on foundation knowledge for deeper infrastructure understanding*

- **[Computer Enumeration](./03_Enumeration_Techniques/07_Computer_Enumeration.md)** 💻
  - **Why Sixth?** Computers are the attack surface - crucial for lateral movement
  - System enumeration, operating system analysis, network topology mapping

- **[GPO Enumeration](./03_Enumeration_Techniques/08_GPO_Enumeration.md)** ⚙️
  - **Why Seventh?** Group Policy reveals security configurations and potential misconfigurations
  - Security setting analysis, configuration extraction, policy abuse opportunities

- **[ACL Enumeration](./03_Enumeration_Techniques/09_ACL_Enumeration.md)** 🔐
  - **Why Eighth?** ACLs define detailed permissions - crucial for privilege escalation
  - Permission analysis, security weakness identification, privilege escalation paths

- **[BloodHound Enumeration](./03_Enumeration_Techniques/10_BloodHound_Enumeration.md)** 🩸
  - **Why Ninth?** Provides complete picture - combines all enumeration data
  - Attack path mapping, comprehensive analysis, privilege escalation planning

- **[SOAPHound Enumeration](./03_Enumeration_Techniques/11_SOAPHound_Enumeration.md)** 🧼
  - **Why Tenth?** Alternative to BloodHound with different capabilities
  - SOAP-based enumeration, alternative attack path discovery, comprehensive analysis

### **⚡ Specialized Enumeration (11-15) - Advanced Techniques**
*Specialized techniques for specific scenarios and advanced red team operations*

- **[Session Enumeration Index](./03_Enumeration_Techniques/12_Session_Enumeration_Index.md)** 👤
  - **Why Eleventh?** Sessions reveal current user activity and privilege escalation targets
  - User activity analysis, session identification, privilege escalation opportunities

- **[Active Session Discovery](./03_Enumeration_Techniques/13_Active_Session_Discovery.md)** 🔍
  - **Why Twelfth?** Active sessions show real-time user activity
  - Live session monitoring, user behavior analysis, attack timing optimization

- **[RDP Session Enumeration](./03_Enumeration_Techniques/14_RDP_Session_Enumeration.md)** 🖥️
  - **Why Thirteenth?** RDP sessions reveal remote access patterns
  - Remote access analysis, session hijacking opportunities, lateral movement planning

- **[Terminal Services Enumeration](./03_Enumeration_Techniques/15_Terminal_Services_Enumeration.md)** ⚡
  - **Why Fourteenth?** Terminal services enable remote execution and enumeration
  - Remote execution, session establishment, remote system enumeration

- **[Session Analysis Techniques](./03_Enumeration_Techniques/16_Session_Analysis_Techniques.md)** 📊
  - **Why Fifteenth?** Session analysis reveals patterns and vulnerabilities
  - Pattern analysis, vulnerability identification, attack optimization

### **🛡️ Security-Focused Enumeration (16-18) - Access Control & Analysis**
*Final phase focusing on security assessment and privilege escalation*

- **[File Share Enumeration](./03_Enumeration_Techniques/17_File_Share_Enumeration.md)** 📁
  - **Why Sixteenth?** File shares are primary data exfiltration targets
  - Data access points, permission analysis, sensitive data identification

- **[Registry Enumeration](./03_Enumeration_Techniques/18_Registry_Enumeration.md)** 🔧
  - **Why Seventeenth?** Registry contains system configurations and security settings
  - System configuration analysis, security setting extraction, vulnerability identification

- **[PowerShell Remoting Enumeration](./03_Enumeration_Techniques/19_PowerShell_Remoting_Enumeration.md)** ⚡
  - **Why Eighteenth?** Enables lateral movement and remote enumeration
  - Remote execution, session establishment, remote system enumeration

- **[WMI Enumeration](./03_Enumeration_Techniques/20_WMI_Enumeration.md)** 🔍
  - **Why Nineteenth?** Deep system information bypassing PowerShell restrictions
  - System management, PowerShell bypass, comprehensive system analysis

- **[Time-Based Enumeration](./03_Enumeration_Techniques/21_Time_Based_Enumeration.md)** ⏰
  - **Why Twentieth?** Temporal analysis can bypass security controls
  - Pattern analysis, timing attacks, security control bypassing

### **🔑 Kerberos & Authentication (22-26) - Advanced Authentication Attacks**
*Specialized Kerberos enumeration and attack techniques*

- **[Kerberos Master Index](./03_Enumeration_Techniques/22_Kerberos_Master_Index.md)** 🔑
  - **Why Twenty-First?** Kerberos is the core authentication mechanism
  - Authentication flow understanding, attack vector identification, comprehensive Kerberos knowledge

- **[Kerberos Basic Enumeration](./03_Enumeration_Techniques/23_Kerberos_Basic_Enumeration.md)** 🔍
  - **Why Twenty-Second?** Foundation for all Kerberos attacks
  - Basic authentication understanding, ticket analysis, fundamental enumeration

- **[SPN Enumeration Techniques](./03_Enumeration_Techniques/24_SPN_Enumeration_Techniques.md)** 🎯
  - **Why Twenty-Third?** SPNs reveal service accounts and delegation opportunities
  - Service account identification, delegation configuration, Kerberoasting preparation

- **[Kerberos Delegation Abuse](./03_Enumeration_Techniques/25_Kerberos_Delegation_Abuse.md)** 🚪
  - **Why Twenty-Fourth?** Delegation enables privilege escalation and lateral movement
  - Delegation abuse, privilege escalation, lateral movement techniques

- **[Kerberos Advanced Attacks](./03_Enumeration_Techniques/26_Kerberos_Advanced_Attacks.md)** ⚔️
  - **Why Twenty-Fifth?** Advanced techniques for sophisticated attacks
  - Golden/Silver/Diamond tickets, advanced persistence, sophisticated attack methods

### **🔐 Advanced Services & Protocols (27-30) - Specialized Infrastructure**
*Advanced enumeration of specialized services and protocols*

- **[AD CS Enumeration](./03_Enumeration_Techniques/27_AD_CS_Enumeration.md)** 🏛️
  - **Why Twenty-Sixth?** Certificate services enable ESC attacks and persistence
  - Certificate enumeration, ESC attack preparation, PKI infrastructure analysis

- **[SQL Server Enumeration](./03_Enumeration_Techniques/28_SQL_Server_Enumeration.md)** 🗄️
  - **Why Twenty-Seventh?** SQL servers contain sensitive data and enable command execution
  - Database enumeration, xp_cmdshell abuse, sensitive data extraction

- **[LDAP Injection](./03_Enumeration_Techniques/29_LDAP_Injection.md)** 💉
  - **Why Twenty-Eighth?** Advanced technique requiring LDAP structure knowledge
  - Advanced querying, filter bypassing, sensitive information extraction

- **[Forest Enumeration](./03_Enumeration_Techniques/30_Forest_Enumeration.md)** 🌳
  - **Why Twenty-Ninth?** Forests contain multiple domains - broader attack scope
  - Cross-domain analysis, trust mapping, forest-wide object discovery

### **🛡️ Detection & OPSEC (31-33) - Security Awareness**
*Understanding detection mechanisms and operational security*

- **[Detection Index](./03_Enumeration_Techniques/31_Detection_Index.md)** 👁️
  - **Why Thirtieth?** Understanding detection enables better OPSEC and evasion
  - Detection mechanism overview, evasion strategy, comprehensive security awareness

- **[Detection Blue Team](./03_Enumeration_Techniques/32_Detection_Blue_Team.md)** 🔵
  - **Why Thirty-First?** Blue team detection methods inform red team evasion
  - Event monitoring, SIEM rules, detection strategies, security control analysis

- **[Detection Red Team](./03_Enumeration_Techniques/33_Detection_Red_Team.md)** 🔴
  - **Why Thirty-Second?** Red team evasion techniques ensure operational success
  - OPSEC strategies, detection avoidance, stealth techniques, attribution prevention

---

## 🛡️ **04_SECURITY_AND_OPSEC** - Operational Security

### **PowerShell Security**
- **PowerShell Security Controls (Coming Soon)** 🔒
  - Security mechanisms overview
  - Control types and purposes
  - Detection methods

- **Invisi-Shell Usage (Coming Soon)** 🥷
  - Advanced security bypass tool
  - CLR profiler API usage
  - Detection evasion techniques

### **Operational Security**
- **Operational Security (Coming Soon)** 🚨
  - Core OPSEC principles
  - Detection avoidance techniques
  - Best practices

- **Detection Avoidance (Coming Soon)** 👁️
  - Stealth enumeration techniques
  - Logging bypass methods
  - Behavioral analysis

- **Stealth Operations (Coming Soon)** 🥷
  - Covert enumeration methods
  - Timing and correlation
  - Attribution prevention

- **Security Bypass (Coming Soon)** 🚪
  - Security control bypass techniques
  - Alternative execution methods
  - Advanced evasion techniques

---

## 🛠️ **05_TOOLS_AND_TECHNIQUES** - Tool Mastery

### **Comprehensive Tool Guide**
- **Enumeration Tools Overview (Coming Soon)** 🛠️
  - Complete tool comparison
  - Selection strategies
  - Detection risk assessment
  - Native vs. specialized tools

---

## 🧪 **06_LAB_PRACTICE** - Hands-On Learning

### **Practical Exercises**
- **Lab Practice Overview (Coming Soon)** 🧪
  - Comprehensive lab framework
  - Exercise templates
  - Skill validation methods
  - Progressive learning exercises

---

## 📖 **07_LEARNING_RESOURCES** - Exam Preparation

### **Learning Guide**
- **Learning Objectives Overview (Coming Soon)** 🎯
  - Complete learning objectives
  - Skill development strategies
  - Assessment and validation
  - Preparation roadmap

---

## 🚀 **Learning Paths**

### **🚀 Quick Start (Beginner)**
1. **[Active Directory Overview](./01_Foundation/Active%20Directory.md)** - Start here
2. **[AD Components Index](./02_Active_Directory_Components/00_AD_Components_Index.md)** - Understand architecture
3. **[Network Enumeration](./03_Enumeration_Techniques/02_Network_Enumeration.md)** - First practical skill
4. **Lab Practice (Coming Soon)** - Hands-on learning

### **📚 Comprehensive Study (Intermediate)**
1. **Foundation**: Complete all component files (01-17)
2. **Enumeration**: Master all enumeration techniques (01-33)
3. **Security**: Understand OPSEC and bypass techniques
4. **Practice**: Complete all lab exercises

### **🎯 Advanced Mastery (Expert)**
1. **Integration**: Combine all techniques
2. **Customization**: Develop custom scripts
3. **Stealth**: Master detection avoidance
4. **Assessment**: Validate all skills

---

## 🔗 **Navigation Features**

### **Cross-Category Links**
- **Bidirectional linking** between all related topics
- **Navigation arrows** for logical progression
- **Related Topics** sections throughout
- **See Also** sections for additional context

### **Search & Discovery**
- **Tags** for topic-based navigation
- **Graph view** for relationship mapping
- **Backlinks** for reverse navigation
- **Category-based organization** for focused learning

---

## 📊 **Current Progress Snapshot**

- **Active Directory Components**: Complete and navigable ✅ (17/17 files)
- **Enumeration Techniques**: Complete and navigable ✅ (33/33 files)
- **Security and OPSEC**: Content in progress ⏳
- **Tools and Techniques**: Content in progress ⏳
- **Lab Practice**: Content in progress ⏳
- **Learning Resources**: Content in progress ⏳

---

## 🎉 **Using This Vault**

Start with the learning paths below. The Active Directory Components and Enumeration Techniques sections are complete and ready for use.

- Begin at **[Active Directory Overview](./01_Foundation/Active%20Directory.md)** 🚀

---

*Tags: #ActiveDirectory #KnowledgeBase #Organization #Categories #LearningPath #Navigation*
