# 🏗️ CRTP Active Directory Knowledge Base - Master Index

## 📚 Structure & Status

Welcome to the comprehensive Active Directory knowledge base for CRTP exam preparation. This vault is a work in progress: core components and enumeration tracks are organized and usable; Security/OPSEC, Tools deep-dives, Labs, and Learning Resources are being filled out.

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
  - **Study timeline** and CRTP exam preparation guide

### **Quick Links**
- **[AD Tools Arsenal (Setup & Loading)](./03_Enumeration_Techniques/01_Tool_Setup_Loading.md)** 🛠️

### **📚 Foundation Enumeration (01-05) - Core Concepts**
*Start here for fundamental enumeration knowledge*

- ****Domain Enumeration (Coming Soon)**** 🏛️
  - **Why First?** Domain enumeration is the foundation - understand domain structure before anything else
  - Domain-level reconnaissance, trust relationship mapping, forest architecture discovery

- ****User Enumeration (Coming Soon)**** 👥
  - **Why Second?** Users are primary targets - essential for privilege escalation
  - User account analysis, property enumeration, user hunting techniques

- ****Computer Enumeration (Coming Soon)**** 💻
  - **Why Third?** Computers are the attack surface - crucial for lateral movement
  - System enumeration, operating system analysis, network topology mapping

- ****Connectivity Testing (Coming Soon)**** 🌐
  - **Why Fourth?** Verify what's actually reachable before attacking
  - Network reachability, live system identification, enumeration validation

- ****DNS Enumeration (Coming Soon)**** 🔍
  - **Why Fifth?** DNS reveals services and additional attack vectors
  - Service discovery, application server identification, infrastructure mapping

### **🔍 Advanced Enumeration (06-10) - Infrastructure Analysis**
*Build on foundation knowledge for deeper infrastructure understanding*

- ****File Share Enumeration (Coming Soon)**** 📁
  - **Why Sixth?** File shares are primary data exfiltration targets
  - Data access points, permission analysis, sensitive data identification

- ****Forest Enumeration (Coming Soon)**** 🌳
  - **Why Seventh?** Forests contain multiple domains - broader attack scope
  - Cross-domain analysis, trust mapping, forest-wide object discovery

- ****Kerberos Enumeration (Coming Soon)**** 🔑
  - **Why Eighth?** Core authentication mechanism - reveals delegation attacks
  - SPN analysis, delegation configuration, authentication flow understanding

- ****LDAP Injection (Coming Soon)**** 💉
  - **Why Ninth?** Advanced technique requiring LDAP structure knowledge
  - Advanced querying, filter bypassing, sensitive information extraction

- ****Network Enumeration (Coming Soon)**** 🌐
  - **Why Tenth?** Network protocols reveal additional attack vectors
  - Protocol analysis, service identification, network topology understanding

### **⚡ Specialized Enumeration (11-15) - Advanced Techniques**
*Specialized techniques for specific scenarios and advanced red team operations*

- ****PowerShell Remoting (Coming Soon)**** ⚡
  - **Why Eleventh?** Enables lateral movement and remote enumeration
  - Remote execution, session establishment, remote system enumeration

- ****Registry Enumeration (Coming Soon)**** 🔧
  - **Why Twelfth?** Registry contains system configurations and security settings
  - System configuration analysis, security setting extraction, vulnerability identification

- ****Session Enumeration (Coming Soon)**** 👤
  - **Why Thirteenth?** Reveals current user activity and privilege escalation targets
  - User activity analysis, session identification, privilege escalation opportunities

- ****Time-Based Enumeration (Coming Soon)**** ⏰
  - **Why Fourteenth?** Temporal analysis can bypass security controls
  - Pattern analysis, timing attacks, security control bypassing

- ****WMI Enumeration (Coming Soon)**** 🔍
  - **Why Fifteenth?** Deep system information bypassing PowerShell restrictions
  - System management, PowerShell bypass, comprehensive system analysis

### **🛡️ Security-Focused Enumeration (16-18) - Access Control & Analysis**
*Final phase focusing on security assessment and privilege escalation*

- ****Group Enumeration (Coming Soon)**** 👥
  - **Why Sixteenth?** Groups define access rights - crucial for privilege escalation
  - Access control analysis, privileged group identification, permission understanding

- ****ACL Enumeration (Coming Soon)**** 🔐
  - **Why Seventeenth?** ACLs define detailed permissions - final access control step
  - Permission analysis, security weakness identification, privilege escalation paths

- ****BloodHound Enumeration (Coming Soon)**** 🩸
  - **Why Eighteenth?** Provides complete picture - combines all enumeration data
  - Attack path mapping, comprehensive analysis, privilege escalation planning

---

## 🛡️ **04_SECURITY_AND_OPSEC** - Operational Security

### **PowerShell Security**
- ****PowerShell Security Controls (Coming Soon)**** 🔒
  - Security mechanisms overview
  - Control types and purposes
  - Detection methods

- ****Invisi-Shell Usage (Coming Soon)**** 🥷
  - Advanced security bypass tool
  - CLR profiler API usage
  - Detection evasion techniques

### **Operational Security**
- ****Operational Security (Coming Soon)**** 🚨
  - Core OPSEC principles
  - Detection avoidance techniques
  - Best practices

- ****Detection Avoidance (Coming Soon)**** 👁️
  - Stealth enumeration techniques
  - Logging bypass methods
  - Behavioral analysis

- ****Stealth Operations (Coming Soon)**** 🥷
  - Covert enumeration methods
  - Timing and correlation
  - Attribution prevention

- ****Security Bypass (Coming Soon)**** 🚪
  - Security control bypass techniques
  - Alternative execution methods
  - Advanced evasion techniques

---

## 🛠️ **05_TOOLS_AND_TECHNIQUES** - Tool Mastery

### **Comprehensive Tool Guide**
- ****Enumeration Tools Overview (Coming Soon)**** 🛠️
  - Complete tool comparison
  - Selection strategies
  - Detection risk assessment
  - Native vs. specialized tools

---

## 🧪 **06_LAB_PRACTICE** - Hands-On Learning

### **Practical Exercises**
- ****Lab Practice Overview (Coming Soon)**** 🧪
  - Comprehensive lab framework
  - Exercise templates
  - Skill validation methods
  - Progressive learning exercises

---

## 📖 **07_LEARNING_RESOURCES** - Exam Preparation

### **CRTP Learning Guide**
- ****Learning Objectives Overview (Coming Soon)**** 🎯
  - Complete CRTP learning objectives
  - Skill development strategies
  - Assessment and validation
  - Exam preparation roadmap

---

## 🚀 **Learning Paths**

### **🚀 Quick Start (Beginner)**
1. **[Active Directory Overview](./01_Foundation/Active%20Directory.md)** - Start here
2. **[AD Components Index](./02_Active_Directory_Components/00_AD_Components_Index.md)** - Understand architecture
3. ****Domain Enumeration (Coming Soon)**** - First practical skill
4. ****Lab Practice (Coming Soon)**** - Hands-on learning

### **📚 Comprehensive Study (Intermediate)**
1. **Foundation**: Complete all component files (01-15)
2. **Enumeration**: Master all enumeration techniques
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

- **Active Directory Components**: structured and navigable ✅
- **Enumeration Techniques**: structured and navigable ✅
- **Security and OPSEC**: content in progress ⏳
- **Tools and Techniques**: content in progress ⏳
- **Lab Practice**: content in progress ⏳
- **Learning Resources**: content in progress ⏳

---

## 🎉 **Using This Vault**

Start with the learning paths below. As sections labeled “in progress” are completed, links will light up with deeper content and workflows.

- Begin at **[Active Directory Overview](./01_Foundation/Active%20Directory.md)** 🚀

---

*Tags: #CRTP #ActiveDirectory #KnowledgeBase #Organization #Categories #LearningPath #Navigation*
