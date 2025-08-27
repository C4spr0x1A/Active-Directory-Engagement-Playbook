## Purpose & Definition
An **Organizational Unit (OU)** is a **container within a domain** used to organize objects like users, groups, and computers. OUs allow **delegation of administrative control** and **application of Group Policies**. They are not security boundaries like domains but are **logical containers** for management.

## How It Works

### Container Contents
OUs can contain:
- **Users**
- **Groups**
- **Computers**
- **Other OUs** (nested OUs)

### Administrative Features
- Administrators can delegate specific permissions on an OU without granting full domain admin rights
- **Group Policy Objects (GPOs)** can be linked to OUs to enforce policies on all contained objects

### Example Structure
```
DC=corp,DC=local
├─ OU=HR
│    ├─ Users
│    └─ Computers
└─ OU=IT
    ├─ Users
    └─ Computers
```

## Administrative Use Cases

### Delegation
- Assign an HR admin permission to manage only `OU=HR` without touching other OUs
- Enable granular administrative control without compromising security

### Group Policy Application
- Apply password policies, desktop restrictions, or software deployment to specific OUs
- **Example implementations**:
  - `OU=HR` has a GPO enforcing auto-lock after 10 minutes
  - `OU=IT` has a GPO allowing software installation scripts for admins

## Red Team / Attacker Perspective

### Enumeration Opportunities
- Attackers can **enumerate OUs** to map the organization and locate high-value targets
- **Examples**:
  - Identify OUs containing privileged accounts (`OU=Admins`)
  - Target GPOs to understand applied restrictions or weaknesses
  - OU names can provide **organizational insights**, which help in social engineering or lateral movement

## Additional Notes

### Security Considerations
- OUs **do not provide security boundaries**; permissions inside can be delegated but domain-wide policies still apply
- Nested OUs allow **hierarchical management** mirroring the company's structure
- Proper OU design improves administration and **reduces attack surface**

## Related Components
- ****02_Active_Directory_Components/03_Domain (Coming Soon)****: Container that holds this OU
- ****02_Active_Directory_Components/09_Group_Policy_Objects (Coming Soon)****: Policies linked to this OU
- ****02_Active_Directory_Components/06_Sites_and_Subnets (Coming Soon)****: Physical locations that may contain OUs
- ****02_Active_Directory_Components/11_Schema (Coming Soon)****: Defines the object types that can be placed in OUs
- ****02_Active_Directory_Components/15_Replication_Service (Coming Soon)****: How OU changes are synchronized across DCs

---

*Tags: #CRTP #ActiveDirectory #OU #OrganizationalUnit #Delegation #GroupPolicy #RedTeam*