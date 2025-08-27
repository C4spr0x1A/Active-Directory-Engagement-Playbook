## Purpose & Definition
Defines objects and their attributes. It defines what types of objects exist in the directory. The schema is **forest-wide** (shared across the entire AD forest) and replicated to every Domain Controller.

## How It Works

### Object Types
- **Objects**: Users, Groups, Computers, Printers, OUs (Organizational Units), etc.

### Attributes
- **Attributes**: `sAMAccountName`, `userPrincipalName`, `memberOf`, `lastLogonTime`, etc. Note that attributes have an **LDAP Display Name** which is commonly seen, and a **Common Name (cn)** which is the actual object name in the directory.

## Administrative Use Cases

### Legit Use (IT/Admins)
- A company integrates a new HR system
- The software extends the schema by adding a new object type like `EmployeeRecord` and attributes such as `employeeID`, `departmentCode`, `jobTitle`
- Now, every user object can store extra HR-related information

### Schema Modification Implications
- Schema modifications are **irreversible** and can have **significant, forest-wide impact**. They must be carefully planned and executed, typically by the Schema Master FSMO role holder.

## Red Team / Attacker Perspective

### Attack Surface
- Attackers query the schema to discover what data is available

### Attack Examples
- Run `ldapsearch` or `Get-ADObject` in PowerShell to enumerate attributes like `servicePrincipalName` (SPN) → used in **Kerberoasting**
- Poorly designed schema extensions may expose sensitive fields (e.g., clear-text info stored in custom attributes)

## Related Components
- ****02_Active_Directory_Components/04_Forest (Coming Soon)****: Forest-wide schema shared by all domains
- ****02_Active_Directory_Components/10_Active_Directory_Partitions (Coming Soon)****: Schema partition contains schema definitions
- ****02_Active_Directory_Components/14_Query_and_Index_Mechanism (Coming Soon)****: Schema defines searchable attributes
- ****02_Active_Directory_Components/08_FSMO_Roles (Coming Soon)****: Schema Master controls schema modifications
- ****02_Active_Directory_Components/15_Replication_Service (Coming Soon)****: How schema changes are distributed forest-wide
- ****02_Active_Directory_Components/12_Global_Catalog (Coming Soon)****: Uses schema for object definitions

---

*Tags: #CRTP #ActiveDirectory #Schema #Objects #Attributes #RedTeam**