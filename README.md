# Hack The Box — Blackfield

Main roadblock beginners would face is LSASS, would recommaned taking a look before moving on with the machine

## Overview
**Blackfield** is a Windows Active Directory machine from Hack The Box that focuses on AD enumeration, abusing Kerberos pre-authentication, SMB share analysis, and privilege escalation within a domain environment.

- **Difficulty:** Hard  
- **OS:** Windows  
- **Category:** Active Directory  
- **Status:** Rooted ✅  

---

## Objectives
- Enumerate a Windows domain environment
- Identify valid domain users
- Abuse Kerberos authentication weaknesses
- Escalate privileges within Active Directory
- Achieve Domain Administrator access

---

## Enumeration

### Network Scanning
Initial enumeration revealed common AD-related services:
- DNS
- Kerberos
- LDAP
- SMB
- WinRM

SMB enumeration exposed multiple shares, including backup-related directories containing sensitive domain data.

### Domain Enumeration
- Extracted and validated domain users
- Identified Kerberos pre-authentication weaknesses
- Enumerated domain structure and privileges

---

## Initial Access

### Kerberos Abuse
- Performed **AS-REP roasting** against users without Kerberos pre-authentication
- Successfully cracked a domain user password
- Gained initial authenticated access to the domain

---

## Privilege Escalation

### Lateral Movement
- Accessed sensitive SMB backups
- Extracted and analyzed domain data
- Leveraged credential reuse and misconfigurations

### Domain Escalation
- Identified excessive privileges assigned to a service account
- Abused Active Directory permissions to escalate privileges
- Achieved **Domain Admin** access

---

## Flags
- **User:** ✅  
- **Root:** ✅  

---

## Key Takeaways
- Always audit Kerberos pre-authentication settings
- Restrict access to backup shares containing sensitive AD data
- Enforce least privilege for service accounts
- Regularly review Active Directory ACLs

---

## Tools Used
- Nmap
- SMBClient
- Impacket
- Kerberos tools (AS-REP roasting)
- PowerView / AD enumeration utilities

---

## Notes
This machine highlights how **small misconfigurations in Active Directory** can chain together into a full domain compromise.

---

## Disclaimer
This write-up is for **educational purposes only** and was completed in a controlled lab environment provided by Hack The Box.
