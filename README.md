# Hack The Box — Blackfield

!!! important note for beginners, would recommened talking a look at LSASS before moving on with this.

## Overview
**Blackfield** is a retired **Hard** Windows Active Directory machine from Hack The Box.  
The box simulates a realistic corporate AD environment and focuses heavily on **Kerberos abuse**, **credential extraction**, and **privilege escalation through misconfigured domain groups**.

- **Difficulty:** Hard  
- **OS:** Windows  
- **Environment:** Active Directory Domain Controller  
- **Status:** Rooted ✅  

---

## Services & Enumeration

Initial enumeration reveals a classic AD setup with the following key services:

- DNS (53)
- Kerberos (88)
- LDAP (389 / 3268)
- SMB (445)
- RPC
- WinRM (5985)

The exposed services clearly indicate that the target is a **Domain Controller**, making Active Directory enumeration the primary attack surface.

---

## SMB Enumeration & User Discovery

SMB enumeration reveals accessible shares that allow:
- Discovery of domain-related files
- Extraction of **valid domain usernames**

These usernames become critical for subsequent Kerberos-based attacks.

---

## Initial Access — Kerberos AS-REP Roasting

One of the identified domain users has **Kerberos pre-authentication disabled**.

This misconfiguration allows:
- Requesting an AS-REP response without valid credentials
- Extracting an encrypted Kerberos hash
- Performing **offline password cracking**

Cracking the AS-REP hash yields valid domain credentials, granting authenticated access to additional resources.

---

## Credential Discovery

With authenticated SMB access:
- Sensitive forensic artifacts are discovered in shared directories
- These include memory dump files (e.g. LSASS-related data)

Analyzing these files leads to the extraction of **additional credentials**, including an account with elevated privileges and **WinRM access**.

---

## Privilege Escalation — Backup Operators Abuse

The newly obtained account is a member of the **Backup Operators** group.

This group has powerful rights within Active Directory, including:
- Ability to back up system files
- Access to sensitive domain data

By abusing these privileges, it is possible to:
- Dump the **Active Directory database (NTDS.dit)**
- Extract password hashes for all domain users

---

## Domain Compromise

From the dumped AD database:
- Domain Administrator credentials are recovered
- Full **Domain Admin** access is achieved

This completes the attack chain and results in total domain compromise.

---

## Flags
- **User:** ✅  
- **Root / Administrator:** ✅  

---

## Key Takeaways
- Kerberos pre-authentication should never be disabled unnecessarily
- Backup Operators is a highly privileged group and must be tightly controlled
- Storing sensitive dumps or backups on accessible shares is extremely dangerous
- Small AD misconfigurations can be chained into full domain takeover

---

## Tools Used
- Nmap
- SMBClient / enum4linux
- Impacket (Kerberos & AD attacks)
- Hashcat / John the Ripper
- Memory dump analysis tools
- NTDS extraction utilities

---

## Disclaimer
This write-up is for **educational purposes only** and was performed in a controlled lab environment provided by Hack The Box.
