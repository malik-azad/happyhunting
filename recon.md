# Recon and Enumeration

The single most valuable skill. Tools change, this order does not.

## Contents

- [Scope and rules of engagement](#scope-and-rules-of-engagement)
- [Host discovery](#host-discovery)
- [nmap](#nmap)
- [Service-specific enumeration](#service-specific-enumeration)
- [Web and DNS enumeration](#web-and-dns-enumeration)
- [Wordlists and where they live](#wordlists-and-where-they-live)
- [Low-noise versus thorough](#low-noise-versus-thorough)
- [When the usual tools do not work](#when-the-usual-tools-do-not-work)

---

## Scope and rules of engagement

Before scanning anything, write down:

- Exact target IPs, ranges, and domains
- Which ports and protocols are permitted
- Start and end time
- Rate limit
- Whether denial of service, resource exhaustion, and social engineering are allowed
- Who to contact when something breaks

A TCP connect scan (`-sT`) is much quieter than a SYN scan (`-sS`) because the
OS completes the handshake. A full version scan (`-sV`) is noisier still. On a
client network with monitoring, these differences are visible.

Most engagements prohibit denial of service testing entirely unless explicitly
written in. Most also prohibit anything that could crash a production service.
Assume both are forbidden unless you have them in writing.

---

## Host discovery

```bash
# Ping sweep, the simplest first pass. Needs root for raw sockets.
nmap -sn 192.168.1.0/24

# ARP discovery on your own LAN. No router involved, very accurate.
sudo arp-scan --localnet

# From a distance, when ICMP is filtered
nmap -sn -PS22 -PS80 -PA80 -PU53 192.168.1.0/24

# Look at the local table
ip neigh
arp -a
```

Understand what you are seeing. `arp -a` shows hosts that recently responded,
not hosts that exist. A silent host is not a dead host.

### When ping fails

This is normal and not a finding. Plenty of production hosts drop ICMP. The
host is up, it just does not answer ping. Move on to port scanning and do not
waste time convincing a host is dead.

**The `-Pn` trap.** If you skip host discovery with `-Pn`, nmap assumes every
host is alive and scans all of them. That is correct for a single known-live
host, and wasteful for a range where you are trying to find live hosts first.
Know which mode you are in and why.

```bash
# Find live hosts, then scan only those. Much faster on a big range.
nmap -sn 192.168.1.0/24 -oA live.txt
grep "Nmap scan report" live.txt | awk '{print $NF}' > live_hosts.txt
nmap -iL live_hosts.txt -p 1-10000
```

---

## nmap

### Scan types

| Command | What it does | Noise |
|---|---|---|
| `nmap -sS target` | SYN scan, half-open | Low. Default, needs root |
| `nmap -sT target` | TCP connect | Higher, completes handshake |
| `nmap -sU target -p 53,161` | UDP scan | Very slow, root |
| `nmap -sn target` | Ping sweep, no ports | Minimal |
| `nmap -sV` | Detect service and version | Moderate |
| `nmap -O` | Guess OS | Moderate, often wrong |

UDP is the one people get wrong. A full UDP scan of a /24 can take hours and is
almost always out of scope. Target the interesting ports instead:

```bash
# The pragmatic UDP list. Fast, high yield.
sudo nmap -sU -p 53,67,68,69,123,135,137,138,139,161,162,500,514,520,623,626,1434,1604,1900,2049,3478,5353,5060,5355,5683,4500,5061,5355,8761,9000,11211 --min-rate 2000 192.168.1.0/24
```

### Version detection and scripts

```bash
# Version + default scripts. The standard opener.
nmap -sV -sC -oA out target

# Faster, less noisy scripts
nmap -sV --script "safe" -oA out target

# Specific script categories
nmap --script vuln -oA out target        # aggressive, will flag a lot of noise
nmap --script auth -oA out target
nmap --script smb-enum -oA out target
nmap --script http-enum -oA out target
```

Read what `vuln` actually found. It fires probes that can cause a service to
log errors, and on a production box that is visible to the client. Have a
reason before running it.

### Output formats

Use `-oA`, it saves you a lot of later pain.

```bash
nmap -sV -sC -oA scan target        # saves scan.nmap, scan.nmap.gnmap, scan.xml
```

| Format | File suffix | Use for |
|---|---|---|
| Normal | `.nmap` | Reading |
| Greppable | `.gnmap` | `awk` and `grep` pipelines |
| XML | `.xml` | Feeding into other tools |

```bash
# Greppable output is the reason to bother
awk -F'"' '/open\/tcp/ {print $4}' scan.nmap.gnmap | sort -u          # open ports
awk -F'"' '/open\/tcp/ {split($4,a,"/"); print a[1]}' scan.nmap.gnmap | sort -un | paste -sd, -   # port list
awk -F'"' '/open\/tcp/ && $4 ~ /http/ {print $6}' scan.nmap.gnmap     # http titles
```

### Timing and evasion

```bash
# Deliberately slow. Use on a monitored client network.
nmap -T2 -oA out target
nmap -T0 -oA out target            # paranoid, for fragile targets

# Slow it down further with explicit delays in milliseconds
nmap --min-rate 50 --max-retries 2 -oA out target
nmap --scan-delay 500ms -oA out target

# Fragment packets. Older IDS evasions, unreliable against modern systems.
nmap -f -oA out target
nmap --mtu 1400 -oA out target

# Decoys and random source. Note this scatters your traffic.
nmap -D 10.0.0.1,10.0.0.2 -S 10.0.0.100 -oA out target
nmap --randomize-hosts -oA out target
```

Treat all of the last group as legacy. Modern IDS and modern nmap both handle
these, and a pentester relying on them looks out of date. Know them for exams
and for the rare legacy environment, but the real low-noise lever is timing and
port selection.

---

## Service-specific enumeration

### SMB, the classic starting point

```bash
# With netexec, the modern replacement for crackmapexec
netexec smb <target> -u '' -p '' --shares            # null session
netexec smb <target> -u guest -p guest --shares
netexec smb <target> -u 'user' -p 'pass' --shares
netexec smb <target> -u 'user' -p 'pass' --enum-users
netexec smb <target> -u 'user' -p 'pass' --enum-sessions
netexec smb <target> -u 'user' -p 'pass' --enum-shares
netexec smb <target> -u 'user' -p 'pass' -x ls

# Useful options
--local-auth          # use the local machine account rather than the domain
-k                    # use Kerberos
--target              # specify the target
--no-bruteforce       # for password spraying
-A                    # look for a list of interesting attacks
```

```bash
# Legacy tools, still everywhere in walkthroughs
smbclient -L //<target> -N                 # list shares, null session
smbclient //<target>/share -U 'user%pass'  # connect
smbmap -H <target> -u 'user' -p 'pass'
crackmapexec smb <target> -u 'users.txt' -p 'passwords.txt' --no-bruteforce   # spray
```

SMB enumeration is where Windows labs usually begin. Look for shares readable
without credentials, and for the version, which tells you which CVEs are even
worth considering.

### SNMP

```bash
snmpwalk -v2c -c public <target>                    # default community string
snmpwalk -v2c -c private <target>
snmpwalk -v1 -c public <target>                     # v1 leaks far more
onesixtyone -c wordlist.txt <target>
```

```bash
# nmap script
nmap -sU -p 161 --script snmp-brute -oA out <target>
nmap -sU -p 161 --script snmp-info -oA out <target>
```

### FTP

```bash
nmap -sV -sC -p 21 --script ftp-anon,ftp-brute,ftp-syst -oA out <target>
ftp <target>          # try anonymous, email as password often accepted
curl -s ftp://<target>/ --user anonymous:anonymous
```

Look for anonymous write access. A writable FTP root plus a web root on the
same host is a straightforward upload-to-RCE path.

### DNS

```bash
# Zone transfer. If this works you get every hostname on the domain.
dig axfr <domain> @<nameserver>
dig axfr <domain> @1.1.1.1
host -t axfr <domain> <nameserver>
```

```bash
# Record types worth pulling
dig <domain> ANY +noall +answer
dig <domain> NS
dig <domain> MX
dig <domain> TXT                      # SPF, DMARC, and stray verification tokens
dig _dmarc.<domain> TXT
dig <domain> CNAME
```

```bash
# Subdomain brute force
subfinder -d <domain> -silent -o subs.txt
assetfinder --subs-only <domain> > subs.txt
amass enum -passive -d <domain> -o subs.txt
gobuster dns -d <domain> -w /usr/share/wordlists/dirbuster/dns.txt -t 50
```

A zone transfer finding is a critical severity issue on its own. It hands an
attacker the complete internal naming scheme for free.

### Kerberos and Active Directory light

```bash
# Enumerate the domain
enum4linux <target>                   # SMB and LDAP
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" -s base namingContexts
crackmapexec ldap <target> -u users.txt -p passwords.txt --no-bruteforce
```

```bash
# Kerberos probing
nmap -p 88 --script kerberos-info -oA out <domain-ip>
nmap -p 389,636 --script ldap-rootdse -oA out <target>
```

Full AD attack technique is its own discipline. Come back to it when SMB
enumeration is second nature.

---

## Web and DNS enumeration

```bash
# Content discovery
ffuf -w /usr/share/wordlists/dirbuster/dir-list-2.3-medium.txt -u https://<target> -mc all -fc 403
gobuster dir -u https://<target> -w /usr/share/wordlists/dirbuster/common.txt -x php,txt,html,bak,old,zip
feroxbuster -u https://<target> -w common.txt -x html,js,json --depth 3
dirsearch -u https://<target> -e php,html,txt,bak,zip

# Filter out the noise every time
ffuf ... -mc all -fc 404,401,403,500
```

```bash
# Virtual host discovery. Frequently finds whole apps that DNS does not show.
ffuf -w subs.txt -u https://<target> -H "Host: FUZZ.<domain>" -mc all -fc 302
gobuster vhost -u https://<target> -w common-hostnames.txt -b acme
```

```bash
# Historical URLs, where old and forgotten endpoints live
waybackurls <domain> > urls.txt
gau --subs <domain> > urls.txt
katana -u https://<target> -d 3 -jc -kf all -o urls.txt
```

```bash
# Everything the target advertises to search engines
amass enum -passive -d <domain> -o subs.txt
subfinder -d <domain> -o subs.txt
```

### Always check these on a web target

```bash
curl -s https://<target>/robots.txt
curl -s https://<target>/.git/HEAD                  # exposed repository
curl -s https://<target>/.env                       # leaked environment file
curl -s https://<target>/.DS_Store
curl -s https://<target>/backup.zip
curl -s https://<target>/wp-config.php.bak
curl -s https://<target>/config.php.bak
curl -s https://<target>/server-status              # Apache
curl -s https://<target>/.svn/entries               # Subversion
curl -s https://<target>/WEB-INF/web.xml            # Java apps
curl -s https://<target>/elmah.axd                  # .NET error logs
```

`robots.txt` and page source are free, legal, and frequently contain the answer.
They were the entire basis of the Anthem writeup in this repo. Never skip them
because they feel too simple.

---

## Wordlists and where they live

Path memorisation saves real time. Confirm yours with `ls` before relying on any
of it, since installs differ.

| Path | Contents |
|---|---|
| `/usr/share/wordlists/` | Everything below, on Kali |
| `/usr/share/wordlists/dirbuster/dir-list-2.3-medium.txt` | General web content discovery |
| `/usr/share/seclists/Discovery/Web-Content/` | Large and finely sorted web lists |
| `/usr/share/seclists/Discovery/DNS/` | Subdomain brute force |
| `/usr/share/seclists/Passwords/` | Password lists, split by size |
| `/usr/share/seclists/Users/` | Username lists |
| `/usr/share/wordlists/rockyou.txt` | The classic. Also `.txt.gz` on newer installs |
| `/usr/share/nmap/nselib/data/` | Nmap's own usernames and passwords |

```bash
ls /usr/share/wordlists/
ls /usr/share/seclists/
sudo apt install seclists          # if the seclists directory is missing
```

**Context beats size.** A 14 million line list against a login form is both
slow and worse than a targeted list, because targeted wordlists have real
passwords in them. Always try the obvious company-specific and role-specific
guesses first.

---

## Low-noise versus thorough

Know which mode you are in before you start, because switching mid-scan is how
you get noticed.

**Low-noise.** Client networks with active monitoring. Targeted ports only,
`-T2` or slower, no `-sU` sweep, no `vuln` scripts, no fuzzing. Confirm every
action in the RoE.

**Thorough.** CTF, HTB, your own infrastructure, or an engagement that
explicitly allows it. Full port range, `-sV -sC`, wordlists, and the automated
tooling.

**Default in a real engagement.** Low-noise, targeted, with the reasoning
written down. The client paid for a considered assessment, not a loud scan. If
you are unsure which mode you are in, you are in the cautious one.

---

## When the usual tools do not work

Nmap will get blocked, tools will crash on odd banners, and half your toolbox
may be missing. Hand work is the fallback that never fails.

```bash
# Raw port checks without nmap
nc -zv <target> 445
nc -zv <target> 1-1024
curl -s https://<target>/ -o /dev/null -w "%{http_code}\n"   # just the status code
curl -sv https://<target>/ 2>&1 | grep -i "server\|x-powered\|location"

# HTTP without curl, using openssl and bash
printf 'GET / HTTP/1.1\r\nHost: <target>\r\nConnection: close\r\n\r\n' | openssl s_client -quiet -connect <target>:443 2>/dev/null

# Python one-liners when curl is unavailable
python3 -c "import requests; r=requests.get('https://<target>',timeout=10,verify=False); print(r.status_code, r.headers)"
python3 -c "import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(('<target>',445)))"
```

If a tool is missing entirely, install it. If you cannot install it, the
`curl`, `nc`, `openssl`, `bash`, and `python3` set above covers most of what
nmap and gobuster would have done.

**And when a target fights back.** Rate limits, IP bans, and WAF blocks on a
host you are authorised to test usually mean one of three things: you are going
too fast, you are missing an API key, or you are missing a header. All three are
covered in [evasion-and-bypass.md](evasion-and-bypass.md).

Do not respond to a block by switching to a different IP to get around it. On a
real engagement that is out of scope and can break the client's monitoring
without them telling you. Slow down, or ask.
