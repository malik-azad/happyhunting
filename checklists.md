# Checklists

Printable, tick-box versions of the process. Run them in order. The value is in
not skipping, not in the individual items.

## Contents

- [Pre-engagement](#pre-engagement)
- [Recon](#recon)
- [Web application](#web-application)
- [API](#api)
- [Initial access and foothold](#initial-access-and-foothold)
- [Privilege escalation, Linux](#privilege-escalation-linux)
- [Privilege escalation, Windows](#privilege-escalation-windows)
- [Post-exploitation](#post-exploitation)
- [Reporting](#reporting)
- [Exam day](#exam-day)

---

## Pre-engagement

Nothing here is technical and all of it prevents the worst outcomes.

- [ ] Written authorisation exists, and I have a copy
- [ ] Scope is written down: IPs, ranges, domains, excluded targets
- [ ] Permitted ports and protocols are stated
- [ ] Permitted testing methods are stated
- [ ] Rate limits are stated and written into my scan plans
- [ ] Time window agreed, including timezone
- [ ] Denial of service is confirmed as prohibited or permitted
- [ ] Social engineering and physical testing confirmed as out of scope
- [ ] Data handling agreed: what I may read, what I may store, what I must delete
- [ ] Emergency contact available, and I know when to use them
- [ ] Encryption required for data transfer, and I have the method
- [ ] I understand that finding a vulnerability does not entitle me to exploit it further

---

## Recon

### Local and network

- [ ] Local interfaces, addresses, and routes recorded
- [ ] ARP table and neighbours reviewed
- [ ] Live hosts identified in scope
- [ ] DNS records collected: A, NS, MX, TXT, CNAME
- [ ] Zone transfer attempted, result recorded either way

### Scanning

- [ ] Ports in the agreed scope, or full range if permitted
- [ ] Timing appropriate to the engagement's noise tolerance
- [ ] Version detection performed
- [ ] Default scripts run, with results reviewed rather than skimmed
- [ ] Results saved in greppable and XML format
- [ ] Open ports reviewed for anything unexpected
- [ ] Anything unexpected investigated, not just noted

### Per service

- [ ] SMB: version, shares, null session, users, groups
- [ ] DNS: zone transfer, subdomains, nameservers
- [ ] SNMP: default community strings
- [ ] FTP: anonymous access, writable directories
- [ ] HTTP/HTTPS: virtual hosts, headers, default pages
- [ ] Mail: names, VRFY, relay testing only if in scope
- [ ] LDAP: anonymous bind, naming contexts
- [ ] Kerberos: domain name, controllers, enum with valid credentials
- [ ] Databases: default credentials, anonymous access

### Web enumeration

- [ ] robots.txt read
- [ ] sitemap.xml read
- [ ] security.txt read
- [ ] Page source read on every distinct template
- [ ] Source maps checked
- [ ] JavaScript collected and searched for endpoints, keys, hostnames
- [ ] Content discovery run
- [ ] Virtual host discovery run
- [ ] Subdomains enumerated and resolved
- [ ] Historical URLs collected
- [ ] Exposed files checked: .git, .env, .DS_Store, backups, .svn
- [ ] Technology stack fingerprinted and version pinned

---

## Web application

### Before testing

- [ ] Two accounts created, for cross-account testing
- [ ] Account used for testing is not an administrator
- [ ] Request logging enabled in the proxy
- [ ] Every request reproducible outside the browser

### Authentication

- [ ] Registration and login flows mapped
- [ ] Password reset flow read end to end
- [ ] Reset token entropy, expiry, and single-use checked
- [ ] Session ID changes on login
- [ ] Session ID changes on logout
- [ ] Old session invalid after logout
- [ ] Cookie flags checked: HttpOnly, Secure, SameSite
- [ ] Rate limiting tested on login, gently
- [ ] Account enumeration: different message, different timing, or none
- [ ] MFA bypass considered, where MFA exists
- [ ] Session timeout configured

### Authorisation

- [ ] Every authenticated endpoint tested for IDOR, across all methods
- [ ] Horizontal access tested, two accounts
- [ ] Vertical access tested, low user against admin function
- [ ] Hidden admin panels found and tested
- [ ] API endpoints checked separately from the UI
- [ ] File download and export endpoints checked
- [ ] Websocket message authorisation checked

### Input handling

- [ ] Every parameter tested for injection
- [ ] Search, filter, and sort parameters specifically, they are the usual ones
- [ ] File upload tested for type, name, content, and location
- [ ] Reflected input tested for XSS
- [ ] Stored input tested for XSS, including in authenticated areas
- [ ] URL parameters tested for SSRF
- [ ] Any parameter naming a file tested for traversal
- [ ] Template-rendered input tested for SSTI
- [ ] XML input tested for XXE
- [ ] Serialised data identified and tested for deserialisation

### Business logic

- [ ] Price and quantity fields tamper-tested
- [ ] Coupon and discount logic tested
- [ ] Multi-step flows tested for skipped steps
- [ ] Race conditions tested on payment and one-time actions
- [ ] Approval workflows tested for state jumping
- [ ] Account linking tested for unverified ownership

### Output and headers

- [ ] Response headers reviewed
- [ ] Security headers assessed
- [ ] CORS policy tested
- [ ] Error pages checked for information disclosure
- [ ] Sensitive data absent from responses, checking every field
- [ ] Directory listing checked
- [ ] API keys absent from client-side source

---

## API

- [ ] Documentation located, or all common paths tried
- [ ] Schema extracted if OpenAPI is exposed
- [ ] Endpoints extracted from JavaScript and mobile apps
- [ ] All API versions enumerated and compared
- [ ] Authentication scheme identified
- [ ] Token claims decoded and reviewed
- [ ] Token signature verified, algorithm confusion tested
- [ ] Two accounts created
- [ ] Object inventory built for every resource type
- [ ] BOLA tested on every endpoint taking an identifier
- [ ] Method-level authorisation checked: GET, PUT, PATCH, DELETE
- [ ] Nested resources tested
- [ ] Mass assignment tested with unexpected fields
- [ ] Response fields reviewed for excessive exposure
- [ ] Rate limiting tested, gently
- [ ] GraphQL introspection attempted
- [ ] GraphQL field-level authorisation tested per type
- [ ] GraphQL mutations tested, they are often weaker
- [ ] Method override and content-type switching tested
- [ ] Every finding re-verified with a clean reproduction

---

## Initial access and foothold

- [ ] Entry point documented precisely
- [ ] Access level recorded: user, group, service account
- [ ] What was accessed to prove it, and only that
- [ ] No data retained beyond the proof
- [ ] Access achieved through a legitimate method, not an accident
- [ ] Access stable enough to work from, or a tunnel built
- [ ] Host fully enumerated before moving on

---

## Privilege escalation, Linux

- [ ] Current identity and groups recorded
- [ ] `sudo -l` checked
- [ ] Kernel version and OS version recorded
- [ ] SUID binaries enumerated and each one considered
- [ ] SGID binaries enumerated
- [ ] Capabilities checked with getcap
- [ ] Cron jobs and timers read, and scripts checked for writability
- [ ] Systemd units read
- [ ] `$PATH` checked for writable directories
- [ ] Sudo rules checked for bare command names and writable binaries
- [ ] World-writable files checked
- [ ] NFS exports checked
- [ ] Kernel and service versions matched against known issues
- [ ] Password reuse tested against services already authenticated to
- [ ] SSH keys, config files, and shell history read
- [ ] Container escape vectors checked if containerised
- [ ] New identity confirmed with `id`, not assumed

---

## Privilege escalation, Windows

- [ ] `whoami /all` recorded
- [ ] Privileges on the current token reviewed
- [ ] Group memberships reviewed
- [ ] Local users and Administrators group listed
- [ ] Impersonation or AssignPrimaryToken privilege present, noted
- [ ] SeDebugPrivilege present, noted
- [ ] Services enumerated with their binary paths
- [ ] Service paths checked for unquoted spaces
- [ ] Service binary and directory permissions checked
- [ ] Registry autoruns read
- [ ] Scheduled tasks read, and their scripts checked for writability
- [ ] Winlogon keys read
- [ ] AlwaysInstallElevated checked
- [ ] Installed software and versions fingerprinted
- [ ] Credential Manager, PowerShell history, and unattend files read
- [ ] New identity confirmed with `whoami /priv`

---

## Post-exploitation

Only with explicit permission for each item.

- [ ] Domain and AD context understood, if applicable
- [ ] Local credential stores checked
- [ ] Cached credentials, tickets, and sessions reviewed
- [ ] Internal network mapped, pivoting only where agreed
- [ ] Additional hosts in scope discovered and confirmed
- [ ] Persistence demonstrated only if it is the agreed objective
- [ ] Lateral movement demonstrated only if agreed
- [ ] No persistence left behind
- [ ] No accounts created
- [ ] No keys or credentials retained
- [ ] Evidence collected and organised
- [ ] Everything cleaned up, or a list of changes handed to the client

---

## Reporting

- [ ] Every finding reproduced from scratch, in order, by me
- [ ] Every finding cross-checked with a second method
- [ ] Benign control tested, does the payload also trigger on harmless input
- [ ] Every finding proven, or explicitly marked as suspected
- [ ] Severity justified, and consistent with the impact described
- [ ] Full requests and responses included, redacted
- [ ] Steps reproducible by someone who has never seen the system
- [ ] Impact written in business language
- [ ] Remediation specific, not generic
- [ ] Real personal data redacted
- [ ] Executive summary written for someone non-technical
- [ ] Scope, methodology, and limitations documented
- [ ] Confirmed findings separated from unconfirmed ones
- [ ] Screenshots referenced and legible
- [ ] Nothing included that the client has not seen
- [ ] Delivery method confirmed, and encrypted if required

---

## Exam day

- [ ] Machine note taken, and the time
- [ ] Host discovered, ports enumerated, services fingerprinted
- [ ] All four AttackBox or Kali boxes working, and adapters configured
- [ ] Foothold script tested before relying on it
- [ ] A web shell and a reverse shell prepared in advance
- [ ] A few privesc one-liners to hand
- [ ] Note-taking structure ready, headings created up front
- [ ] Screenshot directory created, and naming scheme decided
- [ ] Flags noted with their task number as you find them
- [ ] Everything in the report as I go, not at the end
- [ ] Reversion, snapshot, or reset, so I can go back
- [ ] Flag and user hash confirmed before the box times out
- [ ] Report completed with steps as evidence, not from memory
