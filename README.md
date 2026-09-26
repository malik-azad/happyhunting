# happyhunting

Field notes for offensive security. Sixteen sheets, written in plain language,
meant to be read once through in order and then used as reference.

The goal is narrow: a sheet should save you an hour of rediscovering something.
Nothing here is a certification summary, nothing is filler, and nothing is
generated boilerplate. If a tool has a flag you do not remember, the sheet
tells you what it does.

Every sheet works in a browser, in a terminal, or both. If you have never opened
DevTools, start with [browser-and-gui.md](browser-and-gui.md); it is a complete
assessment method on its own and it is the fastest route to real findings.

## Contents

### Start here

| Sheet | Covers |
|---|---|
| [field-notes.md](field-notes.md) | Scope discipline, note-taking, evidence, what to do when stuck |
| [checklists.md](checklists.md) | Tick-box lists for every phase, recon through exam day |
| [recon.md](recon.md) | Host discovery, nmap, per-service enumeration, wordlist locations |

### Application testing

| Sheet | Covers |
|---|---|
| [browser-and-gui.md](browser-and-gui.md) | DevTools panel by panel, reading and editing a live app, GUI tools, setting up a proxy |
| [web-testing.md](web-testing.md) | Web app assessment, the bug classes that pay, browser and CLI paths for each |
| [owasp-top-10.md](owasp-top-10.md) | The current OWASP Top 10:2025, with payloads, detection, proof and remediation per category |
| [rce.md](rce.md) | Remote code execution by vector: injection, upload, templates, deserialisation, XXE, SSRF, CI/CD |
| [api-testing.md](api-testing.md) | REST and GraphQL, authentication, BOLA and IDOR, mass assignment |
| [source-code-review.md](source-code-review.md) | Reading code for vulnerabilities, authorisation model review, secrets, dependencies, IaC |
| [mobile.md](mobile.md) | Android and iOS static analysis, IPC, WebView, certificate pinning |
| [bug-bounty.md](bug-bounty.md) | Scope, recon at scale, triage, deduplication, reporting |

### Post-exploitation

| Sheet | Covers |
|---|---|
| [privilege-escalation.md](privilege-escalation.md) | Linux and Windows, in enumeration order |
| [active-directory.md](active-directory.md) | Kerberos, BloodHound, ACL abuse, DCSync, delegation |
| [pivoting.md](pivoting.md) | SOCKS proxies, tunnels by protocol, SMB pivoting, routing |

### Access and infrastructure

| Sheet | Covers |
|---|---|
| [password-attacks.md](password-attacks.md) | Hash cracking, spraying, relay, and the lockout rule |
| [cloud-and-containers.md](cloud-and-containers.md) | AWS, Azure, GCP, metadata, Docker, Kubernetes |
| [evasion-and-bypass.md](evasion-and-bypass.md) | Low-noise testing, WAF and filter bypass, EDR awareness |

---

## Where to start

**Never tested before.** Read [field-notes.md](field-notes.md) first. It covers
the parts of the job that are not technical, and those are the parts that decide
whether you are still working in three years. Then [recon.md](recon.md) and
[checklists.md](checklists.md) end to end, then do a lab machine without
peeking.

**Comfortable with labs, want a job.**
[browser-and-gui.md](browser-and-gui.md) first, because it is the highest-value
hour in web security and most people skip it. Then [web-testing.md](web-testing.md)
and [api-testing.md](api-testing.md), which is where the interview questions
and the real findings live. [source-code-review.md](source-code-review.md) is
what separates a tester from a scanner, and reading code is the most common
thing clients ask for that nobody volunteers.

**Doing web engagements.** [owasp-top-10.md](owasp-top-10.md) is the current
mapping, so your report speaks the same language as the framework the client
already uses. [rce.md](rce.md) is the one to study before the call that will
probably decide the severity of your report.

**Doing engagements.** [privilege-escalation.md](privilege-escalation.md),
[active-directory.md](active-directory.md) and
[evasion-and-bypass.md](evasion-and-bypass.md) carry the weight. Client
environments have EDR, WAFs, and change windows, and you will need to work
inside them rather than around them noisily.

**Preparing for OSCP or CPENT.** Both are practical. The exam machines reward
the order in [checklists.md](checklists.md), executed without the machine
fighting you. [active-directory.md](active-directory.md) is worth more study
time than most people give it, especially for CPENT.

---

## Four things worth knowing before you read any of it

**Order matters more than it looks.** Almost every wasted week in this field
comes from skipping recon and going straight to exploitation. The sequence in
the sheets is the sequence that works.

**You do not need a terminal to be a good tester.** Every web and API class in
these sheets has a DevTools route, and for access control, business logic, and
client-side bugs the browser is the better instrument. The command line is for
scale and for the parts that genuinely need it. Being CLI-only is a habit, not
a skill, and it puts a ceiling on what you can find.

**Tools change, order does not.** Every command has a plain explanation beside
it. Learn to do the core work by hand first, and treat automation as an
accelerant rather than a replacement. A tool you do not understand is a tool you
cannot troubleshoot at 2am.

**A scanner is a lead generator, never a conclusion.** Everything it finds goes
through the three-step rule in [field-notes.md](field-notes.md): reproduce it,
cross-check it with a second method, and run a benign control. Only then is it
confirmed.

---

## How the sheets are written

Every technique, where it makes sense, follows the same five beats. Knowing the
shape means you can fill in a gap you have not read yet.

1. **What it is** and where it shows up in a real application.
2. **How to detect it**, with the cheapest test first.
3. **The payloads**, grouped by what they are trying to prove.
4. **How to prove it minimally**, which is almost always less than you assume.
5. **How to report it**, and the remediation, in a table.

Commands come with the explanation attached, because a line you copied without
understanding is a line you cannot adapt when the target is different.

---

## Corrections and contributions

Corrections are welcome, especially the "this flag no longer works on current
versions" kind. If something here is wrong or outdated, open a pull request and
say which version you tested on. Include a working proof where the finding is
a vulnerability, and keep real target data out of it.

If you find a sheet missing a technique you have used in anger, that is a gap
worth filling. Bug classes that are genuinely missing, corrections to a payload,
and better explanations of something that is currently unclear are all welcome.

Licensed under the MIT licence, so use it, adapt it, and teach from it.

---

## Scope and ethics

Everything in this repository documents techniques for systems you own or have
**explicit written authorisation** to test. Nothing here is for reaching systems
you have not been authorised to reach.

The practice assumed throughout is that a penetration test is a scoped
engagement with an agreement about what is permitted, agreed before the first
packet is sent. Scope gets amended mid-test more often than anyone expects, so
re-read it. A host being reachable does not make it yours.

The material in [evasion-and-bypass.md](evasion-and-bypass.md) exists so you can
test whether a control actually holds, and the section on operational safety in
that file is worth reading twice. The same applies to
[rce.md](rce.md), which opens with a proof-minimal rule: a marker rendered by
the target is a complete finding, and a reverse shell is not a more convincing
one. **Prove access, then stop.** A boolean differential is a complete proof for
injection. One line of a target file is a complete proof for traversal. Reading
further is not thoroughness, it is an incident waiting for an approver who is
not there.

If you find a vulnerability in a system you are not authorised to test, report
it to the owner through their published disclosure process and stop there.

---

## Related

Lab writeups, with recon and exploitation documented end to end, are in
[ctf-writeups](https://github.com/malik-azad/ctf-writeups).
