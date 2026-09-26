# Pentest Field Notes

Notes to self that turned into something worth sharing. Thirteen sheets covering
offensive security, written in a plain register and meant to be read once
through in order, then used as reference.

The goal is that a sheet saves you an hour of rediscovering something. Nothing
here is a certification summary and nothing is filler.

## Contents

### Core process

| Sheet | Covers |
|---|---|
| [recon.md](recon.md) | Host discovery, nmap, per-service enumeration, wordlist locations |
| [field-notes.md](field-notes.md) | Scope discipline, note-taking, evidence, what to do when stuck |
| [checklists.md](checklists.md) | Tick-box lists for every phase, recon through exam day |
| [bug-bounty.md](bug-bounty.md) | Scope, recon at scale, triage, deduplication, reporting |

### Application testing

| Sheet | Covers |
|---|---|
| [web-testing.md](web-testing.md) | Web app assessment, the bug classes that pay, JS analysis |
| [api-testing.md](api-testing.md) | REST and GraphQL, authentication, BOLA and IDOR, mass assignment |
| [mobile.md](mobile.md) | Android and iOS static analysis, IPC, WebView, certificate pinning |

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

**Comfortable with labs, want a job.** [web-testing.md](web-testing.md) and
[api-testing.md](api-testing.md) are where the interview questions and the real
findings live. [bug-bounty.md](bug-bounty.md) for the business side, which nobody
teaches you and which decides whether you get paid.

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

## Three things worth knowing before you read any of it

**Order matters more than it looks.** Almost every wasted week in this field
comes from skipping recon and going straight to exploitation. The sequence in
the sheets is the sequence that works.

**Tools change, order does not.** Every command has a plain explanation beside
it. Learn to do the core work by hand first, and treat automation as an
accelerant rather than a replacement. A tool you do not understand is a tool you
cannot troubleshoot at 2am.

**A scanner is a lead generator, never a conclusion.** Everything it finds goes
through the three-step rule in [field-notes.md](field-notes.md): reproduce it,
cross-check it with a second method, and run a benign control. Only then is it
confirmed.

---

## Corrections

Corrections are welcome, especially the "this flag no longer works on current
versions" kind. If something here is wrong or outdated, open a pull request and
say which version you tested on.

If you find a sheet missing a technique you have used in anger, that is a gap
worth filling and I would like the contribution.

---

## Scope and ethics

Everything in this repository documents techniques for systems you own or have
**explicit written authorisation** to test. Nothing here is for reaching
systems you have not been authorised to reach.

The practice assumed throughout is that a penetration test is a scoped
engagement with an agreement about what is permitted, agreed before the first
packet is sent. Scope gets amended mid-test more often than anyone expects, so
re-read it. A host being reachable does not make it yours.

The material in [evasion-and-bypass.md](evasion-and-bypass.md) exists so you can
test whether a control actually holds, and the section on operational safety in
that file is worth reading twice. **Prove access, then stop.** A boolean
differential is a complete proof for injection. One line of a target file is a
complete proof for traversal. Reading further is not thoroughness, it is an
incident waiting for an approver who is not there.

If you find a vulnerability in a system you are not authorised to test, report
it to the owner through their published disclosure process and stop there.

---

## Related

Lab writeups, with recon and exploitation documented end to end, are in
[ctf-writeups](https://github.com/malik-azad/ctf-writeups).
