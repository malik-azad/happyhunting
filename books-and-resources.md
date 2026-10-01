# Books and Resources

The sheets in this repository are written from practice. This file is where the
underlying theory and the free reference material live, so you can go deeper on
anything the sheets summarise.

Two rules for using this list. **Prefer the free resources** unless you want the
depth, because most of the field's best material costs nothing. And **check the
edition** before buying, since several of these have been revised and the
command syntax in older editions is stale.

---

## Contents

- [The core four](#the-core-four)
- [Web application security](#web-application-security)
- [Exploitation and reverse engineering](#exploitation-and-reverse-engineering)
- [Infrastructure, cloud and containers](#infrastructure-cloud-and-containers)
- [Active Directory](#active-directory)
- [Windows internals](#windows-internals)
- [Reporting, process and professionalism](#reporting-process-and-professionalism)
- [Free resources worth more than most books](#free-resources-worth-more-than-most-books)
- [Practice labs](#practice-labs)
- [How to keep up](#how-to-keep-up)
- [A note on certificates](#a-note-on-certificates)

---

## The core four

If you read four books, read these. Between them they cover web, code, and
process, which is the whole job.

**The Art of Software Security Assessment** — Mark Dowd, John McDonald, Justin
Schuh. Two hundred pages on finding vulnerabilities by reading code, and the
clearest explanation of taint-style dataflow tracing I have found anywhere.
This is the book that most directly makes you better at the job, and almost
nobody has read it. Pairs with [source-code-review.md](source-code-review.md).

**The Web Application Hacker's Handbook** — Dafydd Stuttard, Marcus Pinto. The
reference the whole web security field is built on. Dense, occasionally dated in
its tooling, and still the best single description of how web vulnerabilities
actually work. Use it for the reasoning, not the payloads.

**Web App Hacker** (Hands-On Web App Testing) — Gordon Ross. The practical
counterpart. Short, current, and readable start to finish. If the Handbook is
the theory, this is the workflow.

**The Penetration Tester's Handbook** — Johnny Long and others. Process, scoping,
reporting, and the business of testing. The chapters on report writing are worth
more to your career than another exploitation book, because a finding nobody
can act on is worth nothing.

---

## Web application security

**The Tangled Web** (Web Security for Developers) — Malcom Richardson. Explains
*why* the web is the way it is: the browser's same-origin policy, the DOM, and
why XSS is inevitable rather than a bug. Best book for making the browser
model click.

**Bulletproof SSL and TLS** — Ivan Ristić. The definitive TLS reference. If you
are writing anything about [A04 Cryptographic Failures](owasp-top-10.md) from
memory, read the relevant chapter instead.

**Web Application Security for Dummies** — not in this list. Avoid books that
promise to make you a penetration tester in a weekend.

**The Web Application Hacker's Handbook** also remains the best reference for
the specific mechanics behind the classes in
[web-testing.md](web-testing.md) and [rce.md](rce.md).

---

## Exploitation and reverse engineering

**Hacking: The Art of Exploitation** — Chris Stevens, Jon Erickson. Program
exploitation and memory corruption from first principles. Not web-focused at
all, and the reason you will understand what a buffer overflow actually is.

**The Shellcoder's Handbook** — Chris Anley, John Heasman, Felix Lindner, Gerardo
Richarte. Shellcode and exploitation of memory corruption, from several angles.

**Gray Hat Hacking** — Steve Shostack, Bryan Allen Thomson, Adam Brundage,
(ANSI press), with the Evolving Exploits material. Good on the tradeoffs between
offensive and defensive work.

**Practical Reverse Engineering** — Bruce Dang, Alexandre Gazet, Elias
Bachaalany. For when you need to understand a binary rather than just run
strings against it.

**SEI/ CERT and the MITRE ATT&CK documentation.** Not a book, but the technique
catalogue the rest of the field maps onto. Free, and it teaches you how to
think about behaviour rather than isolated vulnerabilities.

---

## Infrastructure, cloud and containers

**Container Security** — Liz Rice. The best available explanation of container
risk, and written by someone who has broken containers professionally. Pairs
with [cloud-and-containers.md](cloud-and-containers.md).

**Kubernetes Security** — Liz Rice, with Michael Kerr. The RBAC, network policy,
and secrets model, done properly.

**Security Chaos Engineering** — Casey Rosenthal. How to test that your
detections and your assumptions still hold, which is the part of security
testing nobody outside the industry talks about. Also the best practical
argument for [A09](owasp-top-10.md).

---

## Active Directory

Active Directory is the deepest well in offensive security and the one place
where books genuinely help, because the attack paths are non-obvious and the
tooling does not explain them.

**Active Directory Security** — Steve Wright. Older but still the clearest
explanation of Kerberos and how delegation actually works, which is the
prerequisite for understanding [active-directory.md](active-directory.md).

**The Red Team Field Manual (RTFM)** — a collective work, published 2016. Dense
reference material on red teaming including Active Directory. Check whether a
newer edition exists before buying, since the tooling sections will be dated.

**Practical Active Directory** material worth reading over a book: the
[NTF Security](https://security.ntf.com/) and [adsecurity.org](http://adsecurity.org/)
references. The Microsoft documentation for the Kerberos protocol is genuinely
readable, and understanding MS-PAC and MS-KERB is what makes BloodHound output
make sense. Free.

---

## Windows internals

**Windows Internals, Part 1** — Pavel Yosifovich, Mark Russinovich, Alex
Ionescu, David Solomon. The process, memory and token model. Read it and
Windows privilege escalation stops being a checklist and becomes reasoning,
which is what [privilege-escalation.md](privilege-escalation.md) is trying to
teach you.

**Windows Internals, Part 2** — the same authors. Filesystems, registry, and
the kernel. Deeper than most engagements need.

---

## Reporting, process and professionalism

This is the category nobody reads and everybody needs.

**The Penetration Tester's Handbook** — already listed above, and the reporting
chapters are the part to prioritise. It covers scoping, rules of engagement,
severity argument, and the conversation when a client disagrees with your
rating, which every tester eventually has.

**Public Pentesting Reports** are a genuinely useful free resource. Read the
published reports from HackerOne, GitHub Security Lab, Google, and Cure53. They
show you what a client actually wants: a clear impact statement, a reproduction
path, and a fix. It is the fastest way to learn report structure and it costs
nothing.

**Bug Bounty disclosure reports** serve the same purpose and are usually
better, because they show you severity and impact calibrated to a real bounty
table.

---

## Free resources worth more than most books

Be honest about this section: most of what you need is free, and the free
material is more current than anything you can buy.

**PortSwigger Web Security Academy** — free, hands-on, and the best web
training that exists. Every class in [owasp-top-10.md](owasp-top-10.md) has a
matching lab here, and the explanations are as good as most books. If you do
exactly one thing from this list, do this.

**OWASP Web Security Testing Guide** — the full testing methodology, free and
open. The reference version of what the sheets here compress.

**OWASP Cheat Sheet Series** — short, specific, and correct on remediation. Use
these when writing the fix section of a report.

**OWASP ASVS** — the verification standard. Useful as a scoping document, because
it is written as a list of things that *should* be true, which makes it an
excellent checklist to hand a client.

**HackTricks** — a single enormous page of techniques across every category.
It reads like notes taken by someone with a lot of field experience, which is
exactly what it is. Excellent for the one technique you have not met yet.

**PayloadsAllTheThings** — the payload library, organised by vulnerability
class and by binary format. A lookup table rather than a tutorial.

**MITRE ATT&CK** — technique, tactic and procedure catalogue. The best mental
model for adversary behaviour, and the vocabulary defenders use.

**CISA and CERT advisories, and the CVE database.** Learning to read a CVE
entry properly, including the CVSS vector, is more valuable than it sounds.

**Google Project Zero and Project Zero blog posts.** Deep, free, and written by
people who find real bugs. Reading one post a month changes how you think.

---

## Practice labs

You cannot become good at this from reading. The theory sheets are a map; the
skill is in the repetition.

**TryHackMe** — guided and beginner-friendly, with a large free tier. Use it
first and use the walkups in [ctf-writeups](https://github.com/malik-azad/ctf-writeups)
when you get stuck rather than before you try.

**HackTheBox** — more realistic and less hand-holding. Machines and the Pro
labs, including Active Directory and cloud tracks.

**PG Practice, and the retired Offensive Security Proving Grounds** — ad hoc
labs built from real-world engagement material. The closest thing to a live
engagement you can get legally.

**PortSwigger Academy labs** — for web specifically, and free.

**CyberDefenders** — blue-team and forensics material, useful if you want to
understand the detection side of your own findings.

---

## How to keep up

You cannot read your way to currency. Pick two of these and let them set your
reading list.

- PortSwigger Research and the PortSwigger Daily Swig, which summarises daily
- Google Project Zero, for depth
- NCC Group and Trail of Bits blogs, for high-quality public research
- The advisory feeds for the tools you actually use
- CVE feeds filtered to the technologies you are targeting

The honest answer is that you will learn more from one properly written public
research post than from a book, because it is recent and it shows a real process
rather than a catalogue of outcomes.

---

## A note on certificates

Certifications are useful for getting past a resume filter and for the structured
syllabus, which has value when you are learning alone. They are not a substitute
for practice, and they are not what a client is buying when they hire you.

What clients actually buy is judgement: knowing whether a finding is real,
knowing how to prove it without breaking anything, and knowing what to do when
you find something you were not authorised to look for. That comes from doing
engagements and being wrong occasionally enough to develop a sense of when you
might be wrong now.

If you are going to take one, pick it for the lab access rather than the letters.

---

## Related

- [field-notes.md](field-notes.md) — the process, evidence, and discipline that
  the books describe and the labs teach
- [checklists.md](checklists.md) — the ordered version of everything above