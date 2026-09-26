# Field Notes

The parts nobody teaches you. The professional habits that decide whether a
test is worth what it cost, as opposed to a pile of unauthenticated shell
screenshots.

## Contents

- [The parts nobody teaches you](#the-parts-nobody-teaches-you)
- [Scope discipline](#scope-discipline)
- [Note-taking](#note-taking)
- [Evidence](#evidence)
- [Verify before you believe it](#verify-before-you-believe-it)
- [When you are stuck](#when-you-are-stuck)
- [Common beginner mistakes](#common-beginner-mistakes)
- [Tools and where to get them](#tools-and-where-to-get-them)
- [Staying current](#staying-current)
- [Knowing when to stop](#knowing-when-to-stop)

---

## The parts nobody teaches you

A course will teach you to find a vulnerability. Almost none of them teach the
four things that actually determine whether you keep working as a pentester.

**You will be judged on your reports, not your shells.** A medium finding with a
clean, reproducible report beats a critical finding nobody can reproduce. The
second one gets closed as "could not reproduce" and the triage engineer moves on.

**Enumerate or lose.** The most common reason a competent person fails an exam
or an engagement is not a technique problem. It is that they did not read the
file permissions, the cron jobs, the service paths, or the access control list
that were sitting there the whole time.

**Knowing when to stop is a skill.** Proving you can read `/etc/shadow` ends
the finding. Continuing past that is not thoroughness, it is an incident
waiting for an approver who is not there.

**Most of this field is writing.** Scope documents, findings, risk ratings,
executive summaries, and the email that explains why a critical finding matters
to someone who is not technical. People who are good at the technical part and
bad at the writing part plateau faster than people who are mediocre at both.

---

## Scope discipline

The habit that keeps you out of legal trouble and keeps clients for years.

```bash
# Before you scan anything, write it down and keep it in your notes
# SCOPE
#   In:     10.10.11.0/24
#           https://shop.example.com
#           api.example.com
#   Out:    everything else
#   Rate:   max 100 packets/sec
#   Window: 22:00-06:00 local
#   Do NOT: DoS, social engineering, physical
#   Contact: <name>, <phone>
```

**Re-read scope mid-engagement.** It gets amended more often than anyone
expects. A host that was out of scope this morning may be in scope this
afternoon, and the reverse is more dangerous.

**In scope means the specific thing, not the general area.** These are the traps:

| Looks in scope | Actually |
|---|---|
| `shop.example.com` | Only that hostname, not `admin.example.com` |
| A subdomain you found | Not unless the programme says all subdomains |
| A shared host's IP | Not yours. Others' tenants live there |
| A third-party API the app calls | Not yours, whatever you found in it |
| A certificate naming a host | Certificate transparency is for reconnaissance, not authorisation |
| An employee who found a bug | They may not be the party with authority to authorise you |

**When scope is unclear, the answer is to ask, in writing, before testing.** Not
after. "I found this on a system I believe was in scope" is not a defence in any
jurisdiction, and the client will genuinely appreciate the question.

**Get written authorisation for the specific test you plan.** "You may test the
application" does not necessarily authorise password spraying, social
engineering, or physical testing, and it very rarely authorises a
denial-of-service test even against a dedicated test environment.

---

## Note-taking

Your notes are the deliverable. Write them as you go, not afterwards, because
afterwards you will not remember which request produced which response.

**Structure it before you start.** Create these headings in your notes file on
day one, so nothing has to be invented later:

```
# Engagement name
## 00 Scope and RoE
## 01 Recon
## 02 Enumeration
## 03 Finding <short name>
### Hypothesis
### Evidence
### Reproduction
### Impact
### Status
## 04 Exploitation
## 05 Post-exploitation
## 06 Report notes
## 07 Credentials and keys      <- separate, encrypted, never in the report
## 08 To do
```

**Record commands as you run them**, not from memory. Paste the actual output.

```bash
# A real finding, in raw form
$ curl -s "https://target/api/v1/invoices/1041" -H "Authorization: Bearer $TOKEN"
{"id":1041,"user_id":1042,"name":"A Customer","total":"248.00","address":"..."}
$ curl -s "https://target/api/v1/users/me" -H "Authorization: Bearer $TOKEN"
{"id":1042,"email":"me@example.com"}
# 1041 belongs to user 1042, which is not me (user 1109). BOLA confirmed.
```

**Screenshot naming.** Make them sortable and self-describing, so you can find
them when writing the report at 2am.

```
001_01-recon_nmap-full.png
002_03-bola_curl-my-user.json
003_03-bola_curl-other-user.json
004_03-bola_comparison.png
```

**Keep credentials in a separate note.** Not in the report, not in a
screenshot, not in a commit. If your tooling supports an encrypted store, use
it, and destroy the material at the end of the engagement as the RoE requires.

**Never commit real findings or credentials to a repository.** Especially not a
public one. This repo is an example of the right way: no target data, no
credentials, only methods. See the disclaimer at the bottom of the README.

---

## Evidence

If it is not evidenced, it did not happen.

**What a finding needs.**

1. A **clear statement** of what is wrong, in one sentence a non-tester can follow
2. **Exact steps**, numbered, from a clean start
3. **Raw evidence**: the request and the response, not a description of them
4. **A screenshot** showing the same thing, readable and not blurry
5. **A control**, showing what correct behaviour looks like, so the tester is not left guessing
6. **Impact**, specific and quantified
7. **Remediation**, specific to this application

**The three-step rule for proving anything.** This works for every finding class
and it is what stops you writing false positives.

```bash
# 1. Reproduce. Run the exact request again, from scratch.
# 2. Cross-check. Confirm it a second way, with a different tool or method.
# 3. Control. Show the benign case behaves differently.
```

An example across all three steps, for a suspected SQL injection:

```bash
# Reproduce: the boolean pair returns different sizes
curl -s "https://target/item?id=1' AND '1'='1" | wc -c     # 4821
curl -s "https://target/item?id=1' AND '1'='2" | wc -c     # 2103

# Cross-check: an independent method, time based
curl -s -o /dev/null -w "%{time_total}\n" "https://target/item?id=1' AND SLEEP(5)-- -"   # 5.01

# Control: benign input behaves like the false branch, so the difference is
# the injection and not the page
curl -s "https://target/item?id=2" | wc -c                # 2103, matches the false case
```

Without step 3 you do not know whether the difference is the injection or just
two different products. With it, you do.

**Redact responsibly.** Blur real names, emails, and card numbers. Keep the
structure visible so the finding is still demonstrable. State in the report that
full unredacted evidence is available privately, and send it through the agreed
channel, not in a public comment.

**Do not manipulate anything you did not create.** Change an account you
registered. Delete a test order you placed. Do not touch a real user's data even
to prove you can see it, and do not include it in a report.

---

## Verify before you believe it

Tools produce false positives constantly, and a report that does not reproduce
costs you credibility. A confirmed finding is one that survives all three of
these:

1. **Reproduction.** Run the exact request again, from a clean session.
2. **Independent confirmation.** A different tool, a different angle, a
   different method entirely.
3. **Benign control.** Show it does *not* trigger on input that should be safe.

Only then is it confirmed. Everything else is suspected, and it stays labelled
that way in your notes and in the report.

**Specific tools that produce false positives**, because you need to know where
your scepticism is required:

| Tool | Typical false positive |
|---|---|
| nuclei templates | Version banners that do not imply vulnerability |
| Nikto | Outdated and generic, most findings are noise |
| sqlmap | WAF error pages mistaken for SQL errors |
| testssl.sh | Missing headers reported as high severity |
| LinPEAS / WinPEAS | Permissions that do not translate to escalation |
| nessus / openvas | Missing headers, version disclosure, cookie flags |
| Burp scanner | Reflected XSS that is escaped on render |
| gobuster / ffuf | Extensions and 200 pages that are error pages |

**Rule: a scanner is a lead generator, never a conclusion.** Everything it finds
goes through the three-step rule before it becomes a finding.

---

## When you are stuck

A decision tree that has rescued more evenings than any tool.

```
Not finding anything?
├── Did you enumerate fully, or did you just scan ports?
│   └── Re-read the recon checklist. Permissions, cron, services, logs.
│       This is where it is, and it is boring.
├── Are you on the right host?
│   └── Check for vhosts, and check whether you need a different subdomain.
├── Are you authenticated?
│   └── A huge fraction of findings need an account. Register one.
├── Are you testing the right application?
│   └── Check for hidden directories, an API, a staging environment.
├── Are you reading the application?
│   └── Read the JavaScript. It is frequently more honest than the UI.
├── Is the app simply not vulnerable?
│   └── That happens. Move on, and document that you tested it.
└── Are you going too fast to see it?
    └── Slow down. Read the responses properly instead of scanning them.
```

**Time management.** Two hours of enumeration before exploitation is a good rule
of thumb. If you have found a foothold and have nothing after two hours, go back
to enumeration rather than trying more exploits. Exploits do not appear from
nowhere; they appear because enumeration told you where to aim.

**When to take a break.** Reading stale output at midnight is worse than
useless, because you will miss what is actually there. Sleep and come back. The
finding is still there in the morning.

**When to ask for help.** A second pair of eyes on a specific question, "is this
IDOR or am I misreading the response", resolves in five minutes what an evening
of solo confusion will not.

---

## Common beginner mistakes

Every one of these has cost real engagements time.

| Mistake | What it costs | Instead |
|---|---|---|
| Jumping to exploitation | Missing the config in front of you | Enumerate first, always |
| Running `nuclei` first | Noise, and you miss the manual-only bugs | Read the app first |
| `nmap` with no `-oA` | No greppable output, hours re-scanning | `-oA` always |
| Forgetting `-Pn` on a filtered host | False "host down" | Understand the flag |
| Trusting a scanner's severity | A "critical" that will not reproduce | Verify, every time |
| Proving more than necessary | A service incident, and a report nobody trusts | Prove, then stop |
| No notes during the test | A report written from memory, and gaps | Notes as you go |
| Testing a real user's data | A privacy incident | Test with your own account |
| Not pinning the version | CVE research you cannot use | `nmap -sV`, headers, package list |
| Skipping the boring services | The answer is in SNMP or a backup file | Check all of them |
| One huge wordlist | Slow, noisy, worse than targeted | Target your wordlists |
| Reporting before verifying | "Could not reproduce" | Three-step rule |
| Forgetting the screenshot | A finding that looks unproven | Screenshot everything |
| Assuming the UI is the API | Missing the entire API surface | Enumerate endpoints from source |

**The one that catches everyone.** The flag, the credential, or the interesting
file is usually in the least interesting place. `robots.txt`, a page-source
comment, a `hidden` meta tag, a backup file, an SNMP string, a share with an odd
name, or a file only the `administrator` group can read. The Anthem writeup in
this repo is three hours of the least interesting kind of work. That is the job.

---

## Tools and where to get them

Keep a working baseline. You do not need all of it, and an unused tool is
clutter.

```bash
# Kali ships with nearly everything. Verify your install
nmap --version
nikto -Version
sqlmap --version
gobuster --version
ffuf -V
burpsuite            # in the applications menu
```

```bash
# GitHub-hosted tools, installed on demand
# These are the ones I actually use
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/katana/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/subfinder/subfinder/v2/cmd/subfinder@latest
```

```bash
# Python
pip3 install pwntools
pip3 --break-system-packages install impacket        # AD, on newer Debian
```

```bash
 # Kernel
sudo apt update && sudo apt full-upgrade
sudo apt install seclists amass enum4linux crackmapexec
```

**Always get tools from the source repository**, and check the release page
rather than a search result. Supply-chain compromise of pentest tooling is a
real and recurring problem, because a tool that reads your credentials is an
obvious target. Verify checksums where the project publishes them.

**Build a go-to kit and keep it on every engagement machine:**

```
/opt/kit/
├── nuclei-templates/     updated weekly
├── wordlists/            seclists plus your own targeted additions
├── scripts/              your own, the ones you keep retyping
└── notes/                your own playbook
```

Your own scripts are worth more than any downloaded tool, because they encode
what you have learned about how these systems actually behave.

---

## Staying current

The tools churn constantly. The concepts do not. Balance your reading
accordingly.

**Keep up, weekly.** Kernel and package advisories for your target platforms.
`msrc` and vendor advisories. One of the many curated security newsletters
rather than all of them, because reading forty feeds means reading none.

```bash
# Track a specific technology
# RSS and release notifications for the tools you rely on
gh repo watch projectdiscovery/nuclei
gh repo watch peass-ng/PEASS-ng
```

**Learn to search for exploits by version, rather than by name.**

```bash
searchsploit <keyword>
searchsploit linux kernel 5.15
searchsploit "windows smb"

# And the habit that matters more: read the CVE, do not just run the tool.
# Understand what the vulnerability actually is, then look for it manually.
# A CVE you understand finds the bug. A CVE you have not read does not.
```

**Prioritise learning this over learning tools:** how HTTP really works, how
authentication really works, how authorisation is implemented, how NTFS
permissions actually resolve, how Kerberos really authenticates, how memory
protection works. Tools change every eighteen months. Those four ideas do not.

---

## Knowing when to stop

The part nobody teaches and everybody learns eventually.

**Stop when the finding is proven.** You have demonstrated the flaw. Reading
more data, exploiting further, or pivoting because you can is not completing
the job, it is creating an incident.

**Stop when the scope ends**, even mid-exploit. If you find yourself wondering
whether the next host is in scope, it is not, or you would not be wondering.

**Stop and call when something breaks.** A service went down, a password reset
flood hit real accounts, you deleted data, or you found something that looks
like a serious exposure. Contact the client immediately, with what you know and
what you are unsure about. That call is the most professional thing you will do
all engagement, and it is a documented, defensible part of the work.

**Stop testing a control when it becomes the objective rather than the subject.**
If a WAF is the control under assessment, you are authorised to test it. If you
are bypassing it to get somewhere you were not authorised to go, that is
different, and it is worth a conversation before you continue.

**Do not let sunk cost change your judgement.** Twenty hours in and no findings
does not mean there are findings to find. It frequently means the target is
actually reasonably secure, and that is a legitimate and valuable conclusion to
report.

**Close every engagement properly.** Data destroyed as agreed, access removed,
changes reverted, the client told what you did, and a report delivered on time.
Almost every repeat engagement I have heard about came from a client who got
that last part right.
