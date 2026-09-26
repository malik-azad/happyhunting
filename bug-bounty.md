# Bug Bounty Playbook

Most of this field is not technical. It is reading scope carefully, not
duplicating, and writing a report that gets triaged quickly.

## Contents

- [Read the scope before anything else](#read-the-scope-before-anything-else)
- [Choosing a programme](#choosing-a-programme)
- [Recon at scale](#recon-at-scale)
- [Prioritising what to test](#prioritising-what-to-test)
- [Automation, and when it backfires](#automation-and-when-it-backfires)
- [Deduplication](#deduplication)
- [Writing the report](#writing-the-report)
- [Severity and CVSS](#severity-and-cvss)
- [Disclosure etiquette](#disclosure-etiquette)
- [The business reality](#the-business-reality)

---

## Read the scope before anything else

Every programme has its own rules, and the rules are the contract. Read them
twice, then reread them when you find something interesting, because that is
when you are most tempted to forget them.

**The things to extract, in this order:**

1. **Targets.** Domains, subdomains, mobile apps, APIs, IP ranges, other
   people's software that is explicitly in scope. Check whether a domain means
   all subdomains, because a staging or dev subdomain is a very common in-scope
   find and a very common report.
2. **Out of scope.** Explicitly excluded hosts, third-party integrations,
   social engineering, phishing, physical attacks, denial of service, and
   automated scanning above a stated rate.
3. **Testing methods permitted.** Full automation or manual only. Most
   programmes permit automation, some prohibit scanning tools entirely.
4. **Safe harbour.** The paragraph that legally protects you for testing within
   scope. Read it. If it is vague, ask the programme before testing.
5. **Rules of engagement.** Rate limits, time windows, whether you may use
   your own account only, whether you may create multiple accounts.
6. **Reporting channel and expectations.** Disclosure policy, safe harbour
   contact, PGP key for encrypted reports, response times.
7. **Bounties and ranges.** Whether there is a bounty at all, the range per
   severity, and the fame wall if you are a beginner.

**The specific things that get beginners in trouble.** Testing a domain that
looks related but is a different company's. Scanning a shared host where other
tenants live. Attacking an API without a key that you found in a public repo.
Finding a real vulnerability in a third-party service the target merely embeds,
and reporting it to the wrong programme.

**Be paranoid about shared infrastructure.** One IP addresses dozens of sites
under one CDN. Test the specific hostname, not the IP, and never port scan a
host that is on someone else's shared platform.

---

## Choosing a programme

As a beginner, prioritise learning over payout, because the first few findings
take longer than you expect.

Better first targets:
- Large, established programmes with published safe harbour and generous scope
- VDPs with a clear scope, where no bug is a bug and the feedback is fast
- Programmes that publicly list what they want fixed
- Programmes run by big bug bounty platforms, which have working triage

Avoid as a first target:
- Anything with a vague scope and no safe harbour
- Programmes with a single known public report, because the scope is not understood
- Anything where the payout depends on exploit chains against live users

A VDP is genuinely underused. No payout, but real reports, real disclosure
experience, and often a fast, courteous response. That is worth more than your
first fifty-dollar bounty.

---

## Recon at scale

The goal is a manageable list, not a giant one. A thousand subdomains you never
test is worth less than twenty you understand.

```bash
# Passive collection, in this order. All of it is out-of-band and quiet.
subfinder -d <domain> -silent -o subs.txt
amass enum -passive -d <domain> -o amass.txt
assetfinder --subs-only <domain> > asset.txt
findomain -t <domain> -q > findomain.txt

# Sources nobody searches but everybody should
certspotter -d <domain> -o certs.txt                 # certificate transparency
github-recon                          # org's public repos, git history
github-subdomains -d <domain> -o github.txt

cat subs.txt amass.txt asset.txt findomain.txt certs.txt | sort -u > all_subs.txt
```

```bash
# Which of them actually serve something
httpx -l all_subs.txt -sc -title -tech-detect -o alive.txt
# -sc  status code, -title page title, -tech-detect technology
```

```bash
# Historical URLs. Forgotten endpoints are the most fruitful thing you will find.
gau --subs <domain> > gau.txt
waybackurls <domain> > wayback.txt
katana -u https://<target> -d 3 -jc -kf all -o katana.txt
cat gau.txt wayback.txt katana.txt | sort -u > urls.txt

# Parameterised URLs are where the interesting endpoints live
grep "=" urls.txt | sort -u > params.txt
```

```bash
# Group by what the host actually is. This is the step most people skip and
# it is the step that makes recon usable.
for h in $(cat alive.txt); do echo "$h"; done
httpx -l alive.txt -json -silent | jq -r 'select(.status_code==200) | "\(.host)  \(.title)  \(.tech|join(","))"' | sort -k3

# The two queries that always pay off
# 1. Everything that is not the main site
# 2. Everything running something unusual
```

```bash
# Takeover candidates. A dangling DNS record on someone else's service
nuclei -l alive.txt -t takeovers/ -severity critical,high
subfinder -d <domain> -silent | httpx -silent -json | jq -r 'select(.status_code!=200) | .host' | nuclei -t takeovers/
```

A subdomain that resolves to a service nobody claimed, where you can create
the matching resource, is a subdomain takeover. It is common, it is often
genuinely high severity, and it is verifiable with one screenshot.

---

## Prioritising what to test

Rank by **impact times ease**, and test the easy high-impact things first. This
is the opposite of what feels satisfying, and it is why a lot of good
researchers submit fewer, better reports.

| Priority | Target | Why |
|---|---|---|
| 1 | Subdomain takeover | Trivially verifiable, often high severity |
| 2 | Missing security headers on sensitive pages | Fast, but low payout, so do them in bulk |
| 3 | IDOR on any authenticated endpoint | High impact, no payload crafting |
| 4 | Exposed secrets, keys, and backups in the repository | One grep, sometimes a critical |
| 5 | Out-of-scope-looking subdomain that is in fact in scope | Read the scope rule carefully |
| 6 | Anything behind a login you can register for | The majority of real web findings |
| 7 | GraphQL, file upload, business logic | Higher effort, higher reward |

```bash
# Repository secrets, which is the highest value automated check there is
# Clone the target's public repos and look at history, not just the tip
git clone --depth 1 https://github.com/<org>/<repo> && cd <repo>
trufflehog filesystem .                    # works on history, not just working tree
trufflehog git file://.                   # full history scan
gitleaks detect --source . --log-opts="--all"
git log -p --all | grep -iE "password|secret|api[_-]?key|token" 
```

Finding a live API key in a public repository is a very common and very
high-value finding. It is also the one that requires care: prove the key works
against the service it belongs to, and only that service.

---

## Automation, and when it backfires

Automated finding submission is the single most complained-about behaviour in
bug bounty, and several programmes now ban it outright.

```bash
# Reasonable: a tool you are driving and reviewing
nuclei -l alive.txt -severity critical,high -o nuclei.txt      # hundreds of findings
nuclei -l alive.txt -t takeovers/ -severity high -o takeover.txt

# Not reasonable: submitting automatically
# Sending every nuclei result to a programme destroys your reputation and gets
# you banned. It is also lazy, and it will not get you paid.
```

Rules that keep automation acceptable:

1. Review every automated result before you do anything with it. An unverified
   automated finding is a report that gets rejected and a reputation cost.
2. Respect the stated rate limit, always. It is there because the target's
   infrastructure is production.
3. Never scan out of scope because an automated tool decided to.
4. Do not run heavy scanners against third-party services embedded in the
   target's page. You are only authorised to test the target.

---

## Deduplication

The most common reason a valid finding pays nothing.

```bash
# Search the programme's existing reports on HackerOne and Bugcrowd.
# They are public, and a critical finding there is almost always a dupe.
# Search by: the product name, the endpoint, the vulnerability class.

# Also check the target's own changelog and release notes. A fixed CVE means
# an already-reported issue.
```

Before you invest hours in a finding, search for it. Then do not simply submit
anyway and hope. A duplicate of a known issue is not a bounty, and repeated
duplicates can get your account suspended.

The finding most likely to be a dupe is the one that is most exciting. That is
not a coincidence.

---

## Writing the report

A good report is short, structured, and reproducible by a stranger. Triage
engineers read many reports a day. Make theirs easy.

Include these sections, in this order:

1. **Title.** Precise and technical. `IDOR on /api/v1/invoices/{id} allows access to any user's invoices`, not `I found a security issue`.
2. **Summary.** Two sentences. What the flaw is and what it lets an attacker do.
3. **Severity.** Your assessment, with justification.
4. **Steps to reproduce.** Numbered, exact, copy-pasteable. Include the full request including headers.
5. **Evidence.** Screenshots, raw requests and responses, redacted. A `curl` command is better evidence than a description of one.
6. **Impact.** Written in business language. What does the attacker get, how many users, what data, and does it need user interaction.
7. **Remediation.** Specific to this application, not generic advice.

```bash
# A reproducible request is the strongest evidence you can give.
curl -s https://<target>/api/v1/invoices/1041 \
  -H "Authorization: Bearer <token-of-account-A>" | jq .
```

What separates an accepted report from a rejected one:

| Rejected | Accepted |
|---|---|
| Description with no steps | Numbered steps and a raw request |
| Impact stated as "could be dangerous" | Impact stated as "reads any user's invoices including address and payment method" |
| Your own account, guessed that others exist | Two accounts, side by side, clearly labelled |
| Unredacted third-party personal data | Blurred, with a note that real data is available on request |
| No remediation | One specific, actionable paragraph |

Redact responsibly. Do not paste real personal data into a public report. Blur
names, emails, and phone numbers, and state in the report that full unredacted
evidence is available privately to the programme. Programmes will ask for it
through the proper channel.

---

## Severity and CVSS

CVSS v3.1 is what most programmes use. Getting it approximately right matters
less than being internally consistent, because a human triager will often
disagree and you will have a conversation.

The four questions that decide most API and web findings:

| Question | Effect |
|---|---|
| **Confidentiality** | Does it disclose data? Who can read it? |
| **Integrity** | Can you modify data that is not yours? |
| **Availability** | Can you take the service down? |
| **Authentication** | Do you need an account? An admin account? |

Rough anchors that triage usually agrees with:

- **Critical.** Unauthenticated remote code execution. Full data breach of the whole user base. Authentication bypass on a high-value action.
- **High.** IDOR or BOLA reading any user's sensitive records with a normal account. SQL injection in an authenticated endpoint. Stored XSS reaching other users.
- **Medium.** Stored XSS requiring a click. Limited IDOR, non-sensitive records. Information disclosure that shortens an attack. Missing rate limiting on a real login.
- **Low.** Minor information disclosure, missing headers, verbose errors, a username enumeration.
- **Informational.** Everything else. These frequently get no bounty and are not worth a report unless the programme explicitly wants them.

Write your impact in the language of the business. "Reads invoices belonging to
any user, including names, addresses, partial payment methods, and order
history" beats "violates authorisation" every time.

---

## Disclosure etiquette

- **Never publicly disclose before the programme responds.** Not even a hint, not even a screenshot with the host redacted. A premature disclosure is grounds for immediate removal from most programmes and can be a legal problem.
- **Report privately first**, through the programme's own channel, even if the bug is trivial.
- **Do not contact the vendor directly.** Ever. The programme mediates and your direct contact is a policy violation.
- **Do not access data that is not yours.** Read enough to prove the bug, screenshot it, stop. Do not download a customer database because the technical capability is there and the temptation is real.
- **Respect the timeline.** A critical bug has a fast disclosure clock. A low one may have a 90-day wait. Do not publish the moment the clock expires without checking the programme's stated policy.
- **Be pleasant to the triager.** They are doing you a favour. Being reasonable in the thread after a dispute is worth more than the bounty.

---

## The business reality

Nobody starts earning here, and the honest timeline is worth knowing.

Expect your first several reports to be informative, or invalid, or duplicates.
The learning is in the triager replies, so read them carefully and fix whatever
they point at. A report rejected with a clear reason teaches more than a payout
you were not ready for.

The progression that works:

1. **Read and reproduce disclosed reports.** Do this before your first submission. It is the highest-value hour in bug bounty.
2. **Submit low-severity findings to build a track record**, if the programme accepts them. Some do, and it is worth it for the reputation.
3. **Specialise.** Web, API, mobile, or network. Broad is not a strategy, and specialists get found first.
4. **Go deep on one surface.** A single target tested exhaustively for a month out-performs a hundred targets tested superficially.
5. **Learn to write.** Reporting is a separate skill from testing and it is the one that determines your income.

The research you do not report still counts. A subdomain map, a set of attack
surface notes, or a repeatable script is worth having even when the bounty is
zero, and it is worth far more when it is documented in a repo like this one.
