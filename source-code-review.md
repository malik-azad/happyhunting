# Source Code Review

Reading the code is the highest-yield vulnerability discovery method there is.
A dynamic scanner only sees the paths you happened to exercise. Source access
shows you the entire attack surface, including the endpoints nobody remembered
to write a test for.

This sheet is the review process: how to set up, what order to read in, and the
specific patterns worth looking for per language and per framework.

For the browser-side view of the same material — DevTools, reading minified
JavaScript, source maps — see [browser-and-gui.md](browser-and-gui.md). For
sinks that lead to code execution, see [rce.md](rce.md).

---

## Contents

- [Before you start](#before-you-start)
- [Setup and tooling](#setup-and-tooling)
- [Reading order](#reading-order)
- [Reviewing the authorisation model](#reviewing-the-authorisation-model)
- [Injection patterns by language](#injection-patterns-by-language)
- [Framework files worth reading first](#framework-files-worth-reading-first)
- [Secrets](#secrets)
- [Dependencies and supply chain](#dependencies-and-supply-chain)
- [Infrastructure as code](#infrastructure-as-code)
- [Git history as a finding source](#git-history-as-a-finding-source)
- [Business logic in code](#business-logic-in-code)
- [Reporting from a review](#reporting-from-a-review)
- [Checklist](#checklist)

---

## Before you start

Ask the client for:

- **The source**, with the commit matching the deployed version. A review of
  the wrong branch is worse than no review, because it produces confident,
  wrong findings.
- **Build and dependency files**: `pom.xml`, `build.gradle`, `package.json`,
  `requirements.txt`, `Gemfile`, `composer.json`, `go.mod`, `*.csproj`.
- **The architecture**, at whatever resolution exists. Even a one-page diagram
  tells you where the trust boundaries are.
- **A person who can answer questions.** Ten minutes with a developer beats
  two days of guessing.
- **The deployment configuration**: Dockerfiles, Kubernetes manifests, Terraform,
  CI/CD pipeline definitions.
- **Known issues and previous findings**, so you do not spend a day
  rediscovering a ticket that was already closed as a false positive.
- **Test suites and any existing security tests.**

Write down the commit hash you are reviewing. Put it in the report. When a
finding is disputed, "which commit did you read" is the first question, and
being able to answer it is what makes the report credible.

---

## Setup and tooling

```bash
# Clone the exact deployed commit
git clone <repo> src
cd src
git log -1 --format="%H %ci %s"
git checkout <deployed-commit-sha>
```

```bash
# Semgrep. Fast, low-noise, and the best first pass available.
# The rules are named after CWE numbers, so triage is quick.
pipx install semgrep
semgrep --config auto                 # auto-detects the languages present
semgrep --config p/security-audit      # the general audit ruleset
semgrep --config p/owasp-top-ten
semgrep --config p/javascript         # language-specific
semgrep --config p/java --config p/python --config p/php   # several at once
semgrep --config auto --severity ERROR --severity WARNING --sarif -o results.sarif
```

```bash
# CodeQL, for deeper dataflow. Worth it on Java, C/C++, C#, Go, JS/TS, Python.
# It builds a database and answers "where does this untrusted input reach a sink"
codeql database create db --language=java --command='mvn clean package'
codeql database analyze db security-extended.qls --format=sarif-latest --output=results.sarif
```

```bash
# Gitleaks for secrets, across the whole history
gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif
# TruffleHog, which also verifies live credentials
trufflehog filesystem . --json
trufflehog git file://. --only-verified
```

```bash
# Dependency audit
npm audit
pip-audit
cargo audit
govulncheck ./...
mvn org.owasp:dependency-check-maven:check
bundle audit check
composer audit
```

```bash
# Make the code readable before you read it
# Formatting and dead-code removal are not security, but unreadable code
# hides findings
npx prettier --write "src/**/*.js"
npx eslint --fix src/
ruff check --fix . && ruff format .
```

```bash
# What is actually in here, before you read any of it
tree -L 3 -I 'node_modules|.git|vendor|dist|build|__pycache__'
cloc .                                   # lines of code, per language
```

**A word on trusting the tools.** Semgrep will find things a scanner cannot,
because it reads the code. It will also produce findings that are not
exploitable, because it does not know your authorisation model. Treat every
tool finding as a *pointer to a place to read carefully*, not as a result. This
is the same discipline as
[web-testing.md](web-testing.md) applies to a scanner output.

---

## Reading order

Reviewing in the right order saves hours. This sequence front-loads the
findings with the highest impact.

1. **Entry points.** Controllers, routes, API handlers, GraphQL resolvers,
   message consumers, cron jobs, file upload handlers. This is the attack
   surface, and everything later is a question about one of these.
2. **The authorisation model.** Before you test a single endpoint, understand
   how the application decides who is allowed to do what. See the section below.
3. **The sinks.** Search for dangerous functions. Trace backwards to user input.
   This is where the RCE and injection findings come from.
4. **Data handling.** Where does data go? Database queries, file paths, shell
   commands, template rendering, deserialisation, XML parsing, redirects.
5. **Secrets and configuration.** Hard-coded credentials, weak defaults,
   debug flags, over-permissive CORS.
6. **Dependencies.** Known CVEs in the exact versions in use.
7. **Infrastructure.** Dockerfiles, Kubernetes manifests, Terraform, pipelines.
8. **The tests.** What is tested tells you what the developers were worried
   about, and what is *not* tested tells you where the blind spots are.

---

## Reviewing the authorisation model

**This is the review that finds serious bugs.** Injection bugs are real but
usually obvious. Missing authorisation on one endpoint is how an attacker gets
to the database, and it is trivially easy to miss in dynamic testing because you
have to know the endpoint exists.

**Step 1. Find the mechanism.** How does this application decide that a request
is allowed?

- A middleware or filter, applied per route
- A decorator or annotation, `@PreAuthorize` / `@login_required` /
  `[Authorize]`
- A permission class, Django's `permission_classes`, a policy in the router
- A role check inside the handler body

**Step 2. Enumerate every route.** Then compare each one against the mechanism.

```bash
# Every route, from every framework
rg -n "@(app|router|bp)\.(route|get|post|put|patch|delete)" 
rg -n "@(Get|Post|Put|Patch|Delete|Request)Mapping"                  # Spring
rg -n "url\(|path\(|re_path\("                                        # Django
rg -n "(app|router)\.(get|post|use|patch|put|delete)\("            # Express
rg -n "^\s*(\w+):\s*(\w+)" config/routes.rb                         # Rails
```

**Step 3. Find the exceptions.** This is where the bugs are.

- Routes with no authorisation annotation when their siblings have one
- Routes whose check is a different, weaker check than their siblings
- A route protected in the router but reachable through a second path
- A `PUT` or `DELETE` on a resource where only `GET` was reviewed
- A debug or internal route in the same controller as a public one
- A controller mounted twice, once authenticated and once not

**Step 4. Check the check itself.** An authorisation check can be present and
still wrong.

- Does it compare against a client-supplied value? `if (user.id == req.query.id)`
- Is it a string comparison where the user can supply an array? `?role[]=admin`
- Is it case-insensitive, or type-juggling in PHP?
- Does it fail open, so an error path skips the check?
- Is it checked before or after the object is loaded? Before means the
  enumeration is safe; after means you may already have leaked existence.

**Step 5. Check the object level.** Endpoint-level authorisation is necessary
and not sufficient. Every endpoint that takes an object identifier must also
check that the caller owns it. That is IDOR, and it is a source-review
finding as much as a dynamic one: look for the query, and see whether the
owner's identifier is in the `WHERE` clause.

```sql
-- Missing
SELECT * FROM invoices WHERE id = :id
-- Correct
SELECT * FROM invoices WHERE id = :id AND account_id = :session_account
```

**Step 6. Check the default.** New endpoints should be denied by default and
opened explicitly. If the framework makes it easy to forget, that is a design
finding worth reporting, because the next endpoint will have the same problem.

---

## Injection patterns by language

### SQL

```bash
rg -n "raw\(|extra\(|execute\(\s*[\"'\`]|query\(\s*[\"'\`]|\\\$where|\\\$\{"
rg -n "sql\s*=\s*[\"'].*%s|\.format\(|f[\"'].*\{|\+\s*\w+\s*\+\s*[\"']"
rg -n "createQuery\(|createNativeQuery\(|prepareStatement\("
```

The safe forms, so you can tell them apart in a diff: parameterised queries
(`?` placeholders with a bound parameter array, or named binds), an ORM's
parameterised methods, and query builders. Anything that concatenates a variable
into a query string is a finding, whatever the ORM.

**Second-order injection.** A value is stored safely, then read back and used in
a query. The insert is parameterised, the select is not. This is common where a
name or comment field is later used in a report query.

### Command execution

See [rce.md](rce.md) for the full set. In review terms, the question is always
the same: is a user-controlled value reachable from `system`, `exec`,
`Runtime.exec`, `ProcessBuilder`, `child_process.exec`, or an argument array
with `shell=True`?

### Template injection

```bash
rg -n "render_template_string|Markup\(|Template\(|from_string|compileTemplate|\\\$\\{"
```

A template rendered from a *file* is fine. A template rendered from a *string
the user supplied* is the vulnerability. `render_template` versus
`render_template_string` in Flask is the canonical example.

### Path traversal

```bash
rg -n "open\(|readFile|readFileSync|file_get_contents|sendFile|createReadStream"
rg -n "\.\.\/|path\.join|os\.path\.join|File\(new File\("
```

Look for user input joined into a path without normalisation, and for a
missing check that the resolved path is still inside the intended directory.
`os.path.join` does not help: `os.path.join('/var/data', '/etc/passwd')` returns
`/etc/passwd`.

### Deserialisation

```bash
rg -n "pickle\.loads|yaml\.load\(|marshal\.loads|unserialize|ObjectInputStream|readObject|BinaryFormatter|node-serialize"
```

Any deserialiser applied to data the client can influence. Also check
`yaml.load` without `SafeLoader`, which is deserialisation with a YAML
syntax.

### XML

```bash
rg -n "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|libxml|xml\.parse|XMLParser"
```

Look for entity resolution left on. The fix is a parser configuration, so the
finding is "this factory is configured with defaults" rather than "this one
line is wrong".

### SSRF

```bash
rg -n "requests\.(get|post|head)\(|urlopen\(|fetch\(|axios\.|HttpClient|WebClient|RestTemplate"
```

User-controlled URL in an outbound request. Note whether the code checks the
resolved IP, or only the hostname, and whether it follows redirects.

### Path and file handling

```bash
rg -n "open\(|fopen\(|FileOutputStream|createWriteFile|writeFileSync" 
```

Upload handling: where does the file go, what is it named, and is the name
derived from user input. A filename containing `../` that is not stripped is
traversal; a filename derived only from user input is a second finding, because
the attacker controls the extension.

---

## Framework files worth reading first

| Framework | Files that matter | What to look for |
|---|---|---|
| Django | `settings.py` | `DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY`, `SECURE_*` flags, installed apps |
| Django | `urls.py`, `views.py` | Missing permission classes, `raw()` and `extra()` |
| Django | `serializers.py` | Fields the client should not set, exposed in `fields = '__all__'` |
| Flask | `app.py`, `config.py` | `debug=True`, the secret key, missing decorators on routes |
| Flask | any `render_template_string` | Template injection |
| Express | route files, `app.js` | Missing `authenticate` middleware, string-built queries |
| Express | `middleware/auth.js` | Whether the check actually compares the session to the object |
| Spring | controllers | Missing `@PreAuthorize`, SpEL built from input |
| Spring | `application.properties`, `application.yml` | Actuator exposure, weak secrets, permissive CORS |
| Rails | `config/routes.rb`, controllers | `where` clauses built by interpolation, missing `before_action` |
| Laravel | controllers, `routes/web.php`, `app/Http/Middleware` | Mass assignment via `$fillable`, missing policies |
| ASP.NET | controllers, `Startup.cs` | `[Authorize]` coverage, `BinaryFormatter`, model binding over-posting |
| Go | handler files | `db.Query` with `fmt.Sprintf`, missing middleware in a route group |
| PHP | any controller, `composer.json` | `mysqli_query` with concatenation, `include` with a variable |

**Over-posting and mass assignment.** In review, check what the model binds from
the request. A DTO with only the intended fields is correct. Binding the request
body straight to an ORM model lets the client set `role`, `is_admin`,
`balance`, or `user_id`. This is one of the most reliably exploitable findings
in a code review, and it is invisible from the outside.

```python
# Django, the dangerous form
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'          # role, is_staff, is_superuser all settable

# The safe form
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'name')
```

**The one-line framework smell list.** A `DEBUG = True` in Django, an
`ALLOWED_HOSTS = ['*']`, a `verify=False` on an HTTP client, a `csrf_exempt`
on a state-changing endpoint, actuator exposed without authentication, and
`__proto__` or `Object.assign` on unvalidated input. Each is one grep away and
each is a real finding.

---

## Secrets

```bash
# Patterns, across the working tree and the full history
gitleaks detect --source .
trufflehog git file://. --only-verified
rg -n --hidden -g '!.git' -i "password|secret|api[_-]?key|token|private[_-]?key" -g '!*.lock'
rg -n "AKIA[0-9A-Z]{16}"                        # AWS access key id
rg -n "-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY"
rg -n "gh[pousr]_[A-Za-z0-9]{36,}"             # GitHub tokens
rg -n "sk-[A-Za-z0-9]{20,}"                     # OpenAI-style keys
rg -n "AIza[0-9A-Za-z_-]{35}"                   # Google API keys
rg -n "eyJ[A-Za-z0-9_-]{10,}\."                 # JWTs, which may embed a signing key
```

A secret in source is a finding **and** an incident. The report says: the
credential is in the repository, anyone with read access has it, and it must be
rotated, not just deleted. Deleting the line without rotating leaves the
credential valid forever, because it is in the history and in every clone.

**Where to look that is easy to forget:** test fixtures, example configuration
files, commented-out code, `docker-compose.yml`, `.env` committed by accident,
CI/CD variable definitions, mobile application bundles, and the JavaScript
bundle served to the browser. A key in a JS bundle is a key anyone can read.

---

## Dependencies and supply chain

```bash
# What is actually installed, resolved
npm ls --all
pip list
go list -m all
```

```bash
# Advisories
npm audit --production
pip-audit
govulncheck ./...
osv-scanner scan source -r .          # covers many ecosystems at once
```

Look past the obvious in the manifest files:

- **A pinned or floating version.** `latest`, `*`, `master`, or `^1.0.0` on
  something security-relevant means the build is not reproducible.
- **A dependency with no maintainer**, or a very low version count, on a
  critical path.
- **A fork.** A dependency pointing at a personal GitHub account rather than a
  registry is a supply chain risk and a question for the client.
- **Install scripts.** `postinstall` in `package.json`, or a build plugin that
  executes code, is arbitrary code execution at build time.
- **A lock file that is out of date** relative to the manifest, meaning the
  deployed versions are not the reviewed ones.
- **A package whose name resembles a popular one.** Typosquatting.

CI/CD definitions deserve the same scrutiny as application code: a pipeline that
runs untrusted pull requests on a self-hosted runner is a remote code execution
path into the build network.

---

## Infrastructure as code

```bash
# Dockerfiles
rg -n "^FROM|USER|apt-get|apk add|curl|wget" Dockerfile*
# A build stage and a run stage as one stage means build tools ship to production
# Running as root is a finding; so is a missing USER directive
# A curl in a RUN line, pulling an unpinned URL, is a supply chain issue

# Kubernetes
rg -n "privileged: true|allowPrivilegeEscalation|hostNetwork|hostPID|hostPath" -g '*.yaml'
rg -n "image:" -g '*.yaml'            # is the tag pinned, or is it :latest
# A privileged pod, a hostPath mount, or a cluster-admin RoleBinding is
# a container escape or cluster compromise path

# Terraform
rg -n "0\.0\.0\.0/0|public|acl|encrypted" -g '*.tf'
rg -n "access_key|secret_key|password" -g '*.tf'
# A security group open to the world, an unencrypted volume,
# and a plaintext credential in state are the three to look for
```

A `terraform.tfstate` file is a special case. It is supposed to contain
secrets in plaintext, and it gets committed. Check it explicitly.

---

## Git history as a finding source

History is part of the source, and it is evidence.

```bash
# Credentials that were removed but are still in history
git log -p --all -S "password" | head -50
git log -p --all -S "api_key"
git log --all --oneline --diff-filter=D -- "*.env" "*.pem" "*.key" "id_rsa"

# Secrets in the history but not in the current tree
gitleaks detect --source . --log-opts="--all"
```

Other history findings:

- **A fix that was reverted.** A commit message mentioning "fix", "security",
  or "CVE", followed by a revert. `git log --oneline --grep="revert"`.
- **A commented-out security check.** `git log -p --all -S "verify=False"`.
- **A feature flag that used to disable a control.** The commit that removed it
  is the interesting one.
- **A merge from a branch that should not have existed**, which sometimes
  indicates an unreviewed deployment path.

---

## Business logic in code

Dynamic testing finds broken access control when you happen to try the right
object ID. Code review finds the *pattern*, and the pattern is usually in a
service or helper rather than a controller.

**The places logic lives:** a service or use-case class, a state machine, a
payment or pricing calculation, a validation helper, and the places those are
called from.

**The questions to ask of any of them:**

- Can the client skip a step? Is there a `complete` endpoint that does not check
  that the previous steps happened?
- Can the order be changed? A discount applied after validation, or a quantity
  checked at one point and recalculated at another.
- Can the price change between display and charge? Look for a client-supplied
  amount reaching a payment call.
- Is a check enforced only in the UI? A `role` check in JavaScript and nothing
  in the service.
- Is there a race? A balance check and a debit that are not in one transaction,
  or no unique constraint on what should be unique.
- Does a negative value pass validation? A quantity of `-1`, a refund of
  `-100`, a price of `-0.01`.
- Is a limit applied on one path and not another? A rate limit on the UI route
  and not on the API.
- Can a coupon, a referral, or a promo be applied twice?
- Is a deleted or disabled user still able to act because a token outlived the
  account?

**Greps that help, though the reading is the real work:**

```bash
rg -n "quantity|amount|price|total|discount|balance|credit|refund"
rg -n "if.*(isAdmin|role|admin|permission|verified)"
rg -n "TODO|FIXME|for now|temporarily|hack|do not remove|keep this"
rg -n "if.*user\.id ==|== request\.|== req\.|== params\["      # object ownership
```

Comments like `// do not remove, the frontend depends on it` and
`// we will add auth later` are not trivia. They are the developer telling you
where the gaps are.

---

## Reporting from a review

Findings from a code review are usually more precise than findings from a scan,
and the report should show that.

**Include, per finding:**

1. **File and line.** `src/api/invoices.py:42`. A developer can act on that in
   minutes.
2. **The vulnerable code**, quoted, short.
3. **How user input reaches it.** The taint path, in words: which parameter,
   which function, which sink.
4. **The impact**, in the client's terms, not in CWE language.
5. **The fix**, as a code diff if it is short. A concrete patch is the most
   useful thing in the report.
6. **Whether the deployed build is affected**, since you reviewed a commit and
   the running version may differ.

**Rating findings honestly.** A code pattern that is unreachable in the
deployed configuration is a defect, not a critical vulnerability. Say so, and
say why. Over-rating a source review finding is the fastest way to lose the
reviewer's trust, and they will start ignoring the rest of the report.

**Keep the report about the system, not the tool.** "Semgrep reported 40
findings" is noise. "Four endpoints in the invoice controller omit the ownership
check present on the other twelve" is a finding, and it is one line long.

---

## Checklist

- [ ] Confirm the commit hash being reviewed, and record it
- [ ] Ask for the architecture and the known-issues list
- [ ] Run Semgrep, CodeQL, Gitleaks, and a dependency audit; treat output as
      pointers to read, not results
- [ ] Enumerate every entry point
- [ ] Understand the authorisation mechanism, then find the routes that
      deviate from it
- [ ] Check every object-taking endpoint for an ownership check in the query
- [ ] Search for SQL, command, template, path, deserialisation, and XML sinks
- [ ] Trace each sink back to a source; record the ones with no path as
      "reviewed, not reachable"
- [ ] Check over-posting and mass assignment in every DTO and model binding
- [ ] Grep for secrets in the tree and in the full history
- [ ] Review dependencies, lock files, and install scripts
- [ ] Review Dockerfiles, Kubernetes manifests, Terraform, and CI/CD definitions
- [ ] Read the tests, and note what is not covered
- [ ] Read the business logic for order-skipping, price manipulation, and races
- [ ] Check framework defaults: debug flags, secret keys, host allowlists,
      TLS verification, CSRF exemptions
- [ ] Rate each finding by actual reachability, and mark anything unverified
