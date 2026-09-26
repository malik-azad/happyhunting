# Browser and GUI Testing

A large share of web findings are found **in the browser**, and for access
control, business logic, and client-side bugs it is the better way to work,
because you are testing exactly what a user gets.

This sheet is the browser-first path. It is a complete assessment method on its
own, and the command line is a supplement rather than a prerequisite.

If you have never used DevTools properly, this is the highest-value hour you
can spend in web security.

---

## Contents

- [Do this first, in the browser](#do-this-first-in-the-browser)
- [DevTools, panel by panel](#devtools-panel-by-panel)
- [Reading the source](#reading-the-source)
- [Reading JavaScript](#reading-javascript)
- [Editing and replaying requests](#editing-and-replaying-requests)
- [A full assessment without a terminal](#a-full-assessment-without-a-terminal)
- [GUI tools](#gui-tools)
- [Setting up a proxy](#setting-up-a-proxy)
- [Source code review](#source-code-review)
- [Click-through checklist](#click-through-checklist)

---

## Do this first, in the browser

Before any tool, before any scanner, spend twenty minutes in the browser. This
is where the findings are and it costs nothing.

**1. Read `robots.txt` and the page source of every page.** One of these two
things will find something on most applications.

**2. Look at the URL bar for every page.** The structure of the URLs tells you
the routing scheme, and routing schemes tell you what to fuzz.

**3. Submit every form and watch the Network tab.** Note the request method, the
content type, every parameter, and the response. Half of hidden parameters are
visible in the Network tab without any tool.

**4. Register two accounts.** You cannot test access control with one. This is
the single most important setup step and it takes ninety seconds.

**5. Log in as each account in a separate browser profile or window.** Side by
side. This is how you find IDOR, and it is visually obvious, which makes it
much easier to prove.

**6. Read the JavaScript.** Open the Network tab, filter to `.js`, and read. The
application tells you its own API surface if you let it.

**7. Check the Application tab.** Local storage, session storage, cookies, and
cached responses frequently contain tokens and personal data in cleartext.

---

## DevTools, panel by panel

Open with `F12`, or `Ctrl+Shift+I` / `Cmd+Option+I`.

### Network

The most useful panel in web security, and the one beginners underuse.

- **Filter** by `Fetch/XHR` to see only API calls. This is how you find the API.
- **Filter** by `Doc` to see navigations, and by `JS`, `CSS`, `Img` for assets.
- **Disable cache** while the panel is open. You want to see real requests, not
  cached ones, or you will chase responses that no longer exist.
- **Preserve log** when navigating, so requests do not vanish.
- **Right-click any request → Copy** → as `fetch`, as `cURL`, or as `PowerShell`.
  This is how you convert a browser discovery into a command line, or into a
  Burp request, without typing anything.
- **Right-click → Edit and Resend.** Edit a request and fire it again. For
  parameter fuzzing on a single endpoint, this is faster than any tool.
- **The Initiator tab** shows which JavaScript function built the request. It
  takes you from "this parameter exists" to "this line of code sends it", which
  is how you find parameters the UI never exposes.
- **The Response tab** shows you how your input was encoded or reflected, which
  is the difference between a working XSS payload and a string that got escaped.
- **Right-click → Copy response** to paste a JSON body into a pretty-printer or
  into `jq`.

**To find hidden parameters:** submit a form, find the request, copy it as
cURL, and look for what is being sent. Anything the browser sends that the form
did not visibly contain is worth investigating.

### Elements

The DOM inspector, and much more than "view source".

- **Search across all sources** with `Ctrl+Shift+F`. This searches every loaded
  JavaScript file, stylesheet, and document. Searching for `api`, `token`,
  `admin`, `key`, `password` and reading the results is a legitimate way to
  discover an application's internals.
- **Copy the outer HTML** of a node, or **Copy as** a selector, for scripting.
- **Edit a value in place** to see whether the server actually uses it. Change a
  hidden field, change a display-only price, remove a `disabled` attribute from
  a button. If the server accepts the change, that is a finding.
- **Break on** → attribute modifications, to catch code that sets a cookie or a
  redirect. Useful when a value appears from nowhere.

**The edit-in-place test.** Find a price, a role, a user ID, or a status field
in the DOM. Change it. Submit. If the server honoured the change rather than
recalculating or re-fetching, you have mass assignment or a client-side trust
bug, and you found it with the Elements panel.

### Console

- `fetch('/api/v1/users/1', {headers:{Authorization:'Bearer '+localStorage.getItem('token')}})`
  — call an API directly from the page, with its cookies and origin already set.
- `document.cookie` — read non-HttpOnly cookies.
- `localStorage`, `sessionStorage` — inspect stored values.
- `performance.getEntriesByType('resource').map(r=>r.name)` — every URL the page
  loaded, including ones not visible in the Network panel history.
- `fetch('/admin/users').then(r=>r.status)` — test an endpoint the UI hides,
  with the live session.

The Console is a full request client that inherits the page's authentication.
For access control testing it is often the fastest tool available.

### Sources

- **Pretty-print** (`{}` at the bottom of the file) to read minified JavaScript.
- **Search** across all files, same as Elements.
- **Set a breakpoint** on a line, then interact with the page, and read the
  scope. This tells you what a function received, which is how you follow data
  from input to sink.
- **XHR/fetch breakpoints** — right-click the XHR/fetch category in the left
  pane to break on every request. Invaluable when a value is set by a
  dependency you do not control.
- **Overrides** (right-click a file → Override content) lets you edit a
  JavaScript file and have the change persist across reloads. This is how you
  test a client-side control you cannot reach, such as removing a redirect or a
  feature flag.

### Application

- **Cookies**: the flags, the expiry, and whether the value is readable from
  JavaScript. `HttpOnly` absent means an XSS can steal the session.
- **Local storage / Session storage**: tokens, personal data, and frequently
  role information.
- **Cache**: responses containing personal data, which is the `no-store` finding.
- **Service Workers**: what is cached and what intercepts requests.

### Security tab

- Is the connection HTTPS, and is the certificate valid?
- Any mixed content, meaning HTTP resources on an HTTPS page?
- The certificate's validity period and whether it is expired.

### Overrides and local editing

Under Application → Overrides. Select a folder, then override any JavaScript,
CSS, or image. Changes persist across reloads and are reverted with "Disable
overrides". Use it to:

- Remove a client-side redirect to test what is behind it
- Disable a feature flag
- Make a hidden admin link visible
- Test a fix before the developers deploy it

---

## Reading the source

```bash
# Terminal equivalents, when you want them
curl -s https://<target>/ | less
wget -r -l 3 -A html,js,css -H -k -p -e robots=off https://<target>/ -P ./site
lynx -dump https://<target>/                 # text only, fast, sometimes reveals
```

**What to look for, in order of value:**

1. **Comments.** `<!-- TODO: remove debug -->` in HTML, `// FIXME: auth` in
   JavaScript. Developers leave notes to each other, and those notes describe
   the weaknesses.
2. **Hidden form fields.** Compare what the form shows with what it submits.
3. **JavaScript files.** Every endpoint, key, and internal hostname.
4. **Inline scripts.** Often a debug helper, or a secret key.
5. **Data attributes.** `data-user-id`, `data-role`, `data-admin` are frequently
   present for front-end use and never checked server-side.
6. **Meta tags.** `og:description`, `og:image`, and any custom meta have a habit
   of containing content that was not meant to be published.
7. **Source maps.** `//# sourceMappingURL=app.js.map`. If published, the whole
   original source is available, usually including paths and sometimes
   credentials.
8. **Framework fingerprints.** Generator comments, class names, and asset
   filenames.
9. **Third-party services.** Analytics, chat, CDN, payment, and support widgets.
   Each one is a third party with access to your page.

```bash
# Pull a site and search it, when the browser is not enough
wget -r -l 3 -A html,js -H -k -p -e robots=off https://<target>/ -P ./site
grep -rn "TODO\|FIXME\|HACK\|XXX\|DEBUG\|TEMPORARY" ./site
grep -rohE "https?://[a-zA-Z0-9._/-]+" ./site | sort -u
grep -riE "api[_-]?key|secret|token|password" ./site --include="*.js" --include="*.html"
grep -rn "sourceMappingURL" ./site
```

**Comments in HTML.** A specific pattern worth remembering: a search box whose
`placeholder` attribute is unusually long, or a page with an `og:description` far
longer than the visible content, is often where a flag or a credential is
parked by mistake. This is not a joke technique, it is a real and repeated
pattern in CTF rooms and in sloppy production applications.

---

## Reading JavaScript

Most of the value in a web application assessment is in the front-end source,
and most people never read it.

```bash
# Download and beautify
cat app.js | npx prettier --parser babel > app.pretty.js
cat app.js | js-beautify > app.pretty.js
```

```bash
# The searches that return something
grep -ohE "https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_{}?=&.-]*" app.js | sort -u
grep -ohE "/api/[a-zA-Z0-9/_{}-]+" app.js | sort -u
grep -oiE "(apiKey|api_key|secret|clientSecret|token|auth|bearer|password)\s*[:=]\s*['\"][^'\"]{8,}" app.js
grep -oE "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" app.js     # JWTs
grep -oE "AKIA[0-9A-Z]{16}" app.js                                          # AWS keys
```

**In the browser.** Sources panel → pretty-print → `Ctrl+F`. Search for
`api`, `http`, `token`, `admin`, `role`, `password`, `secret`, `flag`, `key`.
Then set a breakpoint and step through the login function to see exactly what is
sent and what the server expects.

**Client-side trust, the pattern to hunt for.** Look for code that decides
something locally which should be decided on the server:

```javascript
if (user.role === 'admin') { showAdminMenu(); }        // a menu, not a control
const price = cartItem.price * cartItem.qty;           // a price the server trusts
fetch('/api/user', { method:'PUT', body: JSON.stringify(formData) });  // mass assignment
if (!sessionStorage.getItem('loggedIn')) location.href = '/login';      // the only auth check
```

Each of these is a real finding, and each is visible by reading the source.

---

## Editing and replaying requests

Three ways, in increasing order of power.

**DevTools "Edit and Resend".** Edit a request and fire it again. Good for
single-parameter testing, adding a header, or changing a method.

**Copy as fetch into the Console.** The request runs with the page's cookies and
origin, so authorisation is inherited. Best for testing hidden endpoints and
method tampering.

```javascript
// Test an endpoint the UI never calls
fetch('/api/v2/users', {headers:{Authorization:'Bearer '+localStorage.token}}).then(r=>r.status).then(console.log)

// Change a method the UI only uses GET for
fetch('/api/v1/user', {method:'DELETE', credentials:'include'}).then(r=>r.status).then(console.log)

// Mass assignment, straight from the console
fetch('/api/profile', {method:'PUT', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({name:'t', role:'admin'})}).then(r=>r.text()).then(console.log)
```

**Burp Suite.** Capture, edit, and replay anything, with repeater, and with
scanning. This is the tool for sustained work rather than one-off tests.

---

## A full assessment without a terminal

If you only have a browser, this is a complete method. It is genuinely how many
people find their first real bug.

1. **Read the source** of every page. `Ctrl+U`, and the Elements panel.
2. **Read `robots.txt`** and the sitemap.
3. **Open DevTools, Network, filter to Fetch/XHR.** Note every endpoint.
4. **Register two accounts.** Use two browser profiles.
5. **Walk the application as each account.** Note the object IDs in the URLs.
6. **Swap the IDs between accounts.** In the Network tab, edit the request.
   Read the other account's data. This is IDOR, found in a browser.
7. **Edit form values in the Elements panel** before submitting. Price, role,
   quantity, user ID. See whether the server re-validates.
8. **Test every input** with a single quote, then `<svg/onload=alert(1)>`, then
   `{{7*7}}`. Watch the Response tab for reflection and for errors.
9. **Check the Application tab** for tokens in local storage, missing cookie
   flags, and cached personal data.
10. **Search all sources** for `api`, `key`, `secret`, `admin`, `flag`.
11. **Check the Security tab** for mixed content and certificate problems.
12. **Check the response headers** for missing security headers.
13. **Try the obvious paths** in the address bar: `/admin`, `/api`, `/debug`,
    `/config`, `/.env`, `/.git/HEAD`, `/backup`.
14. **Read the error pages.** A stack trace is a finding and it tells you the
    framework and version.
15. **Write it up** while you still remember what you did.

---

## GUI tools

| Tool | Use it for | Notes |
|---|---|---|
| **Burp Suite Community** | Proxy, repeater, site map | The free version covers manual testing fully. Scanner is Pro-only |
| **OWASP ZAP** | Proxy, active scan, spider | Free, good for a repeatable scan |
| **DirBuster** | Content discovery | Has a GUI. Point it at a wordlist, sort by size to spot the real hits |
| **Postman / Insomnia / Bruno** | API exploration | Bruno is open source and stores collections in plain text files |
| **sqlmap GUI** | SQL injection | The `t` flag opens the GTK interface. Easier to learn than the CLI |
| **CyberChef** | Encoding, decoding, `php://` filter chains | Browser-based, nothing to install |
| **jwt.io** | Reading JWTs locally | Do not paste a live token into a public decoder |
| **regex101** | Building and testing patterns | Useful for extracting emails, keys, and IDs from a page |
| **mitmweb** | Proxy with a friendlier UI | Scriptable, good for a repeatable flow |
| **Nuclei** | Templated checks | Run from terminal; results are readable in a web UI |
| **Wappalyzer / WhatWeb** | Technology fingerprinting | Also has a browser extension |
| **Wayback Machine** | Historical versions of the site | A browser tool, and it regularly finds forgotten endpoints |

**A word on GUI scanners.** They will produce findings. Read each one and verify
it before it goes in a report. Burp's scanner, ZAP's active scan, and Nikto all
produce false positives, and "the scanner found it" is not evidence.

---

## Setting up a proxy

**Burp with Firefox or Chrome.**

1. Install the **FoxyProxy** extension. It makes switching proxies one click,
   which is essential when you also need to browse normally.
2. Proxy: `127.0.0.1`, port `8080`.
3. Visit `http://burp` in the browser. Burp serves its certificate authority.
4. Install the CA certificate. **Only ever on a test machine you own.** On your
   own machine, only with awareness that you are trusting a local proxy, and you
   should remove the certificate when you finish.
5. Confirm traffic flows: the Proxy → HTTP history tab fills up.

**Certificate pinning.** If the app refuses to connect, or Burp shows a
handshake failure on a specific app only, that app is pinning. See
[mobile.md](mobile.md) for the pinning bypass, and remember to ask for pinning
bypass in the rules of engagement.

**Do not install a proxy CA into your primary browser profile permanently.**
Pin the certificate to a specific test profile, and remove it afterwards. A
trusted proxy CA in your everyday browser is a genuine risk.

---

## Source code review

Reading the code is the most reliable vulnerability discovery method there is,
and it is available to you whenever a client provides source access.

**Read it looking for the sinks, then trace back to the source.** The pattern
is always the same: a dangerous function, and a path from user input to it.

**Start with the entry points.** Controllers, route handlers, API endpoints,
GraphQL resolvers, file upload handlers, and anything that takes a raw body.

**Then search for the sinks.** The table in [rce.md](rce.md) lists the dangerous
functions per language.

**Framework-specific files worth reading first:**

| Framework | Files that matter |
|---|---|
| Django | `settings.py`, `urls.py`, `models.py`, anything with `raw()` or `extra()` |
| Flask | `app.py`, route definitions, `config.py`, any `render_template_string` |
| Express | route files, `app.use`, anything building a query string by concatenation |
| Spring | controllers, `application.properties`, and any SpEL usage |
| Rails | `config/routes.rb`, controllers, and any `where` built with interpolation |
| Laravel | controllers, routes, `app/Http`, and raw query usage |
| Django REST | `views.py`, `serializers.py`, and permission classes |

**What to look for, in rough priority order:**

1. **String-built SQL.** Concatenation or interpolation into a query.
2. **Command execution** with user input. Covered in [rce.md](rce.md).
3. **Deserialisation** of untrusted data, and raw pickle.
4. **Authorisation checks that live in the client** or in a decorator that is
   missing on one endpoint.
5. **Template rendering of user input**, `render_template_string` and equivalents.
6. **File operations** with user-controlled paths.
7. **Hard-coded secrets.** API keys, passwords, connection strings, JWT secrets.
8. **Weak cryptography.** MD5 for passwords, `random` instead of `secrets`,
   ECB mode, disabled certificate validation.
9. **Debug left on.** `DEBUG = True` in Django is an entire information disclosure.
10. **Mass assignment.** Binding the whole request body to a model.

```bash
# When you have the source, these find the obvious problems fast
# and then you read the hits properly rather than trusting the tool
rg -n "execute\(|exec\(|system\(|popen|Runtime\.getRuntime|ProcessBuilder"
rg -n "eval\(|Function\(|create_function|render_template_string"
rg -n "pickle\.loads|yaml\.load\(|unserialize|ObjectInputStream|BinaryFormatter"
rg -n "raw\(|extra\(|execute\(\"|query\(\"|\\$where"
rg -n "password|secret|api[_-]?key|token" --glob '!*.min.js' -i
rg -n "DEBUG\s*=\s*True|verify\s*=\s*False|rejectUnauthorized:\s*false"
gitleaks detect --source .
trufflehog filesystem .
```

**Review the authorisation model, not just the endpoints.** The most common
serious finding in a code review is a single endpoint missing the permission
decorator or middleware that every other endpoint has. Read the pattern, then
check every route against it. That one review pass routinely out-performs a week
of dynamic testing.

---

## Click-through checklist

For a browser-first pass, in order:

- [ ] `robots.txt`, `sitemap.xml`, `security.txt`
- [ ] Page source of every distinct page, comments included
- [ ] `Ctrl+Shift+F` search of all sources for `api`, `key`, `secret`, `admin`, `flag`
- [ ] Network tab, filtered to `Fetch/XHR`, every endpoint noted
- [ ] Two accounts, side by side, object IDs swapped between them
- [ ] Elements panel, form values edited before submitting
- [ ] A single quote into every input
- [ ] `<svg/onload=alert(1)>` into every reflected input
- [ ] `{{7*7}}` into every input, looking for `49`
- [ ] Application tab: cookies, local storage, cache
- [ ] Security tab: HTTPS, certificate, mixed content
- [ ] Response headers for the security header set
- [ ] `/admin`, `/api`, `/debug`, `/config`, `/.env`, `/.git/HEAD`
- [ ] Error pages, looking for stack traces
- [ ] Mixed content and third-party widgets noted
- [ ] Written up before you close the browser
