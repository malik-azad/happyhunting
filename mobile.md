# Mobile Application Testing

The most under-tested attack surface in most programmes, and the one where the
client's app is the best documentation you will ever get.

## Contents

- [Why mobile is different](#why-mobile-is-different)
- [Static analysis, Android](#static-analysis-android)
- [Static analysis, iOS](#static-analysis-ios)
- [Certificate pinning](#certificate-pinning)
- [The API behind the app](#the-api-behind-the-app)
- [Testing the app on the device](#testing-the-app-on-the-device)
- [Local storage and data protection](#local-storage-and-data-protection)
- [Insecure IPC](#insecure-ipc)
- [WebView and deep link issues](#webview-and-deep-link-issues)
- [Root and jailbreak detection](#root-and-jailbreak-detection)
- [Reporting](#reporting)

---

## Why mobile is different

An APK or IPA gives you the whole application, including every endpoint, every
key, and the logic the UI hides. It is a fuller view of the backend than any
amount of web recon gives you.

Three consequences:

1. **The app is the documentation.** Every API call, every parameter, and often
   the admin endpoints that were never intended to be reachable.
2. **The device is part of the attack surface.** Local storage, IPC, WebViews,
   and certificate pinning are all app bugs, not server bugs.
3. **The security is only as good as the weakest client.** A hard-coded key in
   an APK is a server credential, whether or not the developers consider it one.

```bash
# Check the programme's scope carefully. Mobile is often listed separately,
# and an APK in the Play Store is frequently out of scope unless explicitly
# included. "testmobile" in the APK name is not authorisation.
# Often the rule is: only the exact version published in the store, only
# your own account, and no testing against other users' data.
```

---

## Static analysis, Android

```bash
# Get the APK. From the store, or from your own test build.
# Prefer your own build: it matches the version in scope and may have symbols.
apktool d app.apk -o app_unpacked
jadx-gui app.apk                # decompile to readable Java
d2j-dex2jar classes.dex -o classes.jar
```

```bash
# Endpoints, the highest-value output
grep -rohE "https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_{}?=&.-]+" app_unpacked | sort -u
grep -rohE "/api/v[0-9]+/[a-zA-Z0-9/_{}-]+" app_unpacked | sort -u

# Keys, tokens, and secrets
grep -riE "api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|password|auth" app_unpacked/res app_unpacked/smali app_unpacked/assets
grep -rohE "[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}" app_unpacked    # JWTs

# Cloud and third-party credentials, which are frequently in the APK
grep -riE "AKIA[0-9A-Z]{16}" app_unpacked
grep -riE "AIza[0-9A-Za-z\-_]{35}" app_unpacked
grep -riE "sk_live_|pk_live_|AKIA" app_unpacked
```

```bash
# Configuration files, often overlooked and often rich
cat app_unpacked/res/xml/network_security_config.xml
find app_unpacked/assets -name "*.json" -o -name "*.js" -o -name "*.env"
```

```bash
# The manifest, which describes the attack surface
cat app_unpacked/AndroidManifest.xml
# Look at: exported activities, intent filters, permissions,
# android:debuggable, android:allowBackup, and any exported provider
```

```bash
# Exported components, a real finding when they should not be
# aapt dump badging app.apk | grep -i launchable-activity
d2j-dex2jar classes.dex -o classes.jar
# MobSF automates a lot of this and is worth running before you start manually
python3 mobsf.py -u app.apk
```

```bash
# Native libraries
find app_unpacked/lib -name "*.so" | head
# jadx will not decompile these. strings and file will do
strings lib/armeabi-v7a/libnative.so | grep -iE "http|key|secret|password"
file lib/armeabi-v7a/libnative.so
```

---

## Static analysis, iOS

```bash
# Tools
# class-dump, or frida-ios-dump against a jailbroken device
# or, on macOS, a simple unzip and plutil
class-dump -H app.ipa | head -50
plutil -p app/Info.plist
strings app.app/app | grep -iE "http|api|key|secret|password"
```

```bash
# The same greps, on the binary
grep -aohE "https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_{}?=&.-]+" app.app/app | sort -u
strings app.app/app | grep -iE "api[_-]?key|client[_-]?secret|access[_-]?token"
```

```bash
# The archive, for resources and plists
unzip -o app.ipa -d app_extracted
find app_extracted -name "*.plist" -o -name "*.json" -o -name "*.js"
```

```bash
# Entitlements and capabilities, which describe what the app is allowed
codesign -d --entitlements :- app.app
```

```bash
# TestFlight and IPA distribution
# On an IPA you obtained legitimately for testing
unzip -o app.ipa -d Payload
ls Payload/*.app
```

**Note.** Decompiling an app you are not authorised to test is a legal problem
in several jurisdictions, and an IPA obtained from outside the app store may
itself be unlawful to possess. Work from an app distributed to you legitimately,
or from your own build, and have the authorisation in writing.

---

## Certificate pinning

The main reason people reach for a proxy, and the main obstacle to testing a
mobile app properly.

```bash
# Check whether pinning is present at all
# Look for the OkHttp CertificatePinner, and for the custom trust managers
grep -ri "CertificatePinner\|certificate_pinner\|TrustManager\|X509TrustManager" app_unpacked/smali
# And the network security config
cat app_unpacked/res/xml/network_security_config.xml
```

```bash
# Frida, to bypass pinning on a rooted or jailbroken device
# frida-server on the device, then:
frida -U -f com.example.app -l bypass-ssl.js --no-pause
# bypass-ssl.js typically hooks OkHttp's CertificatePinner and the
# TrustManager, or NSS, depending on the framework.
```

```bash
# Or patch the APK to remove the pinning
apktool d app.apk -o app
# edit network_security_config.xml, or the smali, to trust user certs
apktool b app -o app-patched.apk
apksigner sign --ks <keystore> app-patched.apk

# The difficulty: you must match the application's own signature to install
# over it, or the OS refuses. Either use the original signature, which you
# may not have, or uninstall first, which loses app data.
# This is why a rooted device with frida is the more practical route.
```

```bash
# SSL pinning that fails means the app refuses to talk to your proxy.
# Check the other possibility first: the app trusts only the system store,
# and your proxy's CA is not in it. That is not pinning, it is ordinary
# certificate validation, and installing your CA in the device trust store
# fixes it.
```

**On whether to bypass pinning.** It is standard testing, and it is nearly
always within the scope of a mobile assessment, because you cannot test an app
without intercepting its traffic. State it in the RoE. What is not in scope is
patching a distributed app to reach a server you were not given, or continuing
to bypass pinning after the client's security team has asked you to stop,
because that would be modifying a build that users actually run.

---

## The API behind the app

The most valuable part. Treat it exactly as in [api-testing.md](api-testing.md),
with the app's own source as your documentation.

```bash
# Extract the base URL and every path
grep -rohE "https?://[a-zA-Z0-9._-]+" app_unpacked | sort -u
grep -rohE "\"[a-zA-Z0-9_-]*/api/[a-zA-Z0-9/_{}-]+\"" app_unpacked | sort -u

# Environment-specific endpoints, which often have weaker security
grep -rohE "https?://(dev|staging|test|uat|qa|api-v2|beta)[a-zA-Z0-9._-]*" app_unpacked | sort -u
```

```bash
# A hard-coded key in the app is a server credential
# Report it as such, and prove it against the service it belongs to, only
curl -s https://api.example.com/v1/users -H "Authorization: Bearer <key-from-apk>"
```

```bash
# Mobile-specific API weaknesses
# 1. The app trusts the client for authorisation decisions
# 2. Object identifiers are sequential and guessable
# 3. The app ships admin endpoints that the store build should not expose
# 4. Debug builds leave debug endpoints enabled
# 5. A staging environment is reachable and has weaker authentication
```

```bash
# Proxy everything through Burp or mitmproxy, then read it all
# This is where the real work is. The app becomes a documented, automated
# client for the API, and you can replay any request.
mitmproxy -p 8080 --mode regular
# On the device, set the proxy to your machine's address
```

```bash
# Compare two accounts in the app, which is the BOLA test
# Register two accounts in the app, note the object IDs, and swap them
# This is exactly the api-testing.md workflow, with the app as the reference
# client instead of guessed endpoints.
```

---

## Testing the app on the device

```bash
# Get a rooted Android emulator, or a rooted test device
# The point is to observe runtime behaviour rather than only static code
```

```bash
# The runtime filesystem, and where data ends up
adb shell
run-as <package> ls
adb shell run-as <package> cat shared_prefs/*.xml
adb shell run-as <package> cat databases/*.db
# Look for: cached tokens, stored credentials, personal data in cleartext
```

```bash
# Network traffic from the device itself
adb shell tcpdump -i any -s 0 -w /sdcard/cap.pcap
tcpdump -i any -A -s 0 | grep -iE "http|authorization|cookie"
# If traffic is cleartext, that is the finding
```

```bash
# Interact with the app under test
adb shell am start -n <package>/<activity>
adb shell input tap <x> <y>
adb shell input text "input"
adb shell am broadcast -a <action>
adb logcat | grep -i "yourapp"
# Broadcast receivers on exported activities accept unauthenticated input
adb shell am start -n <package>/<activity> --es <key> <value>
```

```bash
# Check whether debug is left on in a release build
# android:debuggable="true" in a production APK is a serious finding
aapt dump xmltree app.apk AndroidManifest.xml | grep -i debuggable
# A debuggable app lets anyone attach a debugger and read the process memory
```

---

## Local storage and data protection

```bash
# Check the manifest for the flags that matter
# android:allowBackup="true"     -> adb backup can extract app data
# android:debuggable="true"      -> debuggable, memory readable
# android:usesCleartextTraffic   -> HTTP permitted
```

```bash
# Backup, if allowed. This works on a release build.
adb backup -f backup.ab <package>
# convert to tar, and read the data
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

```bash
# Shared storage, and the permissions that leak into it
adb shell ls -la /sdcard/Android/data/<package>/
adb shell ls -la /sdcard/DCIM /sdcard/Download
```

```bash
# iOS equivalents
# The app sandbox, and what is readable in it
ls ~/Library/Developer/CoreSimulator/Devices/<id>/data/Containers/Data/Application/<id>/
# Keychain, which is the correctly protected one
# Caches, which usually are not
```

```bash
# Backups, and whether they are encrypted
# An unencrypted iOS backup contains almost everything
# Test the local backup encryption setting and report it
```

```bash
# Screenshots and the recents screen
# A sensitive screen that appears in the recents switcher is a real finding
# FLAG_SECURE on Android
adb shell settings get secure screenshot_enabled
# A clipboard leak, where the app copies a token to the clipboard
adb shell cmd clipboard get-primary-clip
```

---

## Insecure IPC

```bash
# Exported activities, the usual first check
# Look for android:exported="true" without a permission guard
grep -o 'android:exported="true"' app_unpacked/AndroidManifest.xml | wc -l
```

```bash
# Content providers, frequently unguarded
# A provider that returns other apps' private data is a serious finding
# query it from adb
adb shell content query --uri content://<provider>/<path>
adb shell content read --uri content://<provider>/<path>

# Test whether other apps can reach it, by trying from a second app
# and by checking the exported flag and the permission level
```

```bash
# Broadcast receivers
# An exported receiver that starts an activity or runs a service
# from unauthenticated input is a path to code execution
# adb shell am broadcast -a com.example.ACTION --es cmd "value"
```

```bash
# Deep links, covered in the next section
# Custom URL schemes, which have no per-app protection
adb shell am start -a android.intent.action.VIEW -d "exampleapp://action?param=value"
```

```bash
# iOS equivalents
# URL schemes in Info.plist
plutil -p app.app/Info.plist | grep -A 5 CFBundleURLSchemes
# App extensions, which run in their own process
# Keychain sharing groups, which are cross-app by design
```

---

## WebView and deep link issues

```bash
# WebView with JavaScript enabled and file access
# These settings together are dangerous
grep -ri "setJavaScriptEnabled(true)\|setAllowFileAccess\|addJavascriptInterface" app_unpacked/smali
grep -ri "addJavascriptInterface" app_unpacked/smali
# A JavaScript interface exposed to a WebView that loads untrusted content
# is a code execution path on older Android versions
```

```bash
# Does the app load content over HTTP?
grep -i "usesCleartextTraffic\|http://" app_unpacked/AndroidManifest.xml app_unpacked/res/xml/network_security_config.xml
```

```bash
# Deep links
# Enumerate the schemes and test each parameter
adb shell am start -a android.intent.action.VIEW -d "https://example.com/whatever"
# Test for: open redirect, authentication bypass via a callback,
# and parameters that reach a WebView
```

---

## Root and jailbreak detection

Worth knowing how it works, because "the app detects root" is not a security
control in any meaningful sense.

```bash
# Common checks
su
which su
ls /system/app/Superuser.apk
ls /system/xbin/su
ls /sbin/su
# Build properties
ro.debuggable
ro.build.type
# SafetyNet / Play Integrity, the modern Android attestation
# and App Attest on iOS, which are harder to bypass than file checks
```

```bash
# Client-side checks are bypassable
# Frida, MagiskHide, and simply hooking the function work.
# The correct finding is not "root detection can be bypassed", it is
# "the app relies on client-side root detection to protect <data>,
# which is bypassable, therefore <data> must be protected server-side."
```

```bash
# What to test
# Does the app do something different on a compromised device?
# Is local data protected independently of the check?
# Is there server-side validation of the device state?
```

---

## Reporting

Report app findings like server findings, because they usually are server
findings wearing a disguise.

| Observation | What it really is |
|---|---|
| Hard-coded API key in the APK | A server credential, extractable by anyone |
| A staging URL in the build | An unpatched, weakly authenticated environment |
| Cleartext HTTP in the app | A transport finding, and a MITM one |
| Client-side authorisation | No server-side authorisation |
| Exported provider | An authorisation boundary that does not exist |
| `debuggable` in a release build | Memory readable by any user with adb |
| Root detection as the only control | No control, because it is client-side |

**For a hard-coded key, prove it minimally.** Confirm the key authenticates to
the service it belongs to, make one benign authorised call, and stop. Do not
enumerate the data behind it. The client can then rotate it and decide the
blast radius themselves, which is their decision and not yours.

**Include the exact extraction method** in the report. A finding a developer
cannot reproduce is a finding that will not be fixed, and the command that
revealed the key is as important as the key.

**Offer a version of the writeup with the secret redacted** and provide the real
value through the private channel. Mobile reports are frequently public, and a
live API key in a public report is a real problem for the client.
