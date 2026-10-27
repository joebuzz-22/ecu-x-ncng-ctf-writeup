# MediVault — Mobile / Web

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Mobile / Web · **Result:** ✅ Solved
**Flag:** `HTB{m3d1v4ult_upd4t3_expl01t3d!}`

---

## The short version

A phone app downloaded its own "updates" from a server over an insecure connection, and that
update address, when I visited it directly, just handed back the flag. I never had to take the app
itself apart.

## Background on the challenge

The target ("MediVault") was a web page that compiles an Android APK pointed at the challenge
server, and the hint pointed at the app's update mechanism ("the app wants to update itself; what
is it downloading?"). This is important because it told me the interesting behavior was in the
conversation between the app and its server, not necessarily inside the app. Reversing an APK is
slow, so I wanted to check the server side first.

## Step-by-step walkthrough (with the actual commands)

**Step 1 — Try to build/download the APK (dead end).**
The page POSTed to `/compile` to build the APK, so I tried to trigger it directly:

```bash
curl -s -X POST http://154.57.164.70:34799/compile -H "Content-Type: application/json" \
  -d '{"host":"154.57.164.70","port":"34799","protocol":"http:","fullUrl":"http://154.57.164.70:34799"}'
```

The build was stateful and flaky — concurrent requests collided on a shared server-side working
directory and corrupted it, so I was not reliably getting a clean APK. My reasoning: rather than
fight the build, re-read the hint. The hint is about the *update mechanism*, so the real target is
whatever server endpoint the app's updater talks to.

**Step 2 — Enumerate the server's endpoints.**
I probed a list of likely paths and recorded the HTTP status and response size for each:

```bash
base=http://154.57.164.70:34799
for p in /app.apk /medivault.apk /base.apk /download /downloads/ /files/ /static/ /api /update /api/update /version /api/version /check-update /latest; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 15 "$base$p")"
done
```

The results were the key:

```
/app.apk      -> 200 2256
/medivault.apk-> 200 2256
/download     -> 200 2256
/api          -> 200 2256
/update       -> 200 2256
/api/update   -> 200 48      <-- different!
/version      -> 200 2256
/latest       -> 200 2256
```

This is important because **every path returned the same 2256-byte single-page-app fallback except
`/api/update`, which returned a distinct 48-byte response.** A response that differs from every
other route is almost always real functionality, not a catch-all.

**Step 3 — Read the update endpoint.**

```bash
base=http://154.57.164.70:34799
curl -s --max-time 15 "$base/api/update"
# -> HTB{m3d1v4ult_upd4t3_expl01t3d!}
```

The update endpoint served the flag directly over plain HTTP — no APK reversing required, because
the update URL that would have been embedded in the app just returns the secret on its own.

**Step 4 — Submit the flag.**
`HTB{m3d1v4ult_upd4t3_expl01t3d!}`.

## Technical detail

- **Setup:** a web app that compiles an Android APK whose self-update routine fetches from a server
  endpoint over plain HTTP.
- **Recon result:** SPA fallback (2256 bytes) on every path except `/api/update` (48 bytes = the
  flag).
- **Root cause:** the update channel is unauthenticated and unencrypted, and the update endpoint
  returns sensitive content to anyone who requests it.
- **Why reversing was unnecessary:** the APK would only have told me the update URL — but that URL
  was directly reachable and served the secret itself.

## Lessons / remediation

- **Serve updates over TLS (HTTPS), not plain HTTP**, so the channel can't be read or tampered with.
- **Authenticate the update channel and verify update integrity** (signed updates). An exposed,
  unauthenticated update URL is not just a leak — in a real product it could let an attacker push a
  malicious "update" to every user.

## Tools used

- `curl` — the `/compile` attempt, the endpoint-enumeration loop (status + size), and reading
  `/api/update`.
- A browser — to inspect the front-end page and its `/compile` call.
