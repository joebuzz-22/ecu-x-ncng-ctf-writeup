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

The target was "MediVault," presented as a mobile app challenge. The web page for it would compile
an Android APK that was pointed at the challenge server, and the hint pointed at the app's update
mechanism — essentially asking, "the app wants to update itself; what is it downloading?" This is
important because it told me the interesting behavior was not necessarily *inside* the app, but in
the conversation between the app and its server. Reverse-engineering a full Android APK can be
slow, so I wanted to check the server side first before committing to that.

## Step-by-step walkthrough

**Step 1 — Explore the web front end.**
I loaded the site and read the page. It offered a button to compile and download an APK, which the
server built on demand. I looked at the page's scripts to understand how the download was triggered
and found it POSTed to a `/compile` endpoint.

**Step 2 — First dead end: the APK build was flaky.**
I tried to drive the compile/download so I could inspect the APK. The build process turned out to
be stateful and easily broken — my concurrent requests collided on a shared working directory on
the server and corrupted it, so I was not reliably getting a clean APK out. This is important
because it pushed me to reconsider whether I even needed the compiled app at all.

**Step 3 — Reframe the goal around the hint.**
The hint was explicitly about the *update mechanism*. As a result, instead of fighting the APK
build, I reasoned that the app's self-update feature must fetch from some server endpoint, and that
endpoint was the real target. So I pivoted to probing the server's API directly.

**Step 4 — Probe the server's endpoints.**
I began requesting different paths on the server to see how it responded. Most paths behaved
identically — they returned the same single-page-app fallback page (a 2256-byte HTML response),
which is what a web app typically serves for any unknown route. I was looking for the one path that
behaved *differently*, because that would be the real functionality.

**Step 5 — Find the update endpoint.**
One path broke the pattern: `/api/update` returned a small, distinct response (48 bytes) instead of
the usual fallback page. This is important because a response that differs from every other route is
almost always real, meaningful functionality rather than a catch-all.

**Step 6 — Read the flag.**
I requested that endpoint directly and it returned the flag in plain text, served over an
unencrypted HTTP connection:

```bash
curl http://<target>/api/update
# -> HTB{m3d1v4ult_upd4t3_expl01t3d!}
```

No APK reversing was needed — the update URL that would have been embedded in the app simply served
the flag.

**Step 7 — Submit the flag.**
I submitted `HTB{m3d1v4ult_upd4t3_expl01t3d!}`.

## Technical detail

- **Setup:** a web app that compiles an Android APK whose self-update routine fetches from a server
  endpoint over plain HTTP.
- **Recon result:** all paths returned the SPA fallback (2256 bytes) except `/api/update`, which
  returned a distinct 48-byte body containing the flag.
- **Root cause:** the update channel is unauthenticated and unencrypted, and the update endpoint
  returns sensitive content to anyone who requests it.
- **Why reversing was unnecessary:** the APK would only have told me the update URL — but that URL
  was directly reachable and served the secret on its own, so going through the app was a detour.

## Lessons / remediation

- **Serve updates over TLS (HTTPS), not plain HTTP**, so the channel cannot be read or tampered
  with in transit.
- **Authenticate the update channel and verify update integrity** (for example, with signed
  updates). This is important because an exposed, unauthenticated update URL is not just an
  information leak — in a real product it could let an attacker push a malicious "update" to every
  user of the app.

## Tools used

- `curl`, for probing the server's routes and reading the update endpoint.
- A browser, for inspecting the front-end page and the compile/download flow.
