# MediVault — Mobile / Web

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Mobile / Web · **Result:** ✅ Solved
**Flag:** `HTB{m3d1v4ult_upd4t3_expl01t3d!}`

---

## The short version

A phone app downloaded its own "updates" from a server over an insecure connection, and that
update address, when I visited it directly, just handed back the flag. I never had to take the
app itself apart.

## Walkthrough

Going into this one, my first instinct was that I would have to reverse-engineer the Android
app, which can be slow. Instead, I decided to look at the server the app talks to first, since
the challenge hint pointed at the app's self-update feature. This turned out to be the right
call. When I probed the server's different URLs, every single path returned the same generic
page **except** for one: `/api/update`, which returned a small, distinct response.

That one endpoint was serving the flag over a plain, unencrypted connection:

```bash
curl http://<target>/api/update
# -> HTB{m3d1v4ult_upd4t3_expl01t3d!}
```

The lesson here is that update channels have to be encrypted and verified. This is important
because an exposed, unauthenticated update URL is not just a way to leak information — in a real
product, it could let an attacker push a malicious "update" out to every single user.

## Technical detail

- **Setup:** a web app that compiles an Android APK whose self-update routine fetches from a
  server endpoint over plain HTTP.
- **Recon:** all paths returned the SPA fallback (2256 bytes) except `/api/update`, which
  returned a distinct 48-byte body.
- **Exploit:** `curl http://<target>/api/update` → `HTB{m3d1v4ult_upd4t3_expl01t3d!}`. No APK
  reversing required.
- **Mitigation:** serve updates over TLS with signature/integrity verification; authenticate
  the update channel so clients can't be fed malicious payloads.

---

*Tools used: curl.*
