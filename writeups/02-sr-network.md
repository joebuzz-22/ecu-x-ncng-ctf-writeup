# SR Network — Web / API

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / API · **Result:** ✅ Solved
**Flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`

---

## The short version

A website had a feature that quietly spent from a shared pool of "credits" every single time it
ran, and nothing stopped me from running it over and over. Once I drained that pool all the way
to zero, the error message the server returned handed me the flag.

## Background on the challenge

The target was the "Star Forger Signal Relay," a web service built on **FastAPI**. The story
framing it was that an attacker was "rapidly consuming the corporation's quantum credits,"
disrupting communication across the galaxy. That story detail ended up being a direct hint at the
vulnerability: the whole challenge was about exhausting a shared resource. The challenge brief
also mentioned that API documentation was available at `/docs/`, which is important because
FastAPI auto-generates interactive API docs, and those docs often hand an attacker the entire map
of the application for free.

## Step-by-step walkthrough

**Step 1 — Recon the service.**
I started by fingerprinting the target and confirmed it was a FastAPI/uvicorn app. The fact that
`/docs/` worked (the Swagger UI) confirmed this, so my next move was to pull the machine-readable
version of that documentation.

**Step 2 — Pull the full API specification.**
FastAPI exposes a complete spec at `/openapi.json`. I requested it, which gave me every route, its
parameters, and its description text in one place:

```bash
curl http://<target>/openapi.json
```

This is important because it meant I did not have to guess at hidden endpoints — the app told me
exactly what it had.

**Step 3 — Spot the giveaway in the docs.**
Reading through the spec, one endpoint stood out immediately. The password-reset request route had
a developer note left right in its description:

> *"One request consume 15 star token. TODO: add proper rate limiting to prevent star credit
> depletion."*

As a result, I had both the vulnerability and the intended attack handed to me: each call to this
endpoint spends 15 credits from a shared pool, and there is no rate limiting to stop repeated
calls.

**Step 4 — Register a test account and map the credit system.**
To understand how the app behaved while authenticated, I registered a test user and logged in. I
noticed my account was user ID 2, which suggested there was a seeded admin or privileged account
at ID 1. I pulled the dashboard and profile pages to look for where a "star balance" or the flag
might be shown, but the balance was not exposed directly in those pages.

**Step 5 — Probe the reset endpoint and discover two bonus leaks.**
I began calling the password-reset request endpoint to study the reset flow. In doing so I noticed
two extra weaknesses that were not strictly required but confirmed I was on the right track:
- It acted as a **user-enumeration oracle** — a real username returned a detailed response
  including a `code_hint`, while an unknown username returned a generic "if this user exists"
  message.
- It **leaked the first digit of the one-time passcode** (for example, `"starts with '9'"`).

**Step 6 — Drain the shared credit pool.**
Because each reset request spends 15 credits from one shared company-wide pool, and because I was
already hammering that endpoint (both to test the flow and to enumerate usernames), the shared
pool steadily drained. This is important because, unlike a per-user limit, the pool is global —
so my repeated unauthenticated calls were depleting the same balance the whole "company" relied
on.

**Step 7 — Catch the flag in the failure response.**
Once the pool hit zero, the endpoint stopped behaving normally and instead returned its
depleted-state error — and that error response contained the key directly in its body:

```json
{
  "error": "Error: Company star credits depleted",
  "status": "company_credits_empty",
  "forge_signal_key": "HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}"
}
```

**Step 8 — Submit the flag.**
I pasted `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}` into the flag box.
Overall, this matched the challenge's story about draining the corporation's quantum credits
exactly.

## Technical detail

- **Stack:** FastAPI (Swagger UI at `/docs/`, OpenAPI spec at `/openapi.json`).
- **Vulnerable endpoint:** `POST /api/auth/password/reset/request` — unauthenticated, no rate
  limit, deducts 15 credits per call from a single global pool.
- **Root cause:** a shared, finite resource (the credit pool) is spent by an endpoint that any
  anonymous user can call an unlimited number of times.
- **Information leak on failure:** the depleted-state response discloses the secret key, turning a
  denial-of-service condition into a full secret disclosure.
- **Secondary issues:** user enumeration via differential responses, and partial OTP disclosure
  (first digit).

## Lessons / remediation

- **Rate-limit any endpoint that spends a shared or billable resource**, and require
  authentication where appropriate. This is the exact fix the developer's own TODO comment
  described.
- **Never place secrets in an error or failure response.** The depletion message should have been
  a neutral error, not a carrier for the key.
- **Return uniform responses** for valid and invalid usernames to prevent enumeration, and never
  leak any part of an OTP.

## Tools used

- `curl`, for probing endpoints and pulling the OpenAPI spec.
- The app's own Swagger / OpenAPI documentation, which disclosed the full attack surface.
