# SR Network — Web / API

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Web / API · **Result:** ✅ Solved
**Flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}`

---

## The short version

A website had a feature that quietly spent from a shared pool of "credits" every single time
it ran, and nothing stopped me from running it over and over. Once I drained that pool all the
way to zero, the error message the server returned handed me the flag.

## Walkthrough

The app for this one was called the "Star Forger Signal Relay." The first thing I did was pull
up its API documentation, which it exposed publicly, and that documentation included a very
honest developer note on the password-reset feature:

> *"One request consumes 15 star tokens. TODO: add proper rate limiting to prevent star credit
> depletion."*

As a result, I knew exactly where to look. That one note told me that every call to the reset
endpoint spends 15 credits out of a single shared company-wide pool, that there is no limit on
how often it can be called, and that it doesn't even require a login. This is important because
it means the intended attack was simply to call that endpoint enough times to drain the pool.

I was actually already hitting that endpoint repeatedly to test how the reset flow worked, and
in doing so I drained the shared pool down to empty. Once it hit zero, the server's failure
response leaked the key directly in the body:

```json
{
  "status": "company_credits_empty",
  "forge_signal_key": "HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}"
}
```

Overall, this lined up perfectly with the challenge's story about an attacker "rapidly
consuming the corporation's quantum credits." The lesson here is that anything that spends a
shared or billable resource needs a rate limit, and error messages should never contain
secrets.

## Technical detail

- **Stack:** FastAPI (Swagger UI at `/docs/`, spec at `/openapi.json`).
- **Recon:** the OpenAPI spec disclosed the full route map. The reset route's description
  included the exact cost and the missing control: *"One request consume 15 star token. TODO:
  add proper rate limiting…"*
- **Vulnerable endpoint:** `POST /api/auth/password/reset/request` — unauthenticated, no rate
  limit, deducts 15 credits per call from a single global pool.
- **Exploit:** repeated calls (also used for user enumeration) drained the global pool. The
  depleted-state response body leaks the key:
  ```json
  {"error":"Error: Company star credits depleted","status":"company_credits_empty",
   "forge_signal_key":"HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_6af947840b1b58a27f6f514738fbd823}"}
  ```
- **Secondary leaks (not required):** the reset response is a user-enumeration oracle (valid
  user returns a `code_hint`; unknown returns a generic message) and leaks the OTP's first
  digit (e.g. `"starts with '9'"`).
- **Mitigation:** rate-limit and authenticate resource-spending endpoints; never return secret
  material in an error/failure state.

---

*Tools used: curl, and the app's own OpenAPI/Swagger docs.*
