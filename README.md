# ECU x NCNG CTF — My Writeups (2026-10-23)

These are my writeups from the **[ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676)**,
a Capture The Flag **competition** hosted on the HackTheBox platform. This was a timed, scored
event, so my goal going in was to solve as many challenges as possible across the different
categories. Everything documented here was done against the competition's own authorized
practice targets, which are spun up for the event and torn down afterward. No real systems were
ever involved.

**Authors:** [Joseph Inkumsah (joebuzz-22)](https://github.com/joebuzz-22) & Claude (Anthropic)

---

## What this is (for readers who aren't in security)

A **CTF (Capture The Flag)** is essentially a hacking competition made up of puzzles. Each
challenge is a small app or piece of evidence that has been deliberately built to be broken in a
specific way, and the job is to find that weakness and use it to recover a hidden secret called a
**flag**. Every flag in this event looks like `HTB{...}`, and submitting a correct one scores
points for your team. This is important because it means the entire competition is built around
*finding and understanding* weaknesses rather than causing any actual harm — everything happens
inside a controlled, authorized environment.

This particular competition mixed five different categories, and I ended up touching all of them:
**Web**, **OAuth**, **Mobile / API**, **AI / Prompt Injection**, and **Forensics**. Overall, I
solved four challenges outright and took a hard forensics investigation to 9 of its 12 flags
while reconstructing the entire attack from start to finish.

Each writeup below is written in plain language first, then has a separate technical section for
anyone who wants the exact payloads, commands, and protocol-level detail.

## Writeups

| # | Challenge | Category | Result | Writeup |
|---|-----------|----------|--------|---------|
| 1 | The Oracle | AI / Prompt Injection | ✅ Solved | [01-the-oracle.md](writeups/01-the-oracle.md) |
| 2 | SR Network | Web / API | ✅ Solved | [02-sr-network.md](writeups/02-sr-network.md) |
| 3 | Gateway | Web / OAuth | ✅ Solved | [03-gateway.md](writeups/03-gateway.md) |
| 4 | MediVault | Mobile / Web | ✅ Solved | [04-medivault.md](writeups/04-medivault.md) |
| 5 | BadSignal | Forensics (Hard) | 🟡 9/12 flags | [05-badsignal.md](writeups/05-badsignal.md) |

---

## Tools, VMs & Environment

Since a competition like this is as much about the setup as it is about the actual solving, here
is everything I used to work through these challenges.

**Platforms & machines**
- **HackTheBox** — the competition platform, which provided all of the targets. Some were
  temporary Docker containers I could reach directly, and others were lab machines locked behind
  a VPN.
- **Windows 11** — my main host computer, where I did most of the direct web work.
- **Kali Linux running in Oracle VirtualBox** — a dedicated "attacker" virtual machine. I set
  this up as a separate Linux environment for the parts that needed a full Linux toolkit and a
  VPN tunnel into the lab network. Keeping the attacker tools inside their own VM keeps
  everything contained and easy to reset.
- **OpenVPN** — used to connect into HackTheBox's private lab networks.

**Web hacking & recon**
- **curl** — my main tool for sending web requests and probing endpoints by hand.
- **Bash** and **PowerShell** — for scripting and automating the repetitive parts.
- **Web browsers** (an in-app browser and a Chrome extension) — for interacting with the target
  web apps and pulling down challenge files that were behind a login.
- **Swagger / OpenAPI docs** (`/docs/`, `/openapi.json`) — the apps' own auto-generated API
  documentation, which often hands over the entire attack surface for free.
- **webhook.site** — a free "catch any incoming web request" service, used as an external
  listener to capture a stolen login code in the OAuth challenge.

**Reverse engineering & digital forensics**
- **REA ("Reverse Engineer Anything")** — a reverse-engineering toolkit used to pick apart a
  malicious .NET program.
- **Squid proxy cache + access logs** — the captured web-proxy evidence in the forensics
  challenge.
- **KAPE triage data** — a forensic snapshot of the victim PC (registry, logs, dropped files).
- **Node.js scripts** — small custom scripts to carve files directly out of the raw proxy cache.
- **Stego / payload carving**, **manual deobfuscation** of VBScript/JScript, **MD5 hashing**,
  **SQLite** (browser history), and the **Windows Search index** (`Windows.edb`).
- *What I would have needed to finish the last three forensics flags (and didn't have in this
  environment):* a **.NET deobfuscator/decompiler** (dnSpy / de4dot / ILSpy) and an **Outlook
  mailbox parser** (readpst / pypff / XstReader).

---

## Notes

- Flags are shown as I captured them during the competition. The practice targets are temporary
  and have since been torn down, so specific target IP addresses and one-time download links are
  intentionally left out — they are no longer meaningful.
- The BadSignal investigation was still in progress when the event wrapped, so its writeup
  reflects only what I confirmed (9 of 12 flags), with the remaining three noted honestly as a
  tooling gap rather than a dead end.
