# BadSignal — Forensics (Hard) — 9/12 flags (in progress)

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Forensics · **Difficulty:** Hard (1000 pts) · **Result:** 🟡 In progress — 9 of 12 flags

> I want to be upfront: this one was not a full clear. It was the only challenge in the event
> explicitly rated **Hard**, and I got it to **9 of 12 flags** while reconstructing the entire
> attack. The last three were a tooling limitation, not a dead end — more on that below.

---

## The short version

For this one I was given captured evidence of a company getting hacked, and the goal was to
reconstruct the entire attack and answer 12 questions about it. I was able to piece together the
whole break-in thanks to one lucky source of evidence: the company's web proxy had quietly kept
its own copy of everything the malware downloaded.

## Walkthrough

This was the hardest challenge I worked on, and it was less about breaking into something and
more about acting as a digital investigator. I want to walk through the story I reconstructed
first, and then give the answers.

An employee named **Jack Anderson** clicked a link in a phishing email. That link bounced
through a tracking server and a **cutt.ly** short-link, and then it downloaded a ZIP file that
was disguised as a project brief. The important detail here is that this download supposedly
"never touched the victim's disk" — but the company's **Squid web proxy had cached a full copy
of it**, and that cached copy is what made the entire investigation possible.

Inside that ZIP was a booby-trapped document that did three main things:

- It **checked whether it was being run inside a security sandbox** by looking at how long
  Windows had been installed, and it would quietly shut itself down if the machine was 8 days
  old or newer.
- It **hid its real payload inside an image file**, by tacking a hidden program onto the end of
  a PNG.
- It **set itself to run automatically** using a scheduled task named `SystemUpdateTask`.

From there, it extracted and launched a hidden backdoor program. That backdoor then "phoned
home" to the attacker's server, pulled down a second piece of malware that was disguised as an
error page, and ran further code, with a cleanup tool staged to erase its tracks afterward.

### Answers I recovered (9 of 12)

| # | Question | Answer |
|---|----------|--------|
| 1 | Phishing sender email | ⚠️ needs an email-file parser (see below) |
| 2 | Tracking URL | `http://insighttrackpro.live:1717/open?=3d51435154324150534c4d4746344247` |
| 3 | Short link → ZIP | `https://cutt.ly/6t9AaLkfM` |
| 4 | "Am I in a sandbox?" registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`InstallDate`) |
| 5 | Minimum machine age to run | `8` days |
| 6 | Files it dropped (in order) | `logo.png`, then `updater.vbs` (in `...\UpdateHelpers\`) |
| 7 | Loader launch argument | `-addfile` |
| 8 | First "phone home" endpoint + reply | `/getcalendar:500` |
| 9 | First 3 processes it watches for | ⚠️ locked inside encrypted malware config |
| 10 | Fingerprint (MD5) of the final payload | `16daae5e6f617bae71df573797ebaf74` |
| 11 | First contact with its control server | `2026-06-11 14:09:04` |
| 12 | Stolen-data credentials | ⚠️ locked inside encrypted malware config |

### Why I didn't finish the last three

I want to be clear that the last three were a **tooling limitation, not a dead end.** Question 1
(the sender email) lives inside the victim's Outlook mailbox file, which needs a dedicated
mailbox parser to read, and I did not have one available in my environment. Questions 9 and 12
are both hidden inside the backdoor's **encrypted configuration.** The malware was professionally
obfuscated, so reading those values would require a .NET deobfuscator, which I also did not have
set up at the time. As a result, I safely preserved the malware samples so they could be
analyzed offline later with the right tools.

The main lesson I took from this challenge is that when something supposedly "never hits disk" on
the victim's computer, the surrounding infrastructure — proxies, logs, and backups — very often
still has a copy. This is important because those secondary sources end up being a forensic
goldmine.

## Technical detail

- **Evidence:** `forensics_badsignal.zip` (~115 MB) containing a **Squid** capture (`access.log`
  + `squid_cache` objects) and a **KAPE** triage (`Triage_DESKTOP-TLO18PQ.zip`).
- **Victim:** Jack Anderson, `192.168.1.10` (the `.3` traffic was decoy Windows-Update noise).
- **Carving:** no `strings`/`pandoc` in-environment, so cache objects were parsed with a Node.js
  script that extracted each cached URL and carved the HTTP body. 28 cached objects indexed; key
  ones: the malicious ZIP, the `/eventmanager` 3.9 MB stage, `/planneractivate`, and the `/IUUi`
  shellcode from `20.190.31.101`.
- **Delivery:** `insighttrackpro.live:1717/open?...` → 302 → `cutt.ly/6t9AaLkfM` →
  `insighttrackpro.live:1010/DOCS/RENRGY_Project_Brief_2026.zip`.
- **ZIP contents:** an obfuscated `.hta` (JScript) + `Banner.png` + `file.vbs`.
- **HTA logic:** anti-sandbox check via
  `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate /reg:64`;
  `window.close()` if `(now − InstallDate)/86400 ≤ 8` days; drops
  `%LOCALAPPDATA%\UpdateHelpers\logo.png` then `updater.vbs`; persists via a `schtasks` task
  `SystemUpdateTask` → `wscript.exe updater.vbs`.
- **Loader:** `file.vbs` is a `chr()`-arithmetic obfuscator that builds and `Execute`s a stage
  which carves `Libraries.exe` out of `logo.png` after a `[DATA_START]` marker and runs it with
  `-addfile`.
- **Backdoor:** `Libraries.exe` is a 711,680-byte .NET assembly (`RegexFinder`), beaconing to
  `virtualtimeplanner.pro:9100` (`/getcalendar` → `500`), pulling `meow.exe` (hidden as a decimal
  byte-array inside a fake 404), which runs wininet shellcode to fetch/exec `/IUUi`.
- **Final payload MD5:** `16daae5e6f617bae71df573797ebaf74`. First C2 contact: `2026-06-11 14:09:04`.
- **Open items (tooling-limited):** Q1 sender SMTP is not stored as plaintext in the OST
  (`bCryptMethod=0x00`; only the "REnrgy Group" display name is recoverable) — needs
  `readpst`/`pypff`/XstReader. Q9 (process blacklist) and Q12 (exfil creds) are AES-encrypted in
  IntelliLock-protected managed resources — need dnSpy/de4dot to decrypt.

---

*Tools used: Squid proxy cache + access-log analysis, KAPE triage data, Node.js carving scripts,
manual VBS/JScript deobfuscation, REA (.NET analysis), MD5 hashing, SQLite, Windows Search index.*
