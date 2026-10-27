# BadSignal — Forensics (Hard) — 9/12 flags (in progress)

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Forensics · **Difficulty:** Hard (1000 pts) · **Result:** 🟡 In progress — 9 of 12 flags

> I want to be upfront: this one was not a full clear. It was the only challenge in the event
> explicitly rated **Hard**, and I got it to **9 of 12 flags** while reconstructing the entire
> attack from start to finish. The last three were a tooling limitation, not a dead end — I
> explain exactly where I got stuck and what would finish them.

---

## The short version

For this one I was given captured evidence of a company getting hacked, and the goal was to
reconstruct the entire attack and answer 12 questions about it. I was able to piece together the
whole break-in thanks to one lucky source of evidence: the company's web proxy had quietly kept
its own copy of everything the malware downloaded.

## Background on the challenge

BadSignal was a network-forensics investigation. Instead of breaking into a live target, I was
handed a package of captured evidence and had to play investigator: figure out how the victim got
infected, what the malware did at each stage, and answer 12 specific questions to score the flags.
The challenge hint was the single most useful clue — it said the downloaded archive "never touched
disk," but that the network proxy had kept its own copy of everything it served. This is important
because it told me up front that even though the malware tried to stay off the victim's hard drive,
the proxy's cache would still contain full copies of the malicious files.

The evidence package, `forensics_badsignal.zip` (~115 MB), contained two things:
- **A Squid proxy capture** — the proxy's `access.log` plus a `squid_cache` folder holding the
  proxy's own saved copy of every object it served.
- **A KAPE disk triage** (`Triage_DESKTOP-TLO18PQ.zip`) — a forensic snapshot of the victim PC:
  registry, logs, and dropped files.

## Step-by-step walkthrough

**Step 1 — Unpack the evidence into an isolated folder.**
Because the evidence is literally live malware, I extracted it into its own separate, empty
directory and kept my analysis scripts somewhere else. This is important because it prevents any
accidental execution and keeps the untrusted files from interfering with my tools.

**Step 2 — Read the proxy access log and filter out the noise.**
The Squid `access.log` had about 6,669 lines, and most of them were ordinary Windows Update
traffic — noise. I filtered down to the interesting hosts, request methods, and content types to
find the actual infection chain. As a result, a few suspicious domains quickly surfaced:
`cutt.ly` (a link shortener), `insighttrackpro.live` (on unusual ports), and
`virtualtimeplanner.pro` (also on unusual ports, a likely command-and-control server).

**Step 3 — Build the victim's timeline.**
Pulling the suspicious requests in time order let me reconstruct the sequence for the victim,
`192.168.1.10` (I also confirmed that some `.3` traffic was just decoy Windows-Update noise, not
the victim). The chain was: a click on a tracking link → a 302 redirect → a shortened link → the
download of a malicious ZIP → later callbacks to the C2 server.

**Step 4 — Carve the cached files out of the proxy.**
The proxy had cached 28 objects, including the malicious payloads. There was no `strings` utility
available in my environment, so I wrote a small **Node.js script** to parse each Squid cache
object, pull out the URL it corresponded to, and carve the raw HTTP body back out to a file. This
is important because it recovered the actual malware files — the ZIP, the later stages, and the
shellcode — directly from the proxy, exactly as the hint promised.

**Step 5 — Open the malicious ZIP.**
The key download was `RENRGY_Project_Brief_2026.zip`, disguised as a project brief. Inside it were
three files hidden under an obfuscated folder name: an **HTA file**
(`RENRGY_TechnicalAssessment_2026.html`, a Windows HTML Application), a `Banner.png` image, and a
`file.vbs` script.

**Step 6 — Deobfuscate the HTA (answers several questions).**
The HTA contained obfuscated JScript. After decoding it, I could see exactly what it did, which
answered several of the questions at once:
- **Anti-sandbox check:** it queried
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` value `InstallDate` to find out how long
  Windows had been installed.
- **Age threshold:** it computed the machine's age in days and did
  `if (days <= 8) window.close()` — meaning it would quietly quit on any machine 8 days old or
  newer (a common trick to avoid freshly-built analysis sandboxes).
- **Dropped files:** it wrote `%LOCALAPPDATA%\UpdateHelpers\logo.png` (from `Banner.png`) and then
  `%LOCALAPPDATA%\UpdateHelpers\updater.vbs` (from `file.vbs`), and set up persistence with a
  scheduled task named `SystemUpdateTask` that runs `wscript.exe updater.vbs`.

**Step 7 — Deobfuscate the loader (`file.vbs` → `updater.vbs`).**
This script was a `chr()`-arithmetic obfuscator: it builds another script out of character-code
math and then `Execute`s it. I decoded it programmatically and found that it carves an embedded
executable, `Libraries.exe`, out of the `logo.png` image — specifically the bytes after a
`[DATA_START]` marker — and then launches that executable with the argument **`-addfile`**. This is
a classic stego technique: the real malware was hidden on the end of an innocent-looking PNG.

**Step 8 — Carve and identify the backdoor.**
I carved `Libraries.exe` out of the PNG. It turned out to be a **.NET assembly** of 711,680 bytes
(internally named `RegexFinder`). From the proxy data and the binary, I mapped its behavior: it
beacons to `virtualtimeplanner.pro:9100`, where `/getcalendar` returns `500` as its
success/acknowledgement response, then pulls a second stage (`meow.exe`) that was hidden as a
decimal byte-array inside what looked like a fake 404 error page. That stage runs wininet shellcode
to fetch and execute a further payload from `/IUUi` on `20.190.31.101`.

**Step 9 — Fingerprint the final payload.**
I computed the MD5 hash of the carved `/IUUi` shellcode to get its fingerprint:
`16daae5e6f617bae71df573797ebaf74`. I also pulled the timestamp of the first C2 contact from the
proxy log: `2026-06-11 14:09:04`.

**Step 10 — Collect the answers I had, and hit the wall on the last three.**
At this point I had solid answers for 9 of the 12 questions (listed below). The remaining three
all required capabilities my environment did not have:
- The **phishing sender's email address** lives inside the victim's Outlook mailbox file (`.ost`).
  I confirmed the mailbox was technically unencoded, but the sender's actual SMTP address is not
  stored as readable plaintext in it — only the display name "REnrgy Group" was recoverable.
  Reading the real `From:` address needs a dedicated mailbox parser.
- The **process blacklist** (the first processes the malware watches for) and the **exfil
  credentials** are both stored inside the backdoor's configuration, which is **AES-encrypted
  inside IntelliLock-protected .NET resources**. Reading them needs a .NET deobfuscator/decompiler.

I safely preserved the carved samples so these could be finished offline with the right tools,
rather than guessing.

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

## The full attack chain (summary)

1. **Phishing email** reaches the victim, Jack Anderson (`192.168.1.10`).
2. Victim clicks a **tracking link** → `insighttrackpro.live:1717/open?...` returns a **302
   redirect**.
3. Redirect goes through a **cutt.ly short link** → downloads
   `insighttrackpro.live:1010/DOCS/RENRGY_Project_Brief_2026.zip` (the proxy cached the whole file).
4. The ZIP's **HTA** runs an **anti-sandbox age check**, drops `logo.png` + `updater.vbs`, and
   persists via the `SystemUpdateTask` scheduled task.
5. **`updater.vbs`** carves **`Libraries.exe`** out of `logo.png` (after `[DATA_START]`) and runs it
   with `-addfile`.
6. **`Libraries.exe`** (.NET backdoor) beacons to `virtualtimeplanner.pro:9100`, pulls **`meow.exe`**
   hidden in a fake 404 page, which runs shellcode to fetch/execute **`/IUUi`** from
   `20.190.31.101`. A cleanup tool was staged to erase the tracks.

## Why I didn't finish the last three (tooling, not a dead end)

- **Q1 (sender email):** needs an OST/PST mailbox parser such as `readpst`, `pypff`, or XstReader
  to read the message's real `From:` / `PidTagSenderSmtpAddress`. The display name "REnrgy Group" is
  recoverable, but the SMTP address is not stored in readable form.
- **Q9 & Q12 (process blacklist, exfil creds):** these values are AES-encrypted inside
  IntelliLock-protected managed resources in `Libraries.exe`/`meow.exe`. They need a .NET
  deobfuscator/decompiler (dnSpy, de4dot, or ILSpy) to decrypt and read.

The main lesson I took from this challenge is that when something supposedly "never hits disk" on
the victim's computer, the surrounding infrastructure — proxies, logs, and backups — very often
still has a copy. This is important because those secondary sources end up being a forensic
goldmine, and in this case the proxy cache is the only reason the whole chain could be
reconstructed at all.

## Technical detail

- **Evidence:** `forensics_badsignal.zip` (~115 MB) — a **Squid** capture (`access.log` +
  `squid_cache` objects) and a **KAPE** triage (`Triage_DESKTOP-TLO18PQ.zip`).
- **Victim:** Jack Anderson, `192.168.1.10` (the `.3` traffic was decoy Windows-Update noise).
- **Carving:** 28 cached objects parsed with a Node.js script that extracted each cached URL and
  carved its HTTP body — recovering the ZIP, the `/eventmanager` 3.9 MB stage, `/planneractivate`,
  and the `/IUUi` shellcode from `20.190.31.101`.
- **Delivery:** `insighttrackpro.live:1717/open?...` → 302 → `cutt.ly/6t9AaLkfM` →
  `insighttrackpro.live:1010/DOCS/RENRGY_Project_Brief_2026.zip`.
- **ZIP contents:** an obfuscated `.hta` (JScript) + `Banner.png` + `file.vbs`.
- **HTA logic:** anti-sandbox via
  `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate /reg:64`;
  `window.close()` if `(now − InstallDate)/86400 ≤ 8` days; drops
  `%LOCALAPPDATA%\UpdateHelpers\logo.png` then `updater.vbs`; persists via a `schtasks` task
  `SystemUpdateTask` → `wscript.exe updater.vbs`.
- **Loader:** `file.vbs` — a `chr()`-arithmetic obfuscator that builds and `Execute`s a stage which
  carves `Libraries.exe` from `logo.png` after a `[DATA_START]` marker and runs it with `-addfile`.
- **Backdoor:** `Libraries.exe` — a 711,680-byte .NET assembly (`RegexFinder`) beaconing to
  `virtualtimeplanner.pro:9100` (`/getcalendar` → `500`), pulling `meow.exe` (hidden as a decimal
  byte-array in a fake 404), which runs wininet shellcode to fetch/exec `/IUUi`.
- **Final payload MD5:** `16daae5e6f617bae71df573797ebaf74`. **First C2 contact:** `2026-06-11 14:09:04`.
- **Open items:** Q1 sender SMTP not stored as plaintext in the OST (`bCryptMethod=0x00`; only the
  "REnrgy Group" display name recoverable) — needs `readpst`/`pypff`/XstReader. Q9/Q12 are
  AES-encrypted in IntelliLock-protected managed resources — need dnSpy/de4dot.

## Tools used

- **Squid proxy cache + access-log analysis** — the primary evidence source.
- **KAPE triage data** — registry, logs, and dropped files from the victim PC.
- **Node.js scripts** — custom carving of HTTP bodies out of the raw proxy cache.
- **Manual deobfuscation** of the HTA (JScript) and the VBS loader (`chr()` arithmetic).
- **Stego / payload carving** — extracting `Libraries.exe` from `logo.png` after `[DATA_START]`.
- **REA ("Reverse Engineer Anything")** — .NET assembly analysis.
- **MD5 hashing, SQLite (browser history), Windows Search index (`Windows.edb`)** — supporting
  lookups.
- *Would have needed to finish:* a .NET deobfuscator (dnSpy/de4dot/ILSpy) and an OST parser
  (readpst/pypff/XstReader).
