# BadSignal — Forensics (Hard) — 9/12 flags (in progress)

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Forensics · **Difficulty:** Hard (1000 pts) · **Result:** 🟡 In progress — 9 of 12 flags

> Upfront: this was not a full clear. It was the only **Hard**-rated challenge in the event, and I
> reconstructed the entire attack and got **9 of 12 flags**. The last three were a tooling
> limitation (no .NET deobfuscator, no Outlook mailbox parser in my environment), not a dead end.

---

## The short version

I was given captured evidence of a company getting hacked and had to reconstruct the whole attack
and answer 12 questions. The break-in was fully recoverable because the company's web proxy had
kept its own cached copy of everything the malware downloaded.

## Background on the challenge

BadSignal is a network-forensics investigation. The hint said the downloaded archive "never
touched disk," but the network proxy kept a copy of everything it served. The evidence package
`forensics_badsignal.zip` (~115 MB) contained a **Squid proxy capture** (`access.log` +
`squid_cache`) and a **KAPE disk triage** (`Triage_DESKTOP-TLO18PQ.zip`).

> Safety note: the commands below are the ones I used to *analyze* the evidence. I have deliberately
> not reproduced any malware source, shellcode bytes, or payload contents here.

## Step-by-step walkthrough (with the actual commands)

**Step 1 — Unpack the evidence into an isolated folder.**
Because this is live malware, I extracted everything into its own directory and kept my scripts
elsewhere:

```bash
mkdir -p .../scratchpad/badsignal && cd .../scratchpad/badsignal
unzip -o "/c/Users/joein/Downloads/forensics_badsignal.zip" -d ./extracted
cd extracted && mkdir -p triage proxy
unzip -o Triage_DESKTOP-TLO18PQ.zip -d triage
unzip -o proxy_server_logs.zip -d proxy
```

**Step 2 — Read the proxy access log and strip the noise.**

```bash
cd .../proxy/proxy_server_logs/squid_logs
wc -l access.log            # ~6,669 lines
head -80 access.log
# unique hosts, then drop the Windows-Update / CDN noise:
grep -oE 'https?://[^/ ]+' access.log | sort | uniq -c | sort -rn
grep -vE 'microsoft|windowsupdate|msftconnecttest|msftncsi|digicert|verisign|gvt1|google|mozilla|firefox' access.log | head -60
```

My reasoning: most proxy traffic in a real capture is benign OS/update noise, so filtering it out
is the fastest way to surface the few malicious hosts.

**Step 3 — Pin down the suspicious hosts and the timeline.**

```bash
grep -niE 'virtualtimeplanner|insighttrackpro|20.190.31|bit\.ly|tinyurl|cutt\.ly' access.log
grep -nF 'insighttrackpro' access.log
grep -nF 'virtualtimeplanner' access.log
```

This surfaced `insighttrackpro.live` (tracking/redirect, ports 1717/1010), a `cutt.ly` short link,
`virtualtimeplanner.pro` (C2, ports 9100/etc.), and `20.190.31.101`. The victim was
`192.168.1.10` (the `.3` traffic was decoy Windows-Update noise).

**Step 4 — Carve the cached objects out of the proxy.**
I indexed the cache objects (size + first URL inside each) so I could tell which cached file was
which:

```bash
cd .../squid_cache
find . -type f | wc -l     # 28 cached objects
for f in $(find . -type f | sort); do
  url=$(strings -n 6 "$f" | grep -aoE 'https?://[^ ]+' | head -1)
  sz=$(stat -c%s "$f"); echo "$f  [$sz]  $url"
done
```

The Squid cache objects have HTTP headers prepended to the body, so to get usable files I carved
the bodies out. (My first attempt used a Python carver, `python -I parse_squid.py ...`, but Python
was only the non-functional Store stub here, so I wrote a small Node.js carver instead that wrote
each body to `cache_out/..._NNNNN.body`.)

**Step 5 — Recover the malicious ZIP.**
The carved object `00000011` was the ZIP. I renamed and unpacked it:

```bash
cp cache_out/00_00_00000011.body zip_extract/RENRGY_Project_Brief_2026.zip
cd zip_extract && unzip -l RENRGY_Project_Brief_2026.zip
unzip -o RENRGY_Project_Brief_2026.zip -d contents
find contents -type f -exec ls -la {} \;
```

Inside (under an obfuscated `··/` folder) were an **HTA** file, `Banner.png`, and `file.vbs`.

**Step 6 — Read the decoy HTA (answers Q4–Q6).**
Deobfuscating the HTA's JScript revealed the anti-sandbox logic and the dropped files:
- **Anti-sandbox (Q4):** it queries
  `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate /reg:64`.
- **Age threshold (Q5):** it computes `(now − InstallDate)/86400` days and does
  `if (days <= 8) window.close()` → it only runs on machines **older than 8 days**.
- **Dropped files (Q6):** `%LOCALAPPDATA%\UpdateHelpers\logo.png` (from `Banner.png`), then
  `updater.vbs` (from `file.vbs`); persistence via a `schtasks` task **`SystemUpdateTask`** running
  `wscript.exe updater.vbs`.

**Step 7 — Carve the backdoor out of the PNG (Q7, Q10 setup).**
The VBS loader builds its script via `chr()` arithmetic, then carves an executable out of the PNG
after a `[DATA_START]` marker and runs it with **`-addfile`** (Q7). I located the marker offset and
carved it:

```bash
grep -abo '\[DATA_START\]' "zip_extract/contents/··/Banner.png" | head
dd if="zip_extract/contents/··/Banner.png" of="backdoor/Libraries.exe" bs=1 skip=565579 2>/dev/null
head -c2 backdoor/Libraries.exe | xxd        # "MZ" — a PE executable
md5sum backdoor/Libraries.exe
```

`Libraries.exe` was a 711,680-byte **.NET assembly** (internally `RegexFinder`).

**Step 8 — Map the C2 behavior from the cached stages (Q8, Q11).**

```bash
# the first "phone home" endpoint's cached response body:
cat cache_out/00_00_00000020.body        # /getcalendar -> "500"
# the final payload fetched from 20.190.31.101/IUUi:
md5sum cache_out/00_00_00000024.body      # 16daae5e6f617bae71df573797ebaf74
# first C2 contact time, from the access log:
sed -n '3205,3222p' access.log
```

So the first endpoint + success response is **`/getcalendar:500`** (Q8), the final payload MD5 is
`16daae5e6f617bae71df573797ebaf74` (Q10), and the first C2 contact was **`2026-06-11 14:09:04`**
(Q11). The backdoor beacons to `virtualtimeplanner.pro:9100`, pulls `meow.exe` (hidden as a decimal
byte-array inside a fake 404 page), which runs shellcode to fetch/exec `/IUUi`.

**Step 9 — Hunt for the remaining answers (Q1, Q9, Q12) — where I hit the wall.**
- **Q1 (phishing sender):** the victim's Outlook mailbox is at
  `.../Jack Anderson/AppData/Local/Microsoft/Outlook/jack.a015@outlook.com.ost`. I searched it
  every way I could — ASCII and UTF-16 (null-stripped), the Windows Search index, and Edge history:
  ```bash
  grep -aoiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "jack.a015@outlook.com.ost" | sort -u
  tr -d '\000' < "jack.a015@outlook.com.ost" | grep -aoiE 'SMTP:[a-z0-9._%+-]+@[a-z0-9.-]+' | sort -u
  grep -aoiE 'https?://[a-z0-9./?=:&_%-]{5,}' ".../Edge/User Data/Default/History" | sort -u
  tr -d '\000' < Windows.edb | grep -aoiE 'renrgy[a-z0-9.-]*|[a-z0-9._%+-]{2,}@[a-z0-9.-]{3,}\.[a-z]{2,}' | sort -u
  ```
  Only the sender **display name** "REnrgy Group" was recoverable; the actual SMTP address is not
  stored as readable text (the message bodies are compressed/structured inside the OST). Reading the
  real `From:` needs a proper mailbox parser.
- **Q9 & Q12 (process blacklist, exfil creds):** I pulled strings from the carved backdoor and
  checked for debugger/analysis process names and FTP/credential strings:
  ```bash
  grep -niE 'wireshark|procmon|x64dbg|dnspy|fiddler|vmtoolsd|processhacker|\.exe' lib_strings.txt | grep -iv RegexFinder
  grep -niE 'ftp|USER|PASS|anonymous|login|credential|STOR|:21|@' styles_strings.txt
  for t in de4dot ilspycmd dotnet mono ildasm readpst pff pffexport; do printf "%s: " "$t"; command -v "$t" || echo no; done
  ```
  Both values are **AES-encrypted inside IntelliLock-protected .NET resources**, and none of the
  needed deobfuscation tools were installed. So I preserved the samples for offline analysis rather
  than guessing.

### Answers I recovered (9 of 12)

| # | Question | Answer |
|---|----------|--------|
| 1 | Phishing sender email | ⚠️ needs a mailbox parser (only "REnrgy Group" display name recovered) |
| 2 | Tracking URL | `http://insighttrackpro.live:1717/open?=3d51435154324150534c4d4746344247` |
| 3 | Short link → ZIP | `https://cutt.ly/6t9AaLkfM` |
| 4 | Anti-sandbox registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`InstallDate`) |
| 5 | Minimum machine age | `8` days |
| 6 | Dropped files (in order) | `logo.png`, then `updater.vbs` (in `...\UpdateHelpers\`) |
| 7 | Loader launch argument | `-addfile` |
| 8 | First "phone home" endpoint + reply | `/getcalendar:500` |
| 9 | First 3 blacklist processes | ⚠️ AES-encrypted in the backdoor config |
| 10 | Final payload MD5 | `16daae5e6f617bae71df573797ebaf74` |
| 11 | First C2 contact | `2026-06-11 14:09:04` |
| 12 | Exfil credentials | ⚠️ AES-encrypted in the backdoor config |

## The full attack chain (summary)

1. **Phishing email** to Jack Anderson (`192.168.1.10`).
2. Click → `insighttrackpro.live:1717/open?...` → **302 redirect** → **cutt.ly** short link →
   downloads `insighttrackpro.live:1010/DOCS/RENRGY_Project_Brief_2026.zip` (cached by the proxy).
3. ZIP's **HTA** runs the anti-sandbox age check, drops `logo.png` + `updater.vbs`, persists via
   `SystemUpdateTask`.
4. **`updater.vbs`** carves **`Libraries.exe`** from `logo.png` (after `[DATA_START]`), runs it with
   `-addfile`.
5. **`Libraries.exe`** (.NET backdoor) beacons to `virtualtimeplanner.pro:9100`, pulls `meow.exe`
   (hidden in a fake 404), which runs shellcode to fetch/exec `/IUUi` from `20.190.31.101`.

## Why I didn't finish the last three (tooling, not a dead end)

- **Q1:** needs an OST/PST parser (`readpst`, `pypff`, XstReader) to read the message's real
  `From:` — none installed.
- **Q9 & Q12:** AES-encrypted inside IntelliLock-protected managed resources; need a .NET
  deobfuscator (dnSpy, de4dot, ILSpy).

The lesson: when something "never hits disk" on the victim, the surrounding infrastructure —
proxies, logs, backups — usually still has a copy. That proxy cache is the only reason the whole
chain could be reconstructed.

## Tools used

- `unzip`, `find`, `ls`, `wc`, `head`, `sed` — unpacking and triaging the evidence.
- `grep` (ASCII + `tr -d '\000'` for UTF-16) — log filtering, host/timeline hunting, OST and
  `Windows.edb` searches.
- `strings`, `stat` — indexing the Squid cache objects.
- A **Node.js carver** — extracting HTTP bodies from Squid cache objects (after `python` turned out
  to be unavailable).
- `dd` + `xxd` — carving `Libraries.exe` out of `Banner.png` and confirming the `MZ` header.
- `md5sum` — fingerprinting the carved backdoor and the final `/IUUi` payload.
- **REA** — .NET assembly inspection.
- *Would have needed to finish:* a .NET deobfuscator (dnSpy/de4dot/ILSpy) and an OST parser
  (readpst/pypff/XstReader).
