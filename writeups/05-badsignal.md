# BadSignal — Forensics (Hard) — 9/12 flags (in progress)

**Competition:** [ECU x NCNG CTF](https://ctf.hackthebox.com/event/details/ecu-x-ncng-ctf-3676) (HackTheBox)
**Category:** Forensics · **Difficulty:** Hard (1000 pts) · **Result:** 🟡 In progress — 9 of 12 flags

> Upfront: this was not a full clear. It was the only **Hard**-rated challenge in the event, and I
> reconstructed the entire attack and got **9 of 12 flags**. The last three needed a .NET
> deobfuscator and an Outlook mailbox parser I didn't have — a tooling gap, not a dead end.
>
> Safety note: the commands below are the ones I used to *analyze* the evidence. I have deliberately
> not reproduced malware source, shellcode bytes, or payload contents.

---

## The short version

I was given captured evidence of a company getting hacked and had to reconstruct the whole attack
and answer 12 questions. It was fully recoverable because the company's web proxy kept its own
cached copy of everything the malware downloaded.

## Background

Network-forensics. Evidence package `forensics_badsignal.zip` (~115 MB) held a **Squid proxy
capture** (`access.log` + `squid_cache`) and a **KAPE disk triage** (`Triage_DESKTOP-TLO18PQ.zip`).
The hint said the download "never touched disk," but the proxy kept a copy.

## Every step, in order (exact commands)

**1 — Unpack into an isolated folder (it's live malware).**

```bash
SP="/c/.../scratchpad"
D="$SP/badsignal"; rm -rf "$D"; mkdir -p "$D/extracted"
cd "$D"
unzip -o "/c/Users/joein/Downloads/forensics_badsignal.zip" -d extracted 2>&1 | tail -20
unzip -l extracted/*.zip 2>/dev/null | head
find extracted -maxdepth 3 -printf "%y %10s  %p\n" 2>/dev/null | head -60
```

```bash
D="$SP/badsignal"; cd "$D"; mkdir -p proxy
unzip -o extracted/proxy_server_logs.zip -d proxy 2>&1 | tail -30
find proxy -maxdepth 4 -printf "%y %10s  %p\n" 2>/dev/null | head -80
```

**2 — Read the whole access log (it's the index) and list cache objects.**

```bash
D="$SP/badsignal/proxy/proxy_server_logs"
echo "=== access.log size & lines ==="; wc -l "$D/squid_logs/access.log"
echo "=== access.log (full) ==="; cat "$D/squid_logs/access.log"
echo "=== non-empty cache objects ==="
find "$D/squid_cache" -type f -size +0c -printf "%s  %p\n" 2>/dev/null | sort -n | tail -40
```

**3 — Find the suspicious hosts and the timeline (filter out MS/Windows-Update noise).**

```bash
L="$SP/badsignal/proxy/proxy_server_logs/squid_logs/access.log"
awk '{print $7}' "$L" | sed -E 's#^[a-z]+://([^/]+).*#\1#' | sort | uniq -c | sort -rn \
 | grep -viE 'windowsupdate|microsoft|windows\.com|msftconnecttest|delivery\.mp|digicert|verisign|msedge|office|bing|azureedge|gstatic|google|mozilla|ubuntu|skype' | head -50
```

```bash
L="$SP/badsignal/proxy/proxy_server_logs/squid_logs/access.log"
grep -nE 'virtualtimeplanner|insighttrackpro|cutt\.ly|exceptionless' "$L" | sort -t. -k1 -n | awk '{ $2=$2; print }' | head -80
```

This surfaced `insighttrackpro.live` (tracking/redirect, ports 1717/1010), a `cutt.ly` short link,
and `virtualtimeplanner.pro:9100` (C2). Victim: `192.168.1.10`.

**4 — Map URLs to cache files, and index each object (size + URL).**

```bash
C="$SP/badsignal/proxy/proxy_server_logs/squid_cache"
echo "=== count non-empty cache files ==="; find "$C" -type f -size +0c | wc -l
for kw in "insighttrackpro.live:1717/open" "RENRGY_Project_Brief" "cutt.ly" "virtualtimeplanner.pro:9100/eventmanager" "virtualtimeplanner.pro:9100/getcalendar" "virtualtimeplanner.pro:9100/planneractivate" "submit.php"; do
  echo "--- [$kw] ---"; grep -rlaF "$kw" "$C" 2>/dev/null | head -5
done
```

```bash
C="$SP/badsignal/proxy/proxy_server_logs/squid_cache"
for f in $(find "$C" -type f -size +0c | sort); do
  url=$(strings -n 6 "$f" | grep -aoE 'https?://[^ ]+' | head -1)
  sz=$(stat -c %s "$f")
  printf "%-10s %8s  %s\n" "$(basename $f)" "$sz" "$url"
done
```

**5 — Carve the HTTP bodies out of the Squid cache (custom Node carver).**
Squid cache objects have the HTTP headers prepended, so I wrote a carver to split headers from body
and name each by its URL:

```bash
SP="/c/.../scratchpad/badsignal"
C="$SP/proxy/proxy_server_logs/squid_cache"
OUT="$SP/carved"; mkdir -p "$OUT"
cat > "$SP/carve.js" <<'EOF'
const fs=require('fs'),path=require('path');
const C=process.argv[2], OUT=process.argv[3];
function walk(d){let r=[];for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory())r=r.concat(walk(p));else if(e.isFile()&&fs.statSync(p).size>0)r.push(p);}return r;}
const files=walk(C).sort();
for(const f of files){
  const buf=fs.readFileSync(f);
  const txt=buf.toString('latin1');
  const um=txt.match(/https?:\/\/[^\x00-\x1f ]+/); const url=um?um[0]:'';
  const hi=txt.indexOf('HTTP/1.');
  let status='',ct='',bodyLen=0,id=path.basename(f);
  if(hi>=0){
    const hdrEnd=txt.indexOf('\r\n\r\n',hi);
    const headers=txt.slice(hi,hdrEnd<0?hi+2000:hdrEnd);
    status=headers.split('\r\n')[0];
    const ctm=headers.match(/Content-Type:\s*([^\r\n]+)/i); if(ctm)ct=ctm[1].trim();
    const locm=headers.match(/Location:\s*([^\r\n]+)/i);
    if(hdrEnd>=0){const body=buf.slice(hdrEnd+4);bodyLen=body.length;
      let nm=id+'__'+(url.replace(/[^a-zA-Z0-9._-]/g,'_').slice(-60)||'obj');
      fs.writeFileSync(path.join(OUT,nm),body);
    }
    console.log(`${id}\t${status}\t${ct}\tLoc=${locm?locm[1].trim():''}\tbody=${bodyLen}\t${url}`);
  } else { console.log(`${id}\t(no-http)\t\t\t\t${url}`); }
}
EOF
node "$SP/carve.js" "$C" "$OUT" 2>&1 | sort
```

**6 — Recover and unpack the malicious ZIP (object 00000011).**

```bash
SP="/c/.../scratchpad/badsignal"
O="$SP/carved"; ls -la "$O"
ZIP=$(ls "$O" | grep -i '00000011'); echo "ZIP=$ZIP"
file "$O/$ZIP" 2>/dev/null
unzip -l "$O/$ZIP" 2>&1 | head -40
```

```bash
SP="/c/.../scratchpad/badsignal"
Z="$SP/carved/00000011__insighttrackpro.live_1010_DOCS_RENRGY_Project_Brief_2026.zip"
rm -rf "$SP/zipx"; mkdir -p "$SP/zipx"
unzip -o "$Z" -d "$SP/zipx" 2>&1 | tail
find "$SP/zipx" -type f -printf "%s  %p\n"
HTA=$(find "$SP/zipx" -iname '*.html' -o -iname '*.hta' | head -1)
echo "=== HTA: $HTA ==="; md5sum "$HTA"; cat "$HTA"
```

Inside (under an obfuscated `··/` folder): the HTA, `Banner.png`, and `file.vbs`. The HTA's logic
gave Q4–Q6:
- **Q4 (anti-sandbox):** `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate /reg:64`.
- **Q5 (age threshold):** `if (days <= 8) window.close()` → runs only on machines older than 8 days.
- **Q6 (dropped files):** `%LOCALAPPDATA%\UpdateHelpers\logo.png` then `updater.vbs`; persists via a
  `schtasks` task `SystemUpdateTask` → `wscript.exe updater.vbs`.

**7 — Read and deobfuscate the VBS loader (chr() arithmetic).**

```bash
SP="/c/.../scratchpad/badsignal"
V="$SP/zipx/··/file.vbs"
wc -c "$V"; md5sum "$V"; echo "-----"; cat "$V"
```

```bash
SP="/c/.../scratchpad/badsignal"
cat > "$SP/deob.js" <<'EOF'
const fs=require('fs');
let s=fs.readFileSync(process.argv[2],'latin1');
let out='';
let re=/chr\(([^()]*CLng\("&H[0-9a-fA-F]+"\)[^()]*)\)/g;
let m,cnt=0;
while((m=re.exec(s))){
  let e=m[1];
  e=e.replace(/CLng\("&H([0-9a-fA-F]+)"\)/g, (_,h)=>parseInt(h,16).toString());
  let v; try{ v=Function('"use strict";return ('+e+')')(); }catch(err){ v=NaN; }
  out+=String.fromCharCode(Math.round(v)); cnt++;
}
console.error('chars decoded:',cnt);
fs.writeFileSync(process.argv[3],out,'latin1');
EOF
node "$SP/deob.js" "$SP/zipx/··/file.vbs" "$SP/updater_decoded.vbs"
wc -c "$SP/updater_decoded.vbs"; head -c 1500 "$SP/updater_decoded.vbs"
```

The decoded loader carves an executable out of `Banner.png`/`logo.png` after a `[DATA_START]`
marker and runs it with **`-addfile`** (Q7).

**8 — Carve the .NET backdoor out of the PNG; confirm the C2 response.**

```bash
SP="/c/.../scratchpad/badsignal"
PNG="$SP/zipx/··/Banner.png"
node -e '
const fs=require("fs");const b=fs.readFileSync(process.argv[1]);
const mk=Buffer.from("[DATA_START]");const i=b.indexOf(mk);
console.error("marker at",i,"filelen",b.length);
if(i<0)process.exit(1);
const exe=b.slice(i+mk.length);
fs.writeFileSync(process.argv[2],exe);
console.error("exe len",exe.length,"magic",exe.slice(0,2).toString());
' "$PNG" "$SP/Libraries.exe"
file "$SP/Libraries.exe" 2>/dev/null
md5sum "$SP/Libraries.exe"
echo "=== /getcalendar response ==="
xxd "$SP/carved/00000020__http___virtualtimeplanner.pro_9100_getcalendar"
echo "=== /planneractivate head ==="; head -c 400 "$SP/carved/00000023__http___virtualtimeplanner.pro_9100_planneractivate"
```

`Libraries.exe` = a 711,680-byte **.NET assembly** (`RegexFinder`); `[DATA_START]` was at offset
565579. The first C2 endpoint `/getcalendar` returned **`500`** as its success response (Q8). The
backdoor beacons to `virtualtimeplanner.pro:9100`.

**9 — Pull strings from the backdoor (ASCII + UTF-16) for endpoints/creds/process-blacklist.**

```bash
SP="/c/.../scratchpad/badsignal"
node -e '
const fs=require("fs");const b=fs.readFileSync(process.argv[1]);
let asc=[];let cur="";
for(const c of b){if(c>=0x20&&c<0x7e){cur+=String.fromCharCode(c);}else{if(cur.length>=4)asc.push(cur);cur="";}}
if(cur.length>=4)asc.push(cur);
let u=[];cur="";
for(let i=0;i+1<b.length;i+=2){const c=b[i],h=b[i+1];if(h===0&&c>=0x20&&c<0x7e){cur+=String.fromCharCode(c);}else{if(cur.length>=4)u.push(cur);cur="";}}
if(cur.length>=4)u.push(cur);
fs.writeFileSync(process.argv[2],asc.join("\n"),"latin1");
fs.writeFileSync(process.argv[3],u.join("\n"),"latin1");
console.error("ascii",asc.length,"utf16",u.length);
' "$SP/Libraries.exe" "$SP/lib_ascii.txt" "$SP/lib_utf16.txt"
grep -aiE 'getcalendar|eventmanager|planneractivate|virtualtimeplanner|insighttrack|/pixel|submit|http://|https://|\.php|calendar|activate' "$SP/lib_utf16.txt" | sort -u | head -40
```

```bash
SP="/c/.../scratchpad/badsignal"
cat "$SP/lib_utf16.txt"
grep -aiE 'taskmgr|procexp|wireshark|process|\.exe|getcalendar|eventmanager|activate|pixel|submit|user|pass|ftp|cred|login|token|blacklist|terminat|shellcode|VirtualAlloc|CreateThread' "$SP/lib_ascii.txt" | sort -u | head -60
```

The readable strings were sparse (an obfuscated assembly) — the process-blacklist and exfil creds
were **not** in plaintext; they are AES-encrypted inside the backdoor's managed resources.

**10 — Fingerprint the final payload and extract C2 timestamps.**
(From the continued forensics work on the carved objects and the access log:)

```bash
# MD5 of the /IUUi payload fetched from 20.190.31.101 (Q10):
md5sum cache_out/00_00_00000024.body        # 16daae5e6f617bae71df573797ebaf74
# first C2 contact time from the access log (Q11):
sed -n '3205,3222p' access.log               # 2026-06-11 14:09:04
```

**11 — Hunt the phishing sender email (Q1) across every source — where I hit the wall.**

```bash
OST=".../Jack Anderson/AppData/Local/Microsoft/Outlook/jack.a015@outlook.com.ost"
# ASCII + UTF-16 (null-stripped) email addresses:
grep -aoiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$OST" | sort -u | head -60
tr -d '\000' < "$OST" | grep -aoiE 'SMTP:[a-z0-9._%+-]+@[a-z0-9.-]+|[a-z0-9._%+-]{3,}@[a-z0-9.-]+\.[a-z]{2,}' | sort -u | grep -ivE 'outlook\.com|microsoft' | head -30
# sender display name offsets:
grep -aboE 'R\x00E\x00n\x00r\x00g\x00y\x00' "$OST" | head
# browser history (cleartext URLs):
grep -aoiE 'https?://[a-z0-9./?=:&_%-]{5,}' ".../Edge/User Data/Default/History" | sort -u
# Windows Search index:
tr -d '\000' < Windows.edb | grep -aoiE 'insighttrack[a-z0-9.:/?=_-]*|cutt\.ly/[a-z0-9]+|renrgy[a-z0-9.-]*|[a-z0-9._%+-]{2,}@[a-z0-9.-]{3,}\.[a-z]{2,}' | sort -u | head -40
# check which parsers are available:
for t in de4dot ilspycmd dotnet mono ildasm readpst pff pffexport; do printf "%s: " "$t"; command -v "$t" || echo no; done
```

Only the sender **display name** "REnrgy Group" was recoverable; the real SMTP address is not stored
as readable text in the OST, and no mailbox parser (`readpst`/`pypff`/XstReader) was installed.

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

## The full attack chain

1. **Phishing email** to Jack Anderson (`192.168.1.10`).
2. Click → `insighttrackpro.live:1717/open?...` → **302** → **cutt.ly** short link → downloads
   `insighttrackpro.live:1010/DOCS/RENRGY_Project_Brief_2026.zip` (cached by the proxy).
3. ZIP's **HTA** runs the anti-sandbox age check, drops `logo.png` + `updater.vbs`, persists via
   `SystemUpdateTask`.
4. **`updater.vbs`** carves **`Libraries.exe`** from `logo.png` (after `[DATA_START]`), runs it with
   `-addfile`.
5. **`Libraries.exe`** (.NET backdoor `RegexFinder`) beacons to `virtualtimeplanner.pro:9100`
   (`/getcalendar` → `500`), pulls a second stage hidden in a fake 404, which runs shellcode to
   fetch/exec `/IUUi` from `20.190.31.101`.

## Why I didn't finish the last three (tooling, not a dead end)

- **Q1:** needs an OST/PST parser (`readpst`, `pypff`, XstReader) to read the message's real `From:`.
- **Q9 & Q12:** AES-encrypted inside IntelliLock-protected managed resources; need a .NET
  deobfuscator (dnSpy, de4dot, ILSpy).

The lesson: when something "never hits disk" on the victim, the surrounding infrastructure —
proxies, logs, backups — usually still has a copy. That proxy cache is the only reason the whole
chain could be reconstructed.

## Tools used

- `unzip`, `find`, `wc`, `cat`, `head`, `sed`, `stat`, `file`, `xxd`, `md5sum` — unpacking, triage,
  fingerprinting.
- `awk` + `sed` + `grep` (ASCII and `tr -d '\000'` for UTF-16) — log filtering, host/timeline
  hunting, OST / `Windows.edb` / Edge-history searches.
- `strings` — initial cache-object URL indexing.
- **Custom Node.js scripts** — `carve.js` (split HTTP bodies out of Squid cache objects),
  `deob.js` (decode the VBS `chr()`-arithmetic loader), an inline PNG carver (extract `Libraries.exe`
  after `[DATA_START]`), and an inline ASCII/UTF-16 string extractor.
- **REA** — .NET assembly inspection.
- *Would have needed to finish:* a .NET deobfuscator (dnSpy/de4dot/ILSpy) and an OST parser
  (readpst/pypff/XstReader).
