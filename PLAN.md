# PLAN.md — KQL Threat-Hunting Lab

**Status:** Phase 0 (planning). Awaiting your approval before any build work.
**Plan date:** 2026-11-06
**Pinned ATT&CK version:** Enterprise **v20.1** (released 2026-11-05) — see §3.1

---

## 0. Read this first: whose machine did I inspect?

**I could not inspect your machine.** This session runs in an ephemeral Linux cloud
container, not on your laptop. Everything in §1 describes *that container*. Your
working rule #4 said "inspect my machine" — I can't reach it from here, so the
hardware/OS questions that decide **emulator vs. Azure free cluster** are still open
on your side.

Please run this on your own machine and paste the output; it is read-only:

```bash
uname -srm; echo "---"; (docker version --format '{{.Server.Version}}' 2>&1 || echo "docker: not running"); echo "---"; python3 -V 2>&1; echo "---"; (free -g 2>/dev/null || vm_stat 2>/dev/null | head -3)
```

On Windows (PowerShell):

```powershell
$env:PROCESSOR_ARCHITECTURE; docker version --format '{{.Server.Version}}'; python --version; (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB
```

The one answer that changes the architecture: **is your CPU ARM (Apple Silicon
M-series, Snapdragon) or x86_64?** See §3.2 — the emulator is x86-only, and I verified
that directly rather than trusting the docs.

### What this container's limits mean for the build

Two things here are *not* representative of your machine, and both are recorded as
risks rather than worked around:

| Blocked here | Effect |
|---|---|
| `media.githubusercontent.com` and the Git-LFS endpoint are refused by this session's egress proxy | I cannot download `splunk/attack_data` content here (it is 100% Git LFS). It will work normally on your machine. |
| `learn.microsoft.com` and `attack.mitre.org` do not resolve | I could not read Microsoft's emulator docs or MITRE's release notes. I replaced both with primary-source checks (container registry manifests, the ATT&CK STIX bundle itself) — §3. |

---

## 1. Environment inspected (this cloud container — *not* your machine)

| Property | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS, kernel 6.18.44 |
| Arch | **x86_64** (Intel Xeon @ 2.10GHz) |
| CPU / RAM | 4 vCPU / **15 GiB** |
| Disk free | ~31 GB |
| Docker | client+server **29.9.2**; daemon not running at start, started cleanly (cgroup v1, overlayfs) |
| Python | **3.13.18** (your prompt said 3.11+; 3.13 is fine — see §3.6) |
| Tooling present | `make`, `git`, `git-lfs 3.4.1`, `curl`, `jq`, `gh`, `node 22`, `cargo` |

So this container *can* host the emulator (x86_64, 15 GiB, Docker works) and is a valid
CI-like proving ground. It is ephemeral, so nothing survives unless pushed.

---

## 2. Decisions taken (summary)

1. **Primary dataset: OTRF Security-Datasets.** Verified downloadable here, plain JSON-lines, no LFS, no binary parsing. 24 detections across 9 tactics are achievable from it alone.
2. **Secondary dataset: `splunk/attack_data`** — promoted from "optional" to a required second source, because it is the *only* verified source for 6 techniques you asked for, it is Apache-2.0, and it is actively maintained (last commit 2026-11-03).
3. **Recommend dropping `EVTX-ATTACK-SAMPLES`** on licence grounds — it has **no licence file at all** (§3.4). This also removes the `.evtx` → JSON conversion step and its pinned-parser dependency entirely.
4. **Two of your shortlisted technique IDs are revoked in v20.1** and are remapped (§3.1).
5. **Target the emulator, with the free cluster as a documented fallback**, decided by your arch answer.

---

## 3. (verify) items — resolved, with evidence

Each item records what I checked, how, and what I could *not* confirm.

### 3.1 ATT&CK version and the Defense Evasion restructure — **CONFIRMED, with a correction**

`attack.mitre.org` was unreachable, so I read MITRE's own STIX bundle instead
(`mitre-attack/attack-stix-data`, MIT-adjacent MITRE licence, © 2026).

- **Current version is v20.1, released 2026-11-05 — one day before this plan.** Your prompt pinned v20 (2026-10-13); v20.1 superseded it. Recent releases: v20.1 (2026-11-05), v20.0 (2026-10-13), v19.2 (2026-08-05), v19.1 (2026-05-12).
- I downloaded `enterprise-attack-20.1.json` (53 MB, 26,699 objects, collection version `20.1`) and enumerated tactics directly.

**Your belief was close but not exact.** Defense Evasion was **not** split into "Stealth" and "Impair Defenses". What actually happened:

- **TA0005 was *renamed*** from Defense Evasion to **Stealth** (shortname `stealth`) — same tactic ID.
- A **new tactic TA0112 "Defense Impairment"** (`defense-impairment`) was added — note the name is *Defense Impairment*, not "Impair Defenses".

Current Enterprise tactics (**15**): TA0001 Initial Access, TA0002 Execution, TA0003 Persistence, TA0004 Privilege Escalation, **TA0005 Stealth**, TA0006 Credential Access, TA0007 Discovery, TA0008 Lateral Movement, TA0009 Collection, TA0010 Exfiltration, TA0011 Command and Control, TA0040 Impact, TA0042 Resource Development, TA0043 Reconnaissance, **TA0112 Defense Impairment**.

**Revoked IDs in your shortlist** — I resolved these via `revoked-by` relationships:

| Your ID | v20.1 status | Replacement |
|---|---|---|
| `T1562.001` Disable or Modify Tools | **REVOKED** | **`T1685`** Disable or Modify Tools (now a top-level technique under TA0112) |
| `T1562` Impair Defenses | **REVOKED** | **`T1685`** |
| `T1070.001` Clear Windows Event Logs | **REVOKED** | **`T1685.005`** Clear Windows Event Logs |

The whole `T1562` tree collapsed into `T1685` under the new TA0112. The other 25 IDs in your shortlist all validated as live and non-deprecated.

> This is exactly why `validate_attack.py` must be a build gate, not a formality: two of 27 hand-picked IDs were stale after a release that landed one day before planning.

- **Bundle path pattern confirmed:** `enterprise-attack/enterprise-attack-<version>.json`, plus an unversioned `enterprise-attack.json` that always tracks the latest. I will pin the **versioned** file.
- **Not verified:** MITRE's prose release notes (host unreachable). The tactic rename and the revocations are read from the STIX data itself, which is the authoritative source `validate_attack.py` will use anyway, so this does not block anything.

### 3.2 Kusto emulator: ARM support — **CONFIRMED x86-only**

Docs were unreachable, so I queried the container registry directly:

- `mcr.microsoft.com/v2/azuredataexplorer/kustainer-linux/tags/list` → **26,107 tags**, newest dated **2026-11-05**. The image is actively published and `:latest` exists.
- The `:latest` manifest is an OCI image index listing exactly **one** real platform: **`linux/amd64`** (the only other entry is an `unknown/unknown` attestation blob).

**Conclusion: there is no arm64 image. Your "does not support ARM" belief is correct.** On Apple Silicon this can only run under emulation (slow, and Microsoft does not support it) — so if your machine is ARM, we go to the Azure free cluster.

**Resolved empirically** (docs unreachable, so I booted it in this container):

- Image size **4.45 GB**; engine version `1.0.9805.13559`, build `2026.11.05.0724` — current.
- Boots and answers `.show version` on `127.0.0.1:8080` in **~4 seconds** with `-m 4G`, confirming the ~4 GB figure is adequate.
- `ACCEPT_EULA=Y` accepted; port **8080**; plain **HTTP, no auth** — so binding to `127.0.0.1` only is mandatory, as you said.
- Persistent databases work: `.create database KqlLab persist (...)`.

### 3.3 Ingestion method — **partially verified, test-driven**

Verified by inspection of a real dataset: OTRF files are **JSON-lines** (one JSON object per line), which is Kusto's `multijson`/`json` ingestion sweet spot. I downloaded `empire_mimikatz_logonpasswords.zip` (716,749 bytes, sha256 `bb4c057b…b06fb`), unzipped to one `.json` file of **6,026 events**, and confirmed flat Windows/Sysmon fields:

```
@timestamp, Hostname, Channel, EventID, SourceName, ProcessId,
SourceImage, GrantedAccess, CallTrace, Message, AccountName, ...
```

Sample event: `Channel=Microsoft-Windows-Sysmon/Operational`, `EventID=10` (ProcessAccess), `Hostname=MORDORDC.theshire.local`. That is a genuine T1003.001 LSASS-access event — the first detection has real data behind it.

**Method 1 is PROVEN working end-to-end in this container.** The exact recipe, now fixed:

```kusto
.create table RawEvents (dataset_id:string, source_file:string, raw:dynamic)

.create-or-alter table RawEvents ingestion json mapping 'RawMap'
  '[{"column":"raw","datatype":"dynamic","Properties":{"Path":"$"}},
    {"column":"dataset_id","datatype":"string","Properties":{"ConstValue":"SDWIN-190518202151"}},
    {"column":"source_file","datatype":"string","Properties":{"ConstValue":"empire_mimikatz_logonpasswords"}}]'

.ingest into table RawEvents (@"/data/<file>.json")
  with (format="multijson", ingestionMappingReference="RawMap")
```

Result: **6,026 rows in 0.60 s**, `HasErrors=False`, with `dataset_id` and `source_file`
populated from `ConstValue` — which is exactly the "land raw events in a dynamic column
with dataset_id and source_file" design you asked for, achieved at ingest time with no
post-processing.

**Two traps found and recorded, so Phase 1 doesn't rediscover them:**

1. **A named mapping is mandatory.** Without one, `format="multijson"` maps JSON fields to columns *by name*; since no incoming field is called `raw`, you get the right row count with every column **silently null**. I hit exactly this: 6,026 rows, all empty, no error. A test that only asserts row count would have passed on garbage — so the harness asserts on *parsed entity values*, never just hit counts.
2. `.create table ... ingestion json mapping` returns `BadRequest` if the mapping already exists. Use **`.create-or-alter`** for idempotent `make ingest`.

Verified event profile of that one dataset — note it is multi-source, not just Sysmon:

| Channel | EventID | Events |
|---|---|---|
| Windows PowerShell | 800 | 2,940 |
| Microsoft-Windows-PowerShell/Operational | 4103 | 1,695 |
| Microsoft-Windows-Sysmon/Operational | 10 | 272 |
| Security | 5156 / 5158 | 211 / 195 |

**Normalization layer and a real detection also proven.** A stored function
(`.create-or-alter function SysmonProcessAccess()`) projecting Sentinel-style columns
(`TimeGenerated`, `Computer`, `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`)
works, and the T1003.001 detection querying **only that function** returns a true positive:

```
Computer                      SourceImage                                      Masks      Hits
WORKSTATION5.theshire.local   C:\windows\System32\WindowsPowerShell\v1.0\...   ['0x1010']  1
```

That is Mimikatz `LogonPasswords` opening LSASS with `0x1010` — detection #13 has a
passing real-data test before Phase 2 even starts.

Remaining fallbacks, if a later dataset needs them:
2. `.ingest inline into table T <| {...}` — **verified working** (1 row).
3. For a free cluster: `azure-kusto-ingest` queued ingestion, or blob/one-click for these small files.

`azure-kusto-ingest` is therefore listed as a **conditional** dependency, matching your instruction to add it only if a target needs it.

### 3.4 Dataset availability, licence, size, maintenance — **ALL CHECKED; two problems found**

| Dataset | Licence | Size | Last commit | Verdict |
|---|---|---|---|---|
| **OTRF/Security-Datasets** | ⚠️ **Inconsistent** — `LICENSE` file is **MIT** ("Copyright (c) 2021 Open Threat Research Forge"); `README.md` says "**License: GPL-3.0**" | atomic/windows **124.5 MB** / 165 files; compound/apt29 **126.9 MB** / 124; compound/windows **40.4 MB** / 54 | **2023-09-20** — effectively frozen, ~3 years stale | **USE as primary** (download-only, never redistribute) |
| **splunk/attack_data** | ✅ **Apache-2.0** (clean) | Large; **100% Git LFS** | **2026-11-03** — actively maintained | **USE as secondary** |
| **sbousseaden/EVTX-ATTACK-SAMPLES** | ❌ **No licence of any kind** (`LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING`, `license` all 404) | 59.9 MB / 316 files (278 `.evtx`) | — | **RECOMMEND DROP** — see below |
| **mitre-attack/attack-stix-data** | ✅ MITRE ATT&CK licence — royalty-free use incl. commercial, with required attribution | 53 MB (v20.1 bundle) | current | **USE**; attribution string goes in README |

**Your two suspicions about OTRF were both right.** The licence *is* inconsistent (MIT file vs. GPL-3.0 README — I verified both texts), and it *is* lightly maintained (last commit 2023-09-20). Consequences:

- The licence ambiguity is survivable **only because we never redistribute the data.** `make data` downloads at build time; `data/` is gitignored; `MANIFEST.json` records pinned commit + SHA-256 and nothing else. I will state the MIT/GPL discrepancy plainly in `README.md` and `docs/datasets.md` rather than pick the answer that suits us.
- Because the repo froze in 2023, its `attack_mappings` predate v20.1 by ~7 releases. **Confirmed stale in practice:** the metadata maps `T1222.001` to tactic `TA0005`, which in v20.1 is *Stealth*, while `T1222.001` now lives under *Defense Impairment* (TA0112). Every ID gets re-derived from the v20.1 STIX bundle; dataset metadata is treated as a hint for *which file to use*, never as the tactic source. This is already how you specified it ("Tactics are NOT hand-typed") — the check confirms it is load-bearing.

**On EVTX-ATTACK-SAMPLES:** no licence file means no grant of rights — by default all rights are reserved, so even non-redistributing use is legally murkier than the other two. It would also force a binary-parser dependency. Since `splunk/attack_data` (Apache-2.0) covers every gap it would have filled, I recommend dropping it. **This is your call** — say the word and I will include it with a prominent licence caveat.

**Total download for the detections below: well under 300 MB.** Largest single files: `purplesharp_ad_playbook_I` 37.8 MB, `empire_wmi_local_event_subscriptions_elevated_user` 5.8 MB.

### 3.5 Sentinel export / portal retirement — **NOT VERIFIED**

Your note that the Azure portal experience retires March 2027 and Sentinel is moving to the Defender portal could not be checked: `learn.microsoft.com` is unreachable from this session. `Azure/Azure-Sentinel` on GitHub is reachable, so I can pin the **analytics-rule YAML schema** from the repo itself. I will not write portal click-paths or retirement dates I cannot verify. Phase 5 export ships **labelled untested** unless you deploy it and confirm.

### 3.6 Stack versions — **VERIFIED (current on PyPI today)**

`azure-kusto-data` **6.0.4** (py≥3.9) · `azure-kusto-ingest` **6.0.4** · `mitreattack-python` **6.4.0** (py≥3.11,<4) · `pytest` **9.2.0** · `pyyaml` **6.0.3**.

All support Python 3.13. I will pin exact versions and target **3.11+**, testing on 3.13.
Note: `mitreattack-python` is convenient but heavy; since `validate_attack.py` only needs
technique/tactic/revocation lookups, I plan to **parse the pinned STIX JSON directly**
(stdlib only) — fewer moving parts, fully offline after `make data`, and it is the exact
code path I already used to produce §3.1. `mitreattack-python` stays an optional extra.

### 3.7 Azure free cluster — **NOT VERIFIED**

`dataexplorer.azure.com` is unreachable here, so I could not read the current quota
table, inactivity-deletion rule, or terms. **If your machine is ARM and we need this
fallback, this becomes a blocking question for you** (working rule #6): creating a
cluster needs your browser and account. I will write the step-by-step guide and stop.
Our footprint (<300 MB, a handful of small tables) is very likely inside any free tier,
but I will not assert a number I have not read.

---

## 4. Architecture

```
kql-threat-hunting-lab/
├── README.md  PLAN.md  RESULTS.md  Makefile  .env.example  .gitignore
├── data/                  # gitignored; MANIFEST.json committed
├── kql/
│   ├── schema/            # table DDL: RawEvents (dynamic) + derived
│   └── functions/         # normalization: SecurityEventN, SysmonProcessN, ...
├── detections/<tactic>/<id>_<slug>.yml
├── hunts/                 # 3 markdown write-ups
├── tests/                 # pytest harness
├── tools/                 # ingest.py validate_attack.py make_layer.py
│                          # export_sentinel.py make_docs.py
├── coverage/              # GENERATED: attack-layer.json COVERAGE.md GAPS.md
└── docs/                  # HOW_IT_WORKS.md schema-mapping.md datasets.md setup-*.md
```

**Data flow:** raw JSON-lines → `RawEvents(ingest_time, dataset_id, source_file, raw:dynamic)`
→ KQL stored functions project stable typed columns → detections query **only functions**,
never `RawEvents`. Swapping dataset or target changes the function layer, not 25 detections.

**Normalization:** column names modelled on Sentinel's `SecurityEvent` and ASIM
(`Dvc*`, `Act*`, `Target*`) for Sysmon. `docs/schema-mapping.md` maps lab → Sentinel-native
tables and parsers, so each detection has a documented production translation.

**Target abstraction:** `KUSTO_URI`, `KUSTO_DB`, `KUSTO_AUTH_MODE` from `.env`
(gitignored; `.env.example` committed). Emulator = no auth, bound to **`127.0.0.1` only**
per your security note. Same code path for both targets.

**Untrusted-data handling (working rule #1):** dataset text (command lines, `adversary_view`
blocks, usernames) is treated strictly as data. I confirmed OTRF metadata embeds raw C2
console transcripts, so: no `eval`, no shell interpolation of event content, parameterised
KQL only, and no instruction-shaped dataset text is ever acted on. Logs only — no malware,
binaries or attack tools downloaded, built or run.

---

## 5. Detection shortlist — every entry backed by a verified dataset

I cross-referenced all 104 OTRF metadata files against the v20.1 bundle: **56 distinct
technique IDs** are present in Windows datasets. IDs below are **v20.1-validated**;
tactics are **derived from STIX**, not typed. "n" = OTRF datasets available.

### Covered by OTRF (verified present) — 24 detections, 9 tactics

| # | Technique (v20.1) | Tactic | n | Example dataset |
|---|---|---|---|---|
| 1 | T1059.001 PowerShell | Execution | 1 | PowerShell HTTP Listener |
| 2 | T1047 Windows Management Instrumentation | Execution | 6 | Empire Invoke Execute MSBuild |
| 3 | T1059.005 Visual Basic | Execution | 1 | Empire VBS Execution |
| 4 | T1053.005 Scheduled Task | Execution/Persistence/PrivEsc | 4 | Empire Userland Scheduled Tasks |
| 5 | T1543.003 Windows Service | Persistence/PrivEsc | 1 | Service Modification Fax |
| 6 | T1547.001 Registry Run Keys / Startup Folder | Persistence/PrivEsc | 2 | Empire Userland Registry Run Keys |
| 7 | T1546.003 WMI Event Subscription | Persistence/PrivEsc | 1 | Empire Elevated WMI Eventing |
| 8 | T1574.001 DLL Hijacking | Persistence/PrivEsc | 1 | IKEEXT Remote Service DLL Hijack |
| 9 | T1548.002 Bypass User Account Control | PrivEsc | 1 | Invoke BypassUAC FodHelper |
| 10 | T1055 Process Injection | **Stealth**/PrivEsc | 3 | Mavinject Process DLL Injection |
| 11 | T1055.002 Portable Executable Injection | **Stealth**/PrivEsc | 1 | PurpleSharp PE Injection CreateRemoteThread |
| 12 | T1134.001 Token Impersonation/Theft | PrivEsc/**Stealth** | 1 | APT Simulator Cobalt Strike |
| 13 | T1003.001 LSASS Memory | Credential Access | 5 | Empire Mimikatz LogonPasswords ✅*verified* |
| 14 | T1003.002 Security Account Manager | Credential Access | 4 | Empire Mimikatz SAM Extract Hashes |
| 15 | T1003.003 NTDS | Credential Access | 5 | cmd dumping NTDS.dit (ntdsutil) |
| 16 | T1003.006 DCSync | Credential Access | 2 | Empire DCSync (DRSUAPI DsGetNCChanges) |
| 17 | T1558.003 Kerberoasting | Credential Access | 1 | PurpleSharp AD Playbook I |
| 18 | T1112 Modify Registry (WDigest downgrade) | **Defense Impairment** | 3 | Empire WDigest Downgrade |
| 19 | T1087.001/.002 Account Discovery | Discovery | 2 | Empire Net Local Users / Domain Users |
| 20 | T1069.001/.002 Permission Groups Discovery | Discovery | 4 | Empire Shell Net Domain Admins |
| 21 | T1021.002 SMB/Windows Admin Shares (PsExec) | Lateral Movement | 7 | Empire Invoke SMBExec |
| 22 | T1021.006 Windows Remote Management | Lateral Movement | 3 | Empire Invoke PSRemoting |
| 23 | T1550.002 Pass the Hash | Lateral Movement | 1 | Empire Over-Pass-The-Hash |
| 24 | T1685.001 Disable or Modify Windows Event Log | **Defense Impairment** | **6** | Disabling Windows Event Logging via Audit Policy |

Tactics covered: Execution, Persistence, Privilege Escalation, Stealth, Credential Access,
Discovery, Lateral Movement, Defense Impairment, Collection = **9** (you asked ≥8).
Your ≥2-each minimum is met **from OTRF alone**: Execution 4, Persistence 4,
Credential Access 5, Lateral Movement 3. ✅

### Requires `splunk/attack_data` — the 6 techniques OTRF cannot validate

OTRF has **no** data for these, so they cannot be honestly marked covered without it:

| # | Technique (v20.1) | Tactic | Verified source path |
|---|---|---|---|
| 25 | **T1685.005** Clear Windows Event Logs *(was T1070.001)* | Defense Impairment | `T1070.001/` (17 files) |
| 26 | **T1490** Inhibit System Recovery | Impact | `T1490/shadowcopy_del/` + `windows-security_bcdedit_wbadmin.log` |
| 27 | T1218.011 Rundll32 | Stealth | `T1218.011/` |
| 28 | T1018 Remote System Discovery | Discovery | `T1018/` (19 files) |
| 29 | T1082 System Information Discovery | Discovery | `T1082/` (17 files) |
| 30 | T1059.001 encoded/obfuscated PowerShell *(strong variant)* | Execution | `T1059.001/` (101 files) |

Adding these reaches **30 candidates for a target of ~25**, covering **10 tactics**.
`attack_data` already ships a `T1685/` directory — it tracks current ATT&CK, unlike OTRF.

### Dropped, with reasons

- **T1569.002 Service Execution** — no dedicated dataset; it would overlap the PsExec detections (#21). Better covered honestly as part of T1021.002 than as a thin separate rule.
- **T1218 certutil** — no verified dataset in either source. Not written rather than untested.
- **T1003.004 LSA Secrets** (2 datasets) and **T1021.003 DCOM** (4) are available spares if any above fails its test.

### Multi-stage hunt dataset — verified

`datasets/compound/LSASS_campaign_0{1..7}` are genuine multi-stage chains. e.g.
`LSASS_campaign_01` (5.30 MB, 3 files: host JSON + pcapng + Zeek logs) maps to
**T1003.001, T1033, T1055.002, T1057, T1082, T1134.001, T1204.002** — delivery →
discovery → injection → credential theft, with host *and* network telemetry. That
supports your required host → user → parent/child process → network timeline.

`compound/apt29` (126.9 MB, day1/day2 + pcaps) is the richer option; largest single file
44.5 MB. Feasible but I will start with an LSASS campaign and only add APT29 if ingestion
headroom allows. `Log4Shell` (0.11 MB) is a cheap bonus.

### KQL quality bar (applies to every detection)

Time filter first, then cheap string filters; `has` / `has_any` / `in~` over `contains`;
`project` only needed columns; allowlists and thresholds as commented `let` variables at
the top; entity columns (host, account, process, command line, time) always emitted; no
dataset-specific hostnames in detection logic (`MORDORDC.theshire.local` appears in test
expectations only, never in a query). Deliberate operator mix across the set: `summarize`
with `bin`, `make_set`, `arg_max`, joins with explicit `kind=`, and one
`series_decompose_anomalies` or rarity hunt where the data genuinely supports it.

---

## 6. Risks

| # | Risk | Likelihood | Mitigation / stop-point |
|---|---|---|---|
| 1 | **Your machine is ARM** → emulator impossible | Unknown — blocking | Switch to free cluster; I write the guide and **stop for you** (rule #6) |
| 2 | ~~Emulator rejects file ingestion from a mount~~ | **RETIRED** | Proven working end-to-end in this container (§3.3) |
| 3 | OTRF licence ambiguity (MIT vs GPL-3.0) | **Confirmed** | Never redistribute; download-only; disclose discrepancy in README |
| 4 | EVTX-ATTACK-SAMPLES has no licence | **Confirmed** | Recommend drop; `attack_data` covers the gaps — **your decision** |
| 5 | ATT&CK v20.1 lands mid-build / more revocations | **Already happened once** | Pin versioned STIX file; `make validate-attack` is a hard CI gate |
| 6 | Git LFS blocked in CI (as it is in this container) | Medium | OTRF-only CI job (no LFS) + `attack_data` job that skips cleanly if LFS is unavailable |
| 7 | OTRF frozen since 2023 | **Confirmed** | Pin commit + SHA-256; data doesn't rot; all mappings re-derived from v20.1 |
| 8 | Free-cluster quota/terms unverified | Medium | Only if fallback is needed; I read the terms and report before ingesting |
| 9 | Detection passes on lab data but is useless in production | High (inherent) | Cross-dataset FP proxy runs + `known_blind_spots` per rule + explicit README honesty statement |
| 10 | This container is ephemeral | Certain | Commit and push after every phase |

---

## 7. Phases and acceptance criteria

**Phase 0 — this document. → STOP for your approval.** ← *we are here*

**Phase 1 — Environment and data.** Boot emulator bound to `127.0.0.1` (recipe proven,
§3.3); `make data` downloads pinned OTRF
commits, verifies SHA-256, writes `data/MANIFEST.json`; ingest one dataset; a query
returns rows.
*Acceptance:* on a fresh clone, `make up && make data && make ingest` works.

**Phase 2 — Normalization + 5 detections + harness.** Function layer; 5 detections
(T1003.001, T1047, T1547.001, T1021.002, T1685.001 — the best-evidenced one per tactic);
pytest harness asserting min-hits and entities.
*Acceptance:* `make test` passes; `RESULTS.md` generated.

**Phase 3 — Full set + ATT&CK + coverage.** ~25 detections; `validate_attack.py` as a
hard gate; Navigator layer coloured only by *passing* tests, scored by passing-detection
count; generated `COVERAGE.md` and `GAPS.md`.
*Acceptance:* zero invalid/revoked IDs; coverage pages generated, never hand-written.

**Phase 4 — Hunts + README.** 3 hypothesis-driven hunts (one multi-stage on an LSASS
campaign); Mermaid diagram; results/coverage summary; how to add a detection;
limitations; next steps.

**Phase 5 — Optional.** Sentinel export against the schema pinned from
`Azure/Azure-Sentinel`, **labelled untested** until you deploy it; GitHub Actions
(lint + tests, data downloaded not committed); free-cluster guide.

After every phase: run all tests, commit, and report in ≤5 lines what works, what
doesn't, and what I assumed.

---

## 8. What I need from you to start

1. **Your machine's specs** — the one-liner in §0. Decides emulator vs. free cluster. **Blocking.**
2. **EVTX-ATTACK-SAMPLES: drop or keep?** My recommendation: drop (no licence; gaps covered by Apache-2.0 `attack_data`).
3. **`splunk/attack_data` as a required second source — OK?** Needs Git LFS on your machine. Without it, 6 techniques including Clear Event Logs and Inhibit System Recovery cannot be honestly validated, and the set is ~24 detections over 9 tactics.
4. **Repo name / GitHub org**, and confirm **MIT** for your own code (data stays un-redistributed under its own licences).

---

## Appendix — verification log

| Claim | Method | Result |
|---|---|---|
| ATT&CK latest = v20.1 | `attack-stix-data/index.md` + bundle `x-mitre-collection` | v20.1, 2026-11-05 |
| Tactic restructure | Enumerated `x-mitre-tactic` in v20.1 bundle | TA0005 renamed *Stealth*; TA0112 *Defense Impairment* added; 15 tactics |
| T1070.001 / T1562.001 revoked | STIX `revoked-by` relationships | → T1685.005 / T1685 |
| 25 other shortlist IDs | STIX lookup, revoked+deprecated flags | all live |
| Emulator is x86-only | OCI image index for `kustainer-linux:latest` | `linux/amd64` only; no arm64 |
| Emulator image maintained | Registry tag list | 26,107 tags; newest 2026-11-05 |
| OTRF licence inconsistent | Fetched `LICENSE` and `README.md` | MIT file vs "License: GPL-3.0" README |
| OTRF lightly maintained | `git log -1` | 2023-09-20 |
| OTRF mappings stale | Compared metadata `TA0005` vs v20.1 | T1222.001 now TA0112, metadata says TA0005 |
| OTRF technique coverage | Parsed 104 metadata YAMLs vs v20.1 | 56 technique IDs, Windows |
| OTRF sizes | `git ls-tree -r -l` | atomic/windows 124.5 MB; apt29 126.9 MB; compound/windows 40.4 MB |
| OTRF data usable | Downloaded + unzipped one dataset | 6,026 JSON-lines events; Sysmon EID 10 present |
| EVTX repo unlicensed | Probed 5 licence filenames | all 404 |
| attack_data licence/freshness | Fetched `LICENSE`; `git log -1` | Apache-2.0; 2026-11-03 |
| attack_data uses LFS | `.gitattributes` + 129-byte blobs | all datasets LFS; raw URL serves pointer only |
| attack_data fills gaps | `git ls-tree` on technique dirs | T1490, T1070.001, T1018, T1082, T1059.001, T1685 present |
| PyPI versions | PyPI JSON API | kusto-data 6.0.4, mitreattack-python 6.4.0, pytest 9.2.0 |
| Emulator boots & ingests | Booted image, bind-mounted dataset, ran `.ingest` | 6,026 rows in 0.60 s, `HasErrors=False` |
| Mapping required | Ingested without a mapping | 6,026 rows, all columns **silently null** |
| Normalization + detection | Stored function + T1003.001 query | True positive: powershell.exe → lsass.exe, `0x1010` |
| Emulator engine version | `.show version` | `1.0.9805.13559`, build 2026.11.05 |
| Container specs | `lscpu`, `free`, `docker`, `python3` | x86_64, 4 vCPU, 15 GiB, Docker 29.9.2, Py 3.13.18 |

**Still unresolved (hosts unreachable from this session):** MITRE's prose release notes;
the Sentinel/Defender portal retirement date; Azure free-cluster quota, inactivity-deletion
rule and terms. None blocks Phases 1–4 on an x86 machine. Everything else in the original
(verify) list is now settled above — from primary sources or by direct experiment.
