# Hunt 01 — Reconstructing a multi-stage credential-theft intrusion

**Dataset:** `LSASS_campaign_01` (OTRF compound capture, 3.25 MB, host + pcapng + Zeek)
**Date run:** against the pinned corpus in this repo
**Outcome:** hypothesis **supported**, and it produced a concrete detection improvement

---

## 1. Hypothesis

> If an operator steals credentials from LSASS on a workstation, the dump will not be
> an isolated event. It will sit inside a chain that is visible end to end in host
> telemetry: delivery, execution, command-and-control, persistence, then the dump. If
> that is true, I should be able to reconstruct the whole intrusion from one host's
> logs and pivot between host, user, process lineage and network without any network
> capture.

## 2. Data needed

| Stage | Telemetry | Normalization function |
|---|---|---|
| Delivery | Sysmon 11 (file create) | `SysmonFileEvent()` |
| Execution | Sysmon 1 (process create) | `SysmonProcessCreate()` |
| C2 | Sysmon 3 (network connect) | `SysmonNetwork()` |
| Persistence | Security 4697 / System 7045 | `SecurityServiceInstall()` |
| Credential access | Sysmon 10 (process access) | `SysmonProcessAccess()` |

## 3. Queries

Anchor on anything executing or being written outside system directories, then union
the stages onto one timeline:

```kusto
let campaign = "LSASS_campaign_01";
union
  ( SysmonFileEvent()
    | where DatasetId == campaign and Activity == "FileCreate"
    | where TargetFilename has_any (@"\Users\", @"\Temp\")
        and TargetFilename has_any (".exe", ".dll", ".dmp")
    | project TimeGenerated, Account, Stage = "FileCreate",
              Detail = strcat(Process, " wrote ", TargetFilename) ),
  ( SysmonProcessCreate()
    | where DatasetId == campaign
    | where NewProcessName has_any (@"\Users\", @"\Temp\", @"\AppData\")
    | project TimeGenerated, Account, Stage = "Process",
              Detail = strcat(ParentProcess, " -> ", Process, " : ", CommandLine) ),
  ( SysmonNetwork()
    | where DatasetId == campaign and ProcessName has_any ("winx64_payload", "rundll32")
    | project TimeGenerated, Account, Stage = "Network",
              Detail = strcat(Process, " -> ", DestinationIp, ":", tostring(DestinationPort)) ),
  ( SecurityServiceInstall()
    | where DatasetId == campaign
    | project TimeGenerated, Account, Stage = "ServiceInstall",
              Detail = strcat(ServiceName, " = ", ServiceFileName) ),
  ( SysmonProcessAccess()
    | where DatasetId == campaign and TargetProcess =~ "lsass.exe"
    | where SourceProcessName has_any (@"\Users\", @"\Temp\", @"\AppData\")
    | project TimeGenerated, Account = SourceAccount, Stage = "CredentialAccess",
              Detail = strcat(SourceProcess, " -> lsass.exe mask=", GrantedAccess,
                              " unbacked=", tostring(CallTrace has "UNKNOWN")) )
| order by TimeGenerated asc
```

## 4. Findings

The chain reconstructed cleanly on host `MKT01.pandalab.com`, over about three minutes:

| Time | Stage | What happened |
|---|---|---|
| 09:54:12 | Delivery | `msedge.exe` running as **stevie.marie** wrote `C:\Users\stevie.marie\Downloads\winx64_payload.exe` |
| 09:54:31 | Execution | `explorer.exe` launched that payload — **as `pedro.gustavo`, from stevie.marie's Downloads folder** |
| 09:54:33 | C2 | `winx64_payload.exe` connected outbound to `10.0.5.13:8080`, repeatedly |
| 09:56:15 | Persistence | the payload dropped a DLL into `C:\Users\PEDRO~1.GUS\AppData\Local\Temp\...` and registered service `rtcpef` with image path `rundll32.exe <that DLL>` |
| 09:57:25 | Credential access | `winx64_payload.exe` opened `lsass.exe` **four times**, with masks `0x1000`, `0x1400`, `0x1400`, `0x1410` — all four with an **unbacked call trace** |

Three things stood out beyond the obvious narrative.

**(a) The user pivot is the strongest single signal.** A file downloaded by one user
and executed by a *different* user from the first user's profile directory is very hard
to explain innocently. Neither the download nor the execution is remarkable alone; the
mismatch is.

**(b) The access-mask sequence is a tool fingerprint.** The payload escalated its
requested rights — `0x1000` (QUERY_LIMITED_INFORMATION), then `0x1400`, then `0x1410`
(which adds VM_READ). It was probing for the minimum access that worked.

**(c) Only the last of those four events would have fired my detection.** The shipped
`T1003.001` rule matches an allowlist of masks that includes `0x1410` but not `0x1000`
or `0x1400`. Had the tool succeeded at `0x1400`, the dump would have been invisible to it.

## 5. Pivots

Finding (c) was worth testing properly. Does keying on the **call trace** instead of the
mask do better across the whole corpus?

```kusto
let dump_masks = dynamic(["0x1010","0x1410","0x1438","0x143a","0x1f0fff","0x1fffff"]);
let benign = dynamic(["wmiprvse.exe","msmpeng.exe","svchost.exe","csrss.exe",
                      "wininit.exe","services.exe","lsass.exe","vboxservice.exe","taskmgr.exe"]);
SysmonProcessAccess()
| where TargetProcess =~ "lsass.exe"
| where SourceProcess !in~ (benign)
| extend ByMask = GrantedAccess in~ (dump_masks),
         ByCallTrace = CallTrace has "UNKNOWN"
| summarize Events = count(),
            MaskOnly = countif(ByMask and not(ByCallTrace)),
            CallTraceOnly = countif(ByCallTrace and not(ByMask)),
            Both = countif(ByMask and ByCallTrace),
            Neither = countif(not(ByMask) and not(ByCallTrace))
```

Result across the corpus:

| Events | Mask only | Call-trace only | Both | Neither |
|---:|---:|---:|---:|---:|
| 1,613 | 2 | **1,556** | 7 | 48 |

And by dataset reach: mask approach **6** datasets, call-trace approach **6** datasets,
union **7**.

So the call trace is *not* a free upgrade. It would catch 1,556 events the mask misses
but only one additional dataset, at roughly 170× the event volume — most of that being
legitimate processes whose stacks are unbacked for mundane reasons (JIT, packers,
instrumented binaries). Replacing the mask test with the call-trace test would have made
the rule much noisier for almost no coverage gain.

## 6. Resulting detection

No change to the primary rule's matching logic. Instead:

- `T1003.001` keeps the mask allowlist as its gate, and **surfaces** `UnbackedCallTrace`
  as an output column so an analyst sees it during triage. This is already in the shipped
  rule.
- The mask-allowlist limitation is now written into that rule's `known_blind_spots`
  explicitly: *"Masks outside the allowlist are missed by design; a tool requesting only
  0x0010 slips through."*
- The right production answer — which this corpus cannot validate — is a **bitwise** test
  (`binary_and(toint(GrantedAccess), 0x0410) == 0x0410`) rather than an enumerated list.
  That would have caught `0x1400` and `0x1410` but still not `0x1000`. It is recorded in
  the rule's `tuning_notes`.

The user-pivot observation (a) did not become a rule, because one compound dataset is far
too thin an evidence base for a behavioural rule about cross-user execution. It is logged
in `coverage/GAPS.md` territory as a candidate.

## 7. Gaps

- **One capture.** Every quantitative claim about mask sequences rests on a single
  intrusion. The escalation pattern may be specific to this tool.
- **No process-tree depth.** Sysmon 1 gives a parent, not a full ancestry. Reconstructing
  deeper lineage needs `ProcessGuid` joins, which this hunt did not attempt.
- **Network capture unused.** The dataset ships pcapng and Zeek logs. This hunt
  deliberately used host telemetry only, to test whether host data alone was sufficient
  (it was). Correlating the C2 to `10.0.5.13:8080` with the Zeek logs would strengthen
  attribution and is unexplored.
- **The dump's outcome is unknown.** Telemetry shows LSASS being opened, not what was
  read or whether credentials were successfully extracted.
