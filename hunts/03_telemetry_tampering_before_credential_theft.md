# Hunt 03 — Does telemetry tampering precede credential theft?

**Scope:** whole corpus (420,977 events, 39 datasets)
**Outcome:** hypothesis **NOT supported by this corpus** — and the reason is instructive

---

## 1. Hypothesis

> An operator who intends to dump credentials will blind the host first. So a
> high-confidence telemetry-tampering event (audit policy weakened, event log cleared,
> WDigest downgraded, script-block logging disabled) should be followed, within the same
> hour and on the same host, by adversary access to LSASS. If that sequence exists, it is
> a far higher-confidence signal than either event alone and deserves its own correlation
> rule.

## 2. Data needed

| Side | Telemetry | Function |
|---|---|---|
| Tampering | Security 4719, Security 1102, Sysmon 13 on specific keys | `SecurityAuditPolicyChange()`, `SecurityLogCleared()`, `SysmonRegistry()` |
| Credential access | Sysmon 10 against `lsass.exe` | `SysmonProcessAccess()` |

## 3. Queries

### First attempt — and why it was useless

The naive version treated any registry key containing `EventLog` as tampering:

```kusto
let tamper = union
  ( SecurityAuditPolicyChange() | project TimeGenerated, Computer, DatasetId, What = "audit policy change" ),
  ( SecurityLogCleared()        | project TimeGenerated, Computer, DatasetId, What = "security log cleared" ),
  ( SysmonRegistry()
    | where RegistryKey has_any ("EventLog", "ScriptBlockLogging", "WDigest")
    | project TimeGenerated, Computer, DatasetId,
              What = strcat("registry: ", tostring(split(RegistryKey, @"\")[-1])) );
// ... joined to loud activity on Computer, DatasetId within 1h
```

This returned **96,976 correlated pairs on a single host/dataset**. The registry arm was
matching the enormous volume of benign ETW provider configuration writes —
`LoggerName`, `EnableProperty`, `OwningChannel`, `Guid`, and keys named after provider
GUIDs — all of which live under paths containing `EventLog`. The "signal" was Windows
configuring its own tracing at boot.

Lesson: `has_any("EventLog")` is not a tampering test, it is a substring coincidence.

### Refined attempt

Restrict tampering to keys whose modification is *itself* meaningful, and exclude the
processes that legitimately open LSASS:

```kusto
let high_confidence_tamper = union
  ( SecurityAuditPolicyChange()
    | project TimeGenerated, Computer, DatasetId, What = "audit policy changed (4719)" ),
  ( SecurityLogCleared()
    | project TimeGenerated, Computer, DatasetId, What = "security log cleared (1102)" ),
  ( SysmonRegistry()
    | where RegistryKey has_any (@"\SecurityProviders\WDigest\UseLogonCredential",
                                 @"\ScriptBlockLogging\EnableScriptBlockLogging",
                                 @"\Services\EventLog\Security\File",
                                 @"\Lsa\LMCompatibilityLevel")
    | project TimeGenerated, Computer, DatasetId,
              What = strcat("registry: ", tostring(split(RegistryKey, @"\")[-1])) );
let credential_access =
    SysmonProcessAccess()
    | where TargetProcess =~ "lsass.exe"
    | where SourceProcess !in~ ("svchost.exe","wmiprvse.exe","vboxservice.exe","csrss.exe",
                                "wininit.exe","services.exe","lsass.exe","msmpeng.exe")
    | project CredTime = TimeGenerated, Computer, DatasetId,
              Src = SourceProcess, Mask = GrantedAccess;
high_confidence_tamper
| join kind=inner (credential_access) on Computer, DatasetId
| extend DeltaSec = datetime_diff('second', CredTime, TimeGenerated)
| where DeltaSec between (0 .. 3600)        // tampering FIRST
| summarize Sequences = count(), FirstTamper = min(TimeGenerated), FirstCred = min(CredTime)
  by Computer, DatasetId
```

## 4. Findings

**The refined query returns zero rows.** No host in this corpus shows high-confidence
telemetry tampering followed by adversary LSASS access within an hour.

Investigating why, rather than loosening the query until something appeared:

**(a) Only one dataset contains both halves at all.** Dropping the time-ordering
constraint and asking simply "which datasets contain both?" returns exactly one:
`SDWIN-201018195009` (the comsvcs.dll LSASS dump), where the LSASS access is
`rundll32.exe`. And the "tampering" in that dataset is EventID 1102 — which, as recorded
in the `T1685.005` rule's false positives, is the **OTRF collection harness clearing the
Security log before the capture began**, not adversary behaviour. The sequence is an
artefact of how the data was recorded.

**(b) The WDigest dataset has no dump to correlate with.** `SDWIN-190518201922` contains
a genuine `UseLogonCredential = 1` downgrade at 20:19:45. Its only LSASS accesses are
`svchost.exe` (mask `0x1000`) at 20:19:31 and `wmiprvse.exe` (`0x1400`/`0x1000`) at
20:20:32 — both routine OS behaviour, both correctly excluded. The capture recorded the
*setup* for credential theft and stopped there.

**(c) This is structural, not bad luck.** OTRF *atomic* datasets are deliberately
single-technique recordings. A hypothesis about a sequence spanning two techniques cannot
be confirmed by data that, by construction, contains one technique per file. The only
place such a sequence could live is a compound capture, and the compound captures here
(the LSASS campaign, APT29) do not include defence-impairment steps.

## 5. Pivots

Having established the corpus cannot answer the question, the useful pivot was to ask
what the corpus *can* say about the component events:

- Audit policy changes (4719): **63 events, but all within a single dataset**
  (`SDWIN-220630130349`). So 4719 is bursty rather than widespread here — one capture of
  `auditpol` activity produced all of them. That burstiness is exactly why the shipped
  `T1685.001` rule aggregates by host and account instead of alerting per event: without
  aggregation that one dataset alone would generate 63 alerts.
- Log clears (1102): 6 events, all the harness artefact described above.
- WDigest/LSA downgrades: **7 events across 2 datasets**, and these **are** clean signal —
  which is why `T1112` ships as a standalone High-severity rule rather than waiting for a
  correlation that this data cannot provide.

## 6. Resulting detection

**No correlation rule shipped**, and that is the correct outcome rather than a failure.
Shipping a `tamper-then-dump` rule would have meant shipping a rule with no passing test,
which this repo's harness forbids (`test_experimental_detections_are_labelled` fails any
rule marked `validated` without a real-data true positive).

What the hunt did produce:

- The `T1685.001` rule's narrow key list, instead of `has_any("EventLog")`. The first
  attempt here is the direct evidence for why that matters — 96,976 false pairs from one
  careless substring.
- The explicit lab-artefact warning in `T1685.005`'s `false_positives`, which is the
  clearest example in this repo of the difference between "the test passes" and "the
  detection found an attack".
- A recorded gap: the correlation rule is designed and documented but **unvalidatable
  here**. It needs either a purpose-built compound capture or production telemetry.

## 7. Gaps

- **The hypothesis remains untested, not disproven.** Nothing here says attackers do not
  blind hosts before dumping credentials; this corpus simply cannot show it.
- **Tampering list is incomplete.** ETW patching, AMSI bypass and in-memory event-log
  thread killing (Invoke-Phant0m) leave none of the four signals searched for.
- **One-hour window is arbitrary.** It was not varied, because with zero hits in the
  ordered case there was nothing to tune against.
- **Host-scoped only.** An operator who tampers on host A and dumps on host B would not
  match a join keyed on `Computer`, and this corpus has no such pairing to test with.
- **`DatasetId` in the join is a lab affordance.** It stops events from unrelated captures
  correlating with each other. In production the join would be on host and time alone,
  which is strictly noisier than what was measured here.
