# Porting these detections to Microsoft Sentinel

`python tasks.py export-sentinel` writes one analytics-rule YAML per detection into
`export/sentinel/`. The detection format in this repo was modelled on Sentinel's
scheduled-rule schema specifically so that export is a transform rather than a rewrite.

## The export is UNTESTED

No rule here has been deployed to a live Sentinel workspace, and this repo makes no claim
that any of them run there. That label stays until someone actually deploys one and says
otherwise.

Two concrete reasons they will **not** work as-is:

1. **The queries call this lab's stored functions.** `SysmonProcessAccess()`,
   `SecurityLogon()` and the rest are stored functions in the lab database. They do not
   exist in a Sentinel workspace. Each maps to a Sentinel-native table or ASIM parser —
   the full table is in `docs/schema-mapping.md`.
2. **`DatasetId` is meaningless in production.** Every rule projects it so the test
   harness can attribute hits to the dataset that produced them. Delete it when porting.

Also change `let lookback = 3650d;` to something sane (`1d`–`7d`). The 10-year lookback
exists because these captures are from 2019–2023.

## Tactic names may be rejected (unverified)

ATT&CK v20.1 renamed TA0005 *Defense Evasion* to **Stealth** and added TA0112 **Defense
Impairment**. Sentinel validates `tactics:` against a fixed enum, and that enum could not
be checked when this repo was built (`learn.microsoft.com` was unreachable), so the new
names may be rejected on upload.

Where a rule uses one, the export emits the v20.1 name and adds an inline comment naming
the legacy fallback:

```yaml
tactics:
  - DefenseImpairment
  # if rejected on upload, use: DefenseEvasion (pre-v19 name)
```

The full v20.1 tactic list is also preserved in each rule's `metadata.attackTactics`, so
nothing is lost by substituting.

## What the export does produce

Faithful structural translation of: `id`, `name`, `description`, `severity`, `tactics`,
`relevantTechniques` (parent IDs) and `subTechniques`, `queryFrequency`/`queryPeriod`,
`triggerOperator`/`triggerThreshold`, `entityMappings`, `incidentConfiguration` with
entity grouping, plus `falsePositives` and `knownBlindSpots` carried across verbatim so
the operational knowledge travels with the rule.

## A realistic porting checklist

1. Replace the function call with the Sentinel table or ASIM parser from
   `docs/schema-mapping.md`.
2. Rename columns where ASIM differs (`TargetFilename` → `TargetFilePath`,
   `DestinationIp` → `DstIpAddr`, and so on).
3. Delete `DatasetId` from the final `project`.
4. Set `lookback` to match `queryFrequency`.
5. Check the rule's `tuning_notes` — several say explicitly what to change for
   production (for example the Kerberoasting rule's `min_distinct_spns` is set to 1 to be
   provable on this corpus and should be 3+ in production).
6. Confirm the data connector actually carries what the rule needs. Several rules depend
   on **Sysmon** events (8, 9, 10, 17/18, 19/20/21) that have no `SecurityEvent`
   equivalent at all; without Sysmon forwarded to the workspace those rules have no
   telemetry.
7. Deploy one rule, in a test workspace, with incident creation off, and look at what it
   returns over a week before trusting it.

## On the portal

Sentinel is moving to the Microsoft Defender portal, and the Azure-portal experience is
being retired. **This repo does not state a date**, because the authoritative page
(`learn.microsoft.com`) was unreachable when it was built and a retirement date quoted
from memory would be worse than none. Check Microsoft's current documentation for where
to create analytics rules before following any click-path you read elsewhere, including
here.

The analytics-rule YAML schema itself is stable and is pinned by reference from
<https://github.com/Azure/Azure-Sentinel> — that repository's `Detections/` directory is
the best live reference for the current field set.
