# How to add a detection

The harness enforces most of this, so the fastest route is to write the file and let
`python tasks.py test` tell you what is missing.

## 1. Find out what the data actually contains

Do not guess field names. Ask the corpus:

```kusto
// which channels and event IDs exist, and in how many datasets?
LabEventProfile() | where Events > 50 | order by Events desc
```

```kusto
// what fields does a given event type carry?
LabEvents()
| where tostring(raw.Channel) =~ "Microsoft-Windows-Sysmon/Operational"
    and toint(raw.EventID) == 1
| take 20
| project k = bag_keys(raw)
| mv-expand k to typeof(string)
| summarize by k
| order by k asc
```

## 2. Use (or add) a normalization function

Detections must query a function from `kql/functions/`, never `RawEvents` or
`LabEvents()` directly. If no function exposes what you need, add one:

- Compare `Channel` with `=~`, never `==` (the corpus contains both `Security` and
  `security`).
- Set `TimeGenerated = NormalizeTime(raw)`, never `todatetime(raw["@timestamp"])`.
- Read from `LabEvents()` so both collector schemas are handled.
- Name columns after Sentinel's `SecurityEvent` where an equivalent exists, and record
  the mapping in `docs/schema-mapping.md`.
- Project a `DatasetId` column — the harness needs it.

Apply it with `python tasks.py ingest --schema-only`.

## 3. Write the detection YAML

Put it in `detections/<tactic>/<technique>_<slug>.yml`. The directory is only a label;
the real tactics are derived from the technique IDs via STIX, so a mismatch produces a
warning from `validate-attack`, not an error.

Required fields (the loader exits on a missing one):

```
id                 UUID, unique across the repo
name               unique, human-readable
description        what the attacker is doing
severity           Informational | Low | Medium | High
status             validated | experimental
attack_version     must equal the pinned version (currently 20.1)
techniques         ATT&CK IDs only — never tactics
data_sources       which event types it reads
query              KQL block; must project DatasetId
entity_mappings    Host / Account / Process / IP / RegistryKey
false_positives    non-empty
tuning_notes       why the query is specific, and what to tune first
known_blind_spots  non-empty — how it can be evaded
references
tests              list of {dataset_id, min_hits, expect:{column: substring}}
```

Optional: `max_cross_dataset_rate` (default 0.85) to raise the ceiling for how many
undeclared datasets the rule may fire on, when the overlap is genuinely correct.

## 4. KQL quality bar

- Time filter first, then cheap string filters, then expensive work (regex, `extract`,
  large-field scans).
- `has` / `has_any` / `in~` over `contains`.
- `project` only what is needed; always emit entity columns.
- Thresholds and allowlists as named `let` variables at the top, with a comment saying
  what they do and how to tune them.
- No dataset-specific hostnames in the logic. `MORDORDC.theshire.local` belongs in the
  `tests` block, never in a `where` clause.
- Verbatim strings (`@"\CurrentVersion\Run"`) for Windows paths — a non-verbatim `"\\"`
  means two literal backslashes and will silently match nothing.
- Aggregate when a rule would otherwise return thousands of near-identical rows. The
  PowerShell rule went from 10,519 rows to 100 by summarizing per host/account/marker set.

## 5. Write tests that can fail

```yaml
tests:
  - dataset_id: SDWIN-190518202151
    min_hits: 1
    expect:
        Computer: WORKSTATION5
        SourceProcess: powershell.exe
```

`expect` values are case-insensitive substring matches against rows **from that dataset
only**. Assert on entities, not just hit counts: a row count alone passed while every
column was NULL during this repo's development, because an ingestion mapping was missing.

## 6. Run it

```bash
python tasks.py test
```

```bash
python tasks.py validate-attack
```

```bash
python tasks.py coverage
```

```bash
python tasks.py docs
```

What the harness checks:

| Test | Fails when |
|---|---|
| `test_detection_structure` | a required field is missing/empty, severity or status is invalid, `attack_version` drifts, or the query does not emit `DatasetId` |
| `test_attack_ids_are_current` | any technique ID is revoked, deprecated or absent in the pinned ATT&CK version |
| `test_declared_test_datasets_are_ingested` | *skips* (not fails) when the data simply is not loaded — so "broken rule" and "missing data" are distinguishable |
| `test_queries_execute` | the KQL is invalid |
| `test_true_positives` | fewer than `min_hits` on a declared dataset, or an `expect` entity is absent |
| `test_experimental_detections_are_labelled` | a rule is marked `validated` but no test produced its required hits |
| `test_false_positive_proxy_is_bounded` | the rule fires on more undeclared datasets than its ceiling allows |

## 7. If it cannot be validated

Mark it `status: experimental`. It will still run, still be reported in `RESULTS.md`, and
will be listed in `coverage/GAPS.md` — but it will **not** be counted as covered in
`COVERAGE.md` or coloured in the Navigator layer. That is the point: coverage is derived
from passing tests, so an unvalidated rule cannot inflate it.
