# GAPS.md

**Generated** by `make coverage` -- do not edit.
Last generated 2026-11-15 17:20:13Z.

Techniques that the ingested datasets claim to contain but which no passing detection covers. This is the honest to-do list.

> Upstream dataset metadata was authored against a much older ATT&CK release (OTRF's last commit is 2023-09-20), so some claimed IDs are revoked or deprecated in v20.1. Those are listed separately rather than silently dropped.

## Uncovered techniques present in the data (5)

| Technique | Name | Datasets that contain it |
|---|---|---|
| [T1033](https://attack.mitre.org/techniques/T1033) | System Owner/User Discovery | LSASS_campaign_01 |
| [T1057](https://attack.mitre.org/techniques/T1057) | Process Discovery | LSASS_campaign_01 |
| [T1134.001](https://attack.mitre.org/techniques/T1134/001) | Token Impersonation/Theft | LSASS_campaign_01, SDWIN-210611210814 |
| [T1134.002](https://attack.mitre.org/techniques/T1134/002) | Create Process with Token | SDWIN-210611210814 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002) | Malicious File | LSASS_campaign_01 |

## Claimed by dataset metadata but stale in v20.1 (1)

These need no detection; they are listed so the mismatch between the datasets' ATT&CK vintage and the pinned version stays visible.

| Claimed ID | Status | Datasets |
|---|---|---|
| T1562.002 | REVOKED -> T1685.001 | SDWIN-220630130349, SDWIN-220705170038, SDWIN-220708104215 |

## Detections without a passing test (0)

None: every detection in this repo has at least one passing real-data test.

