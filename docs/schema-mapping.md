# Schema mapping: lab → Microsoft Sentinel

Detections in this repo query **stored KQL functions**, never the raw table. That
indirection is the whole point: it keeps column names stable, it absorbs the fact that
the source datasets are not uniform, and it gives every rule a documented production
equivalent.

This page is what you would use to port a rule out of the lab.

## Why the normalization layer exists

Three concrete problems in the source data, all solved here rather than in 24 rules:

**1. Two different collectors, two different JSON schemas.** 38 of 39 datasets are
NXLog-style — flat, PascalCase at the top level. One (`SDWIN-190518201922`) is
winlogbeat-style — nested, snake_case:

```jsonc
// NXLog shape (38 datasets)
{ "Channel": "...", "EventID": 13, "Hostname": "...", "TargetObject": "..." }

// winlogbeat shape (SDWIN-190518201922)
{ "log_name": "...", "event_id": 13, "computer_name": "...",
  "event_data": { "TargetObject": "..." } }
```

Before `LabEvents()` unified them, that dataset's 2,710 events had a NULL `Channel` and
every function silently ignored it — including the only dataset in the corpus containing
the WDigest credential downgrade.

**2. Inconsistent timestamp fields.** Most events carry `@timestamp`. Dataset
`SDWIN-201018195009` carries none and only populates `TimeCreated`. `NormalizeTime()`
resolves `@timestamp` → `UtcTime` → `TimeCreated` → `EventTime`. Without it, any
detection with a `where TimeGenerated > ago(...)` filter dropped that whole dataset — and
it is a real LSASS dump.

**3. Case-inconsistent channel names.** Both `Security` and `security` appear. Every
function compares `Channel` with `=~` (case-insensitive). An `==` comparison silently
loses roughly half the Security-channel events.

## Helper functions

| Function | Purpose |
|---|---|
| `LabEvents()` | All raw events with both collector schemas unified to one flat shape; adds a `Collector` column (`nxlog` / `winlogbeat`) |
| `NormalizeTime(r)` | Scalar: resolves an event timestamp across the four possible fields |
| `LabDatasets()` | One row per ingested dataset with event counts and time bounds |
| `LabEventProfile()` | Channel / EventID profile across the corpus |

## Function → Sentinel mapping

`Computer`, `Account`, `TimeGenerated` and the entity columns are named to match
Sentinel's `SecurityEvent` table so that most rules need only a table substitution.

| Lab function | Source | Sentinel equivalent | Notes on porting |
|---|---|---|---|
| `SysmonProcessCreate()` | Sysmon 1 | `SecurityEvent` where `EventID == 4688`, or `Event`/`WindowsEvent` with the Sysmon parser, or ASIM `imProcessCreate` | Sysmon 1 has richer fields (`Hashes`, `IntegrityLevel`, `OriginalFileName`) than 4688. Prefer ASIM `imProcessCreate` for portability. |
| `SecurityProcessCreate()` | Security 4688 | `SecurityEvent` where `EventID == 4688` | Near-direct: column names already match (`NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`). |
| `SysmonProcessAccess()` | Sysmon 10 | `Event` / `WindowsEvent` with Sysmon parser | **No `SecurityEvent` equivalent.** Needs Sysmon forwarded to the workspace. No ASIM schema covers cross-process handle access. |
| `SysmonRemoteThread()` | Sysmon 8 | `Event` / `WindowsEvent` | Same: Sysmon-only. |
| `SysmonRawAccessRead()` | Sysmon 9 | `Event` / `WindowsEvent` | Same. |
| `SysmonRegistry()` | Sysmon 12/13/14 | `Event` / `WindowsEvent`, or ASIM `imRegistry` | ASIM `imRegistry` uses `RegistryKey`/`RegistryValueData`, matching this layer's names. |
| `SysmonFileEvent()` | Sysmon 11/23 | ASIM `imFileEvent` | ASIM uses `TargetFilePath`; this layer uses `TargetFilename` (Sysmon's own name). Rename on port. |
| `SysmonImageLoad()` | Sysmon 7 | `Event` / `WindowsEvent` | Sysmon-only; very high volume, often not collected. |
| `SysmonNetwork()` | Sysmon 3 | ASIM `imNetworkSession`, or `VMConnection` | ASIM uses `DstIpAddr`/`DstPortNumber`; this layer uses `DestinationIp`/`DestinationPort`. |
| `SysmonPipe()` | Sysmon 17/18 | `Event` / `WindowsEvent` | Sysmon-only, no ASIM schema. |
| `SysmonWmiEvent()` | Sysmon 19/20/21 | `Event` / `WindowsEvent` | Sysmon-only. |
| `SecurityLogon()` | Security 4624/4625 | `SecurityEvent`, or ASIM `imAuthentication` | Column names already match `SecurityEvent` (`LogonType`, `TargetUserName`, `IpAddress`). |
| `SecurityExplicitCredentials()` | Security 4648 | `SecurityEvent` where `EventID == 4648` | Direct. |
| `SecurityKerberos()` | Security 4768/4769 | `SecurityEvent` | Direct; `TicketEncryptionType` is already the Sentinel name. |
| `SecurityServiceInstall()` | Security 4697 + System 7045 | `SecurityEvent` (4697) + `Event` (7045) | This layer unions both. In Sentinel you must union two tables, since 7045 is not in `SecurityEvent`. |
| `SecurityScheduledTask()` | Security 4698–4702 | `SecurityEvent` | Direct. |
| `SecurityObjectAccess()` | Security 4661/4662/4674 | `SecurityEvent` | Direct; `Properties`, `AccessMask`, `ObjectType` keep their names. |
| `SecurityShareAccess()` | Security 5140/5145 | `SecurityEvent` | Direct. |
| `SecurityAuditPolicyChange()` | Security 4719 | `SecurityEvent` | Direct. |
| `SecurityLogCleared()` | Security 1102 | `SecurityEvent` where `EventID == 1102` | **Account is parsed out of `Message`** here because 1102 carries no structured subject fields. Sentinel's `SecurityEvent` has the same limitation. |
| `SecurityGroupEnumeration()` | Security 4798/4799 | `SecurityEvent` | Direct. |
| `PowerShellScriptBlock()` | PowerShell 4104 | `Event` where `Source == "Microsoft-Windows-PowerShell"` | `ScriptBlockText` must be extracted from `EventData` in Sentinel. |
| `PowerShellModule()` | PowerShell 4103 | `Event` | Same. |
| `PowerShellClassic()` | PowerShell 800 | `Event` | This layer parses `HostApplication` and `CommandLine` out of `Message` — unavoidable, 800 is unstructured. |

## Two things to strip when porting

**`DatasetId`.** Every detection projects it. It is lab provenance that the test harness
uses to attribute hits to the dataset that produced them. It has no production meaning —
delete it.

**The `lookback` value.** Every rule opens with `let lookback = 3650d;` because these
captures are historical (2019–2023). In production that becomes `1d`–`7d`, matched to
your rule's `queryFrequency`.

## Column naming conventions used here

- **Sentinel `SecurityEvent` names win** where one exists: `Computer`, `Account`,
  `TimeGenerated`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`,
  `LogonType`, `IpAddress`, `ServiceName`, `TaskName`.
- **ASIM-style names** for Sysmon-only concepts that have no `SecurityEvent` equivalent:
  `SourceProcessName`/`TargetProcessName`, `RegistryKey`/`RegistryValueData`,
  `DestinationIp`/`DestinationPort`.
- **Sysmon's own field names** are kept where neither applies (`GrantedAccess`,
  `CallTrace`, `PipeName`, `ImageLoaded`, `StartModule`), because renaming them would make
  the rules harder to compare against public Sysmon research.
- A short `Process` column (just the image name) sits alongside every full
  `*ProcessName` path, so that `Process =~ "reg.exe"` is cheap and readable.
