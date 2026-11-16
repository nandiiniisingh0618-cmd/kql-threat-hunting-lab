# COVERAGE.md

**Generated** by `make coverage` from `RESULTS.md` -- do not edit.
Last generated 2026-11-16 09:21:39Z.

- ATT&CK Enterprise **v20.1**
- Detections: **24**, passing a real-data test: **24**
- Techniques covered: **38**
- Tactics touched: **8** of 15 Enterprise tactics

> A technique appears here ONLY if a detection claiming it has a test that produced its required hits on real events from the pinned datasets. Nothing on this page is hand-maintained.

> **Scope warning.** These are public *attack-simulation* datasets, not production telemetry. "Covered" means the query fires on the recorded attack; it does not mean the rule would survive a real estate's noise, nor that it catches variants absent from these captures. Read each detection's `known_blind_spots`.

## Coverage by tactic

### Credential Access (TA0006)

| Technique | Name | Passing detections |
|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001) | LSASS Memory | LSASS process handle opened with credential-dump access mask |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002) | Security Account Manager | SAM or SYSTEM registry hive exported to disk |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003) | NTDS | NTDS.dit extraction via ntdsutil, shadow copy or direct copy |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006) | DCSync | DCSync - directory replication rights used by a non-machine account |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003) | Password Spraying | Password spraying - failed logons across many distinct accounts |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003) | Kerberoasting | Kerberoasting - RC4 service tickets requested for multiple SPNs |

### Defense Impairment (TA0112)

| Technique | Name | Passing detections |
|---|---|---|
| [T1112](https://attack.mitre.org/techniques/T1112) | Modify Registry | Credential-protection registry downgrade (WDigest, LSA PPL or NTLM) |
| [T1685.001](https://attack.mitre.org/techniques/T1685/001) | Disable or Modify Windows Event Log | Windows event logging disabled or audit policy weakened |
| [T1685.005](https://attack.mitre.org/techniques/T1685/005) | Clear Windows Event Logs | Windows Security audit log cleared |

### Execution (TA0002)

| Technique | Name | Passing detections |
|---|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047) | Windows Management Instrumentation | Process spawned by WMI provider host |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005) | Scheduled Task | Scheduled task created or modified with a suspicious action |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001) | PowerShell | Obfuscated or encoded PowerShell execution |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005) | Visual Basic | Windows Script Host execution of a script from a user-writable path |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002) | Service Execution | PsExec-style remote execution - suspicious service correlated with named pipe; Service installed with an interpreter, temp path or named-pipe image path |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001) | DLL | Unsigned or user-path DLL loaded by a service or system binary |

### Persistence (TA0003)

| Technique | Name | Passing detections |
|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005) | Scheduled Task | Scheduled task created or modified with a suspicious action |
| [T1112](https://attack.mitre.org/techniques/T1112) | Modify Registry | Credential-protection registry downgrade (WDigest, LSA PPL or NTLM) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003) | Windows Service | Service installed with an interpreter, temp path or named-pipe image path |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003) | Windows Management Instrumentation Event Subscription | WMI permanent event subscription created |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001) | Registry Run Keys / Startup Folder | Autorun registry Run key written by a non-installer process |

### Privilege Escalation (TA0004)

| Technique | Name | Passing detections |
|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005) | Scheduled Task | Scheduled task created or modified with a suspicious action |
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | Remote thread created in another process |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002) | Portable Executable Injection | Remote thread created in another process |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003) | Windows Service | Service installed with an interpreter, temp path or named-pipe image path |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003) | Windows Management Instrumentation Event Subscription | WMI permanent event subscription created |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001) | Registry Run Keys / Startup Folder | Autorun registry Run key written by a non-installer process |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002) | Bypass User Account Control | UAC bypass via hijacked shell-open registry handler |

### Lateral Movement (TA0008)

| Technique | Name | Passing detections |
|---|---|---|
| [T1021.002](https://attack.mitre.org/techniques/T1021/002) | SMB/Windows Admin Shares | PsExec-style remote execution - suspicious service correlated with named pipe |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006) | Windows Remote Management | WinRM remote execution - process spawned by WinRM host |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002) | Pass the Hash | Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials |

### Stealth (TA0005)

| Technique | Name | Passing detections |
|---|---|---|
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | Remote thread created in another process |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002) | Portable Executable Injection | Remote thread created in another process |
| [T1218.003](https://attack.mitre.org/techniques/T1218/003) | CMSTP | LOLBin proxy execution - mshta, regsvr32, rundll32 or similar |
| [T1218.004](https://attack.mitre.org/techniques/T1218/004) | InstallUtil | LOLBin proxy execution - mshta, regsvr32, rundll32 or similar |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005) | Mshta | LOLBin proxy execution - mshta, regsvr32, rundll32 or similar |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010) | Regsvr32 | LOLBin proxy execution - mshta, regsvr32, rundll32 or similar |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011) | Rundll32 | LOLBin proxy execution - mshta, regsvr32, rundll32 or similar |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001) | DLL | Unsigned or user-path DLL loaded by a service or system binary |

### Discovery (TA0007)

| Technique | Name | Passing detections |
|---|---|---|
| [T1016](https://attack.mitre.org/techniques/T1016) | System Network Configuration Discovery | Burst of distinct discovery commands from one host |
| [T1018](https://attack.mitre.org/techniques/T1018) | Remote System Discovery | Burst of distinct discovery commands from one host |
| [T1049](https://attack.mitre.org/techniques/T1049) | System Network Connections Discovery | Burst of distinct discovery commands from one host |
| [T1069.001](https://attack.mitre.org/techniques/T1069/001) | Local Groups | Burst of distinct discovery commands from one host |
| [T1069.002](https://attack.mitre.org/techniques/T1069/002) | Domain Groups | Burst of distinct discovery commands from one host |
| [T1082](https://attack.mitre.org/techniques/T1082) | System Information Discovery | Burst of distinct discovery commands from one host |
| [T1087.001](https://attack.mitre.org/techniques/T1087/001) | Local Account | Burst of distinct discovery commands from one host |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002) | Domain Account | Burst of distinct discovery commands from one host |
| [T1135](https://attack.mitre.org/techniques/T1135) | Network Share Discovery | Burst of distinct discovery commands from one host |

## Detections and their techniques

| Detection | Severity | Techniques | TP hits | Cross-dataset | Runtime |
|---|---|---|---:|---:|---:|
| Autorun registry Run key written by a non-installer process | Medium | T1547.001 | 2 | 0 | 0.206s |
| Burst of distinct discovery commands from one host | Medium | T1087.001, T1087.002, T1069.001, T1069.002, T1082, T1018, T1016, T1049, T1135 | 2 | 1 | 0.167s |
| Credential-protection registry downgrade (WDigest, LSA PPL or NTLM) | High | T1112 | 5 | 0 | 0.136s |
| DCSync - directory replication rights used by a non-machine account | High | T1003.006 | 2 | 0 | 0.086s |
| Kerberoasting - RC4 service tickets requested for multiple SPNs | Medium | T1558.003 | 1 | 0 | 0.063s |
| LOLBin proxy execution - mshta, regsvr32, rundll32 or similar | Medium | T1218.005, T1218.010, T1218.011, T1218.003, T1218.004 | 4 | 2 | 0.124s |
| LSASS process handle opened with credential-dump access mask | High | T1003.001 | 2 | 2 | 0.448s |
| NTDS.dit extraction via ntdsutil, shadow copy or direct copy | High | T1003.003 | 4 | 0 | 0.220s |
| Obfuscated or encoded PowerShell execution | Medium | T1059.001 | 9 | 22 | 0.699s |
| Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials | High | T1550.002 | 1 | 3 | 0.312s |
| Password spraying - failed logons across many distinct accounts | Medium | T1110.003 | 1 | 0 | 0.158s |
| Process spawned by WMI provider host | Medium | T1047 | 2 | 1 | 0.060s |
| PsExec-style remote execution - suspicious service correlated with named pipe | High | T1021.002, T1569.002 | 4 | 1 | 0.322s |
| Remote thread created in another process | High | T1055, T1055.002 | 2 | 2 | 0.123s |
| SAM or SYSTEM registry hive exported to disk | High | T1003.002 | 4 | 0 | 0.423s |
| Scheduled task created or modified with a suspicious action | Medium | T1053.005 | 16 | 9 | 0.283s |
| Service installed with an interpreter, temp path or named-pipe image path | High | T1543.003, T1569.002 | 4 | 2 | 0.152s |
| UAC bypass via hijacked shell-open registry handler | High | T1548.002 | 4 | 0 | 0.105s |
| Unsigned or user-path DLL loaded by a service or system binary | Medium | T1574.001 | 2 | 24 | 0.101s |
| WMI permanent event subscription created | High | T1546.003 | 3 | 0 | 0.132s |
| WinRM remote execution - process spawned by WinRM host | Medium | T1021.006 | 2 | 6 | 0.358s |
| Windows Script Host execution of a script from a user-writable path | Medium | T1059.005 | 2 | 3 | 0.102s |
| Windows Security audit log cleared | High | T1685.005 | 1 | 5 | 0.112s |
| Windows event logging disabled or audit policy weakened | High | T1685.001 | 4 | 0 | 0.402s |

