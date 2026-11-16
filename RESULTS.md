# RESULTS.md

**Generated** by `make test` -- do not edit. Last run 2026-11-16 09:21:37Z.

- ATT&CK version pinned: **v20.1**
- Corpus: **420,977 events** across **39 datasets**
- Detections run: **24**, with a passing real-data true positive: **24**
- Total query time: **5.29s** (mean 0.221s per detection)

> Every detection below is executed once against the **entire** ingested corpus. Hits are then attributed by `DatasetId`. "Cross-dataset" counts datasets the detection fired on that it does not declare as a true-positive source -- a false-positive *proxy*, not a production FP rate. These are all attack datasets, so some overlap is genuinely correct (a Mimikatz capture really does contain LSASS access).

## Detection results

| Detection | Techniques | Status | TP hits | Cross-dataset | Rate | Time (s) |
|---|---|---|---:|---:|---:|---:|
| Autorun registry Run key written by a non-installer process | T1547.001 | validated / pass | 2 | 0 | 0.00 | 0.206 |
| Burst of distinct discovery commands from one host | T1087.001, T1087.002, T1069.001, T1069.002, T1082, T1018, T1016, T1049, T1135 | validated / pass | 2 | 1 | 0.03 | 0.167 |
| Credential-protection registry downgrade (WDigest, LSA PPL or NTLM) | T1112 | validated / pass | 5 | 0 | 0.00 | 0.136 |
| DCSync - directory replication rights used by a non-machine account | T1003.006 | validated / pass | 2 | 0 | 0.00 | 0.086 |
| Kerberoasting - RC4 service tickets requested for multiple SPNs | T1558.003 | validated / pass | 1 | 0 | 0.00 | 0.063 |
| LOLBin proxy execution - mshta, regsvr32, rundll32 or similar | T1218.005, T1218.010, T1218.011, T1218.003, T1218.004 | validated / pass | 4 | 2 | 0.05 | 0.124 |
| LSASS process handle opened with credential-dump access mask | T1003.001 | validated / pass | 2 | 2 | 0.05 | 0.448 |
| NTDS.dit extraction via ntdsutil, shadow copy or direct copy | T1003.003 | validated / pass | 4 | 0 | 0.00 | 0.220 |
| Obfuscated or encoded PowerShell execution | T1059.001 | validated / pass | 9 | 22 | 0.59 | 0.699 |
| Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials | T1550.002 | validated / pass | 1 | 3 | 0.08 | 0.312 |
| Password spraying - failed logons across many distinct accounts | T1110.003 | validated / pass | 1 | 0 | 0.00 | 0.158 |
| Process spawned by WMI provider host | T1047 | validated / pass | 2 | 1 | 0.03 | 0.060 |
| PsExec-style remote execution - suspicious service correlated with named pipe | T1021.002, T1569.002 | validated / pass | 4 | 1 | 0.03 | 0.322 |
| Remote thread created in another process | T1055, T1055.002 | validated / pass | 2 | 2 | 0.05 | 0.123 |
| SAM or SYSTEM registry hive exported to disk | T1003.002 | validated / pass | 4 | 0 | 0.00 | 0.423 |
| Scheduled task created or modified with a suspicious action | T1053.005 | validated / pass | 16 | 9 | 0.24 | 0.283 |
| Service installed with an interpreter, temp path or named-pipe image path | T1543.003, T1569.002 | validated / pass | 4 | 2 | 0.05 | 0.152 |
| UAC bypass via hijacked shell-open registry handler | T1548.002 | validated / pass | 4 | 0 | 0.00 | 0.105 |
| Unsigned or user-path DLL loaded by a service or system binary | T1574.001 | validated / pass | 2 | 24 | 0.63 | 0.101 |
| WMI permanent event subscription created | T1546.003 | validated / pass | 3 | 0 | 0.00 | 0.132 |
| WinRM remote execution - process spawned by WinRM host | T1021.006 | validated / pass | 2 | 6 | 0.16 | 0.358 |
| Windows Script Host execution of a script from a user-writable path | T1059.005 | validated / pass | 2 | 3 | 0.08 | 0.102 |
| Windows Security audit log cleared | T1685.005 | validated / pass | 1 | 5 | 0.13 | 0.112 |
| Windows event logging disabled or audit policy weakened | T1685.001 | validated / pass | 4 | 0 | 0.00 | 0.402 |

## Per-detection detail

### Autorun registry Run key written by a non-installer process

- File: `detections/persistence/T1547.001_run_key_persistence.yml`
- Techniques: T1547.001 -> tactics Persistence, Privilege Escalation
- Severity: Medium | Status: validated
- Runtime: 0.206s | total hits: 2

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200722001847 | 1 | yes |
| SDWIN-190319023812 | 1 | yes |

### Burst of distinct discovery commands from one host

- File: `detections/discovery/T1087_recon_command_burst.yml`
- Techniques: T1087.001, T1087.002, T1069.001, T1069.002, T1082, T1018, T1016, T1049, T1135 -> tactics Discovery
- Severity: Medium | Status: validated
- Runtime: 0.167s | total hits: 3

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190319023812 | 1 | yes |
| LSASS_campaign_01 | 1 | yes |
| SDWIN-190518184306 | 1 | no |

### Credential-protection registry downgrade (WDigest, LSA PPL or NTLM)

- File: `detections/defense_impairment/T1112_wdigest_credential_downgrade.yml`
- Techniques: T1112 -> tactics Defense Impairment, Persistence
- Severity: High | Status: validated
- Runtime: 0.136s | total hits: 5

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-191225045202 | 4 | yes |
| SDWIN-190518201922 | 1 | yes |

### DCSync - directory replication rights used by a non-machine account

- File: `detections/credential_access/T1003.006_dcsync_replication.yml`
- Techniques: T1003.006 -> tactics Credential Access
- Severity: High | Status: validated
- Runtime: 0.086s | total hits: 2

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200805020926 | 1 | yes |
| SDWIN-190301174830 | 1 | yes |

### Kerberoasting - RC4 service tickets requested for multiple SPNs

- File: `detections/credential_access/T1558.003_kerberoasting.yml`
- Techniques: T1558.003 -> tactics Credential Access
- Severity: Medium | Status: validated
- Runtime: 0.063s | total hits: 1

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201022042947 | 1 | yes |

### LOLBin proxy execution - mshta, regsvr32, rundll32 or similar

- File: `detections/stealth/T1218_lolbin_proxy_execution.yml`
- Techniques: T1218.005, T1218.010, T1218.011, T1218.003, T1218.004 -> tactics Stealth
- Severity: Medium | Status: validated
- Runtime: 0.124s | total hits: 8

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200721232741 | 2 | yes |
| SDWIN-201018195009 | 2 | no |
| SDWIN-201022022144 | 2 | yes |
| LSASS_campaign_01 | 2 | no |

### LSASS process handle opened with credential-dump access mask

- File: `detections/credential_access/T1003.001_lsass_handle_access.yml`
- Techniques: T1003.001 -> tactics Credential Access
- Severity: High | Status: validated
- Runtime: 0.448s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201018195009 | 1 | yes |
| SDWIN-190319131123 | 1 | no |
| LSASS_campaign_01 | 1 | no |
| SDWIN-190518202151 | 1 | yes |

### NTDS.dit extraction via ntdsutil, shadow copy or direct copy

- File: `detections/credential_access/T1003.003_ntds_extraction.yml`
- Techniques: T1003.003 -> tactics Credential Access
- Severity: High | Status: validated
- Runtime: 0.220s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-230718151900 | 2 | yes |
| SDWIN-230718150800 | 2 | yes |

### Obfuscated or encoded PowerShell execution

- File: `detections/execution/T1059.001_powershell_obfuscation.yml`
- Techniques: T1059.001 -> tactics Execution
- Severity: Medium | Status: validated
- Runtime: 0.699s | total hits: 103

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190518213907 | 9 | no |
| SDWIN-190518210125 | 9 | no |
| SDWIN-190518184306 | 9 | no |
| SDWIN-190518211456 | 8 | no |
| SDWIN-200921175806 | 7 | no |
| SDWIN-200904032946 | 6 | no |
| SDWIN-190319023812 | 6 | no |
| SDWIN-190518182022 | 5 | yes |
| SDWIN-200721232741 | 4 | yes |
| SDWIN-190403133337 | 3 | no |
| SDWIN-190518201922 | 3 | no |
| SDWIN-190319024742 | 3 | no |
| SDWIN-191225045202 | 3 | no |
| SDWIN-190518201207 | 3 | no |
| SDWIN-190319020729 | 3 | no |
| SDWIN-190625133822 | 3 | no |
| SDWIN-200722001847 | 3 | no |
| SDWIN-190319021158 | 3 | no |
| SDWIN-190319020147 | 3 | no |
| SDWIN-190518202151 | 2 | no |
| SDWIN-190319131123 | 2 | no |
| SDWIN-190301174830 | 2 | no |
| SDWIN-190625103712 | 2 | no |
| SDWIN-220708104215 | 2 | no |

### Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials

- File: `detections/lateral_movement/T1550.002_pass_the_hash.yml`
- Techniques: T1550.002 -> tactics Lateral Movement
- Severity: High | Status: validated
- Runtime: 0.312s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190319023812 | 1 | no |
| SDWIN-190518184306 | 1 | no |
| SDWIN-200921175806 | 1 | no |
| SDWIN-190319131123 | 1 | yes |

### Password spraying - failed logons across many distinct accounts

- File: `detections/credential_access/T1110.003_password_spraying.yml`
- Techniques: T1110.003 -> tactics Credential Access
- Severity: Medium | Status: validated
- Runtime: 0.158s | total hits: 1

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201022042947 | 1 | yes |

### Process spawned by WMI provider host

- File: `detections/execution/T1047_wmi_process_execution.yml`
- Techniques: T1047 -> tactics Execution
- Severity: Medium | Status: validated
- Runtime: 0.060s | total hits: 3

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200806035621 | 1 | yes |
| SDWIN-190518184306 | 1 | no |
| SDWIN-190518213907 | 1 | yes |

### PsExec-style remote execution - suspicious service correlated with named pipe

- File: `detections/lateral_movement/T1021.002_psexec_service_and_pipe.yml`
- Techniques: T1021.002, T1569.002 -> tactics Execution, Lateral Movement
- Severity: High | Status: validated
- Runtime: 0.322s | total hits: 6

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190518210125 | 2 | yes |
| SDWIN-200921175806 | 2 | no |
| SDWIN-210611210814 | 2 | yes |

### Remote thread created in another process

- File: `detections/privilege_escalation/T1055_remote_thread_injection.yml`
- Techniques: T1055, T1055.002 -> tactics Privilege Escalation, Stealth
- Severity: High | Status: validated
- Runtime: 0.123s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201019232515 | 1 | yes |
| SDWIN-201023031210 | 1 | yes |
| LSASS_campaign_01 | 1 | no |
| SDWIN-190518184306 | 1 | no |

### SAM or SYSTEM registry hive exported to disk

- File: `detections/credential_access/T1003.002_sam_hive_extraction.yml`
- Techniques: T1003.002 -> tactics Credential Access
- Severity: High | Status: validated
- Runtime: 0.423s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190625133822 | 2 | yes |
| SDWIN-230718150800 | 2 | yes |

### Scheduled task created or modified with a suspicious action

- File: `detections/persistence/T1053.005_scheduled_task_creation.yml`
- Techniques: T1053.005 -> tactics Execution, Persistence, Privilege Escalation
- Severity: Medium | Status: validated
- Runtime: 0.283s | total hits: 41

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200921175806 | 14 | yes |
| SDWIN-190518184306 | 10 | no |
| SDWIN-220705170038 | 7 | no |
| SDWIN-190319023812 | 2 | no |
| SDWIN-190319024742 | 2 | yes |
| SDWIN-200806035621 | 1 | no |
| SDWIN-190319131123 | 1 | no |
| SDWIN-190403133337 | 1 | no |
| SDWIN-220708104215 | 1 | no |
| SDWIN-230718151900 | 1 | no |
| LSASS_campaign_01 | 1 | no |

### Service installed with an interpreter, temp path or named-pipe image path

- File: `detections/persistence/T1543.003_suspicious_service_install.yml`
- Techniques: T1543.003, T1569.002 -> tactics Execution, Persistence, Privilege Escalation
- Severity: High | Status: validated
- Runtime: 0.152s | total hits: 8

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190518210125 | 2 | yes |
| SDWIN-200921175806 | 2 | no |
| SDWIN-210611210814 | 2 | yes |
| LSASS_campaign_01 | 2 | no |

### UAC bypass via hijacked shell-open registry handler

- File: `detections/privilege_escalation/T1548.002_uac_bypass_registry.yml`
- Techniques: T1548.002 -> tactics Privilege Escalation
- Severity: High | Status: validated
- Runtime: 0.105s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-200904032946 | 4 | yes |

### Unsigned or user-path DLL loaded by a service or system binary

- File: `detections/stealth/T1574.001_dll_search_order_hijack.yml`
- Techniques: T1574.001 -> tactics Execution, Stealth
- Severity: Medium | Status: validated
- Runtime: 0.101s | total hits: 60

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201022042947 | 7 | no |
| SDWIN-200921175806 | 7 | no |
| SDWIN-190518184306 | 4 | no |
| SDWIN-190518211456 | 4 | no |
| SDWIN-220705170038 | 4 | no |
| SDWIN-190518213907 | 3 | no |
| SDWIN-200721232741 | 3 | no |
| SDWIN-210611210814 | 3 | no |
| SDWIN-190319023812 | 2 | no |
| SDWIN-190403133337 | 2 | yes |
| SDWIN-190518210125 | 2 | no |
| LSASS_campaign_01 | 2 | no |
| SDWIN-201021204544 | 2 | no |
| SDWIN-200806035621 | 2 | no |
| SDWIN-201019232515 | 2 | no |
| SDWIN-201023031210 | 2 | no |
| SDWIN-200904032946 | 1 | no |
| SDWIN-190518182022 | 1 | no |
| SDWIN-190301174830 | 1 | no |
| SDWIN-190319131123 | 1 | no |
| SDWIN-190518202151 | 1 | no |
| SDWIN-220708104215 | 1 | no |
| SDWIN-230718151900 | 1 | no |
| SDWIN-201022022144 | 1 | no |
| SDWIN-201018195009 | 1 | no |

### WMI permanent event subscription created

- File: `detections/persistence/T1546.003_wmi_event_subscription.yml`
- Techniques: T1546.003 -> tactics Persistence, Privilege Escalation
- Severity: High | Status: validated
- Runtime: 0.132s | total hits: 3

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190518184306 | 3 | yes |

### WinRM remote execution - process spawned by WinRM host

- File: `detections/lateral_movement/T1021.006_winrm_remote_execution.yml`
- Techniques: T1021.006 -> tactics Lateral Movement
- Severity: Medium | Status: validated
- Runtime: 0.358s | total hits: 19

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-191225045202 | 5 | no |
| SDWIN-201022042947 | 4 | no |
| SDWIN-190518201922 | 3 | no |
| SDWIN-200722001847 | 3 | no |
| SDWIN-190518211456 | 2 | yes |
| SDWIN-200721232741 | 1 | no |
| SDWIN-190518184306 | 1 | no |

### Windows Script Host execution of a script from a user-writable path

- File: `detections/execution/T1059.005_wsh_script_execution.yml`
- Techniques: T1059.005 -> tactics Execution
- Severity: Medium | Status: validated
- Runtime: 0.102s | total hits: 6

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-190518182022 | 2 | yes |
| SDWIN-210611210814 | 2 | no |
| SDWIN-190319023812 | 1 | no |
| LSASS_campaign_01 | 1 | no |

### Windows Security audit log cleared

- File: `detections/defense_impairment/T1685.005_security_log_cleared.yml`
- Techniques: T1685.005 -> tactics Defense Impairment
- Severity: High | Status: validated
- Runtime: 0.112s | total hits: 6

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-201018195009 | 1 | no |
| SDWIN-201021204544 | 1 | yes |
| SDWIN-201019232515 | 1 | no |
| SDWIN-201022022144 | 1 | no |
| SDWIN-201023031210 | 1 | no |
| SDWIN-201102041306 | 1 | no |

### Windows event logging disabled or audit policy weakened

- File: `detections/defense_impairment/T1685.001_event_logging_tampering.yml`
- Techniques: T1685.001 -> tactics Defense Impairment
- Severity: High | Status: validated
- Runtime: 0.402s | total hits: 4

| Dataset | Hits | Declared true positive |
|---|---:|---|
| SDWIN-220705170038 | 2 | yes |
| SDWIN-220630130349 | 1 | yes |
| SDWIN-220708104215 | 1 | yes |

