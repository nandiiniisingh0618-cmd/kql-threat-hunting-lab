# How it works: every detection in plain English

**Generated** by `make docs` from the detection YAML -- do not edit.
Regenerate with `make docs` after changing any detection.

ATT&CK Enterprise **v20.1** - 24 detections.

Each entry covers the same four things, because those are the four things worth being able to explain about a detection:

1. **The behaviour** - what the attacker is actually doing.
2. **The telemetry** - which events make it visible.
3. **Why the query catches it** - the logic, and what makes it specific.
4. **How to evade it** - the honest limits.

## Index

**Credential Access**

- [DCSync - directory replication rights used by a non-machine account](#dcsync-directory-replication-rights-used-by-a-non-machine-account) (T1003.006)
- [Kerberoasting - RC4 service tickets requested for multiple SPNs](#kerberoasting-rc4-service-tickets-requested-for-multiple-spns) (T1558.003)
- [LSASS process handle opened with credential-dump access mask](#lsass-process-handle-opened-with-credential-dump-access-mask) (T1003.001)
- [NTDS.dit extraction via ntdsutil, shadow copy or direct copy](#ntdsdit-extraction-via-ntdsutil-shadow-copy-or-direct-copy) (T1003.003)
- [Password spraying - failed logons across many distinct accounts](#password-spraying-failed-logons-across-many-distinct-accounts) (T1110.003)
- [SAM or SYSTEM registry hive exported to disk](#sam-or-system-registry-hive-exported-to-disk) (T1003.002)

**Defense Impairment**

- [Credential-protection registry downgrade (WDigest, LSA PPL or NTLM)](#credential-protection-registry-downgrade-wdigest-lsa-ppl-or-ntlm) (T1112)
- [Windows Security audit log cleared](#windows-security-audit-log-cleared) (T1685.005)
- [Windows event logging disabled or audit policy weakened](#windows-event-logging-disabled-or-audit-policy-weakened) (T1685.001)

**Discovery**

- [Burst of distinct discovery commands from one host](#burst-of-distinct-discovery-commands-from-one-host) (T1087.001, T1087.002, T1069.001, T1069.002, T1082, T1018, T1016, T1049, T1135)

**Execution**

- [Obfuscated or encoded PowerShell execution](#obfuscated-or-encoded-powershell-execution) (T1059.001)
- [Process spawned by WMI provider host](#process-spawned-by-wmi-provider-host) (T1047)
- [PsExec-style remote execution - suspicious service correlated with named pipe](#psexec-style-remote-execution-suspicious-service-correlated-with-named-pipe) (T1021.002, T1569.002)
- [Scheduled task created or modified with a suspicious action](#scheduled-task-created-or-modified-with-a-suspicious-action) (T1053.005)
- [Service installed with an interpreter, temp path or named-pipe image path](#service-installed-with-an-interpreter-temp-path-or-named-pipe-image-path) (T1543.003, T1569.002)
- [Unsigned or user-path DLL loaded by a service or system binary](#unsigned-or-user-path-dll-loaded-by-a-service-or-system-binary) (T1574.001)
- [Windows Script Host execution of a script from a user-writable path](#windows-script-host-execution-of-a-script-from-a-user-writable-path) (T1059.005)

**Lateral Movement**

- [Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials](#pass-the-hash-overpass-the-hash-ntlm-network-logon-with-explicit-credentials) (T1550.002)
- [PsExec-style remote execution - suspicious service correlated with named pipe](#psexec-style-remote-execution-suspicious-service-correlated-with-named-pipe) (T1021.002, T1569.002)
- [WinRM remote execution - process spawned by WinRM host](#winrm-remote-execution-process-spawned-by-winrm-host) (T1021.006)

**Persistence**

- [Autorun registry Run key written by a non-installer process](#autorun-registry-run-key-written-by-a-non-installer-process) (T1547.001)
- [Credential-protection registry downgrade (WDigest, LSA PPL or NTLM)](#credential-protection-registry-downgrade-wdigest-lsa-ppl-or-ntlm) (T1112)
- [Scheduled task created or modified with a suspicious action](#scheduled-task-created-or-modified-with-a-suspicious-action) (T1053.005)
- [Service installed with an interpreter, temp path or named-pipe image path](#service-installed-with-an-interpreter-temp-path-or-named-pipe-image-path) (T1543.003, T1569.002)
- [WMI permanent event subscription created](#wmi-permanent-event-subscription-created) (T1546.003)

**Privilege Escalation**

- [Autorun registry Run key written by a non-installer process](#autorun-registry-run-key-written-by-a-non-installer-process) (T1547.001)
- [Remote thread created in another process](#remote-thread-created-in-another-process) (T1055, T1055.002)
- [Scheduled task created or modified with a suspicious action](#scheduled-task-created-or-modified-with-a-suspicious-action) (T1053.005)
- [Service installed with an interpreter, temp path or named-pipe image path](#service-installed-with-an-interpreter-temp-path-or-named-pipe-image-path) (T1543.003, T1569.002)
- [UAC bypass via hijacked shell-open registry handler](#uac-bypass-via-hijacked-shell-open-registry-handler) (T1548.002)
- [WMI permanent event subscription created](#wmi-permanent-event-subscription-created) (T1546.003)

**Stealth**

- [LOLBin proxy execution - mshta, regsvr32, rundll32 or similar](#lolbin-proxy-execution-mshta-regsvr32-rundll32-or-similar) (T1218.005, T1218.010, T1218.011, T1218.003, T1218.004)
- [Remote thread created in another process](#remote-thread-created-in-another-process) (T1055, T1055.002)
- [Unsigned or user-path DLL loaded by a service or system binary](#unsigned-or-user-path-dll-loaded-by-a-service-or-system-binary) (T1574.001)

---

## Autorun registry Run key written by a non-installer process

- **Techniques:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
- **Tactics:** Persistence, Privilege Escalation
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/persistence/T1547.001_run_key_persistence.yml`
- **Validated against:** SDWIN-190319023812, SDWIN-200722001847

**1. The behaviour**

A value was written under a CurrentVersion\Run or RunOnce key by a process that is not a known installer or OS component. Run keys execute at logon, which makes them the cheapest reliable user-level persistence on Windows.

**2. The telemetry**

- Sysmon EventID 12/13 (registry)

**3. Why the query catches it**

WrittenByInterpreter is surfaced, not filtered, because an interpreter writing persistence is the high-fidelity case while an unknown .exe is merely unbaselined. Promote to High when WrittenByInterpreter is true. The cheap has "CurrentVersion" gate runs before the has_any so the expensive comparison only sees candidate rows. In production, pair this with the value DATA: an autorun value pointing into a user-writable path (AppData, Temp, ProgramData) is far more suspicious than one pointing into Program Files.

Known false positives:

- Any application installer or updater not in the allowlist writes autorun values legitimately; the allowlist is estate specific and will need extending.
- User-installed software (browsers, chat clients, VPNs) adds Run values on first launch.
- Roaming-profile and provisioning tooling can rewrite autorun values at logon.
- Note: Sysmon EventID 13 does not always populate User, so Account is blank for some rows in this corpus - triage on Process and Computer instead.

**4. How to evade it**

- Startup-folder persistence (a shortcut dropped in Start Menu\Programs\Startup) is the same ATT&CK sub-technique but is a file event, not a registry event, and is not covered here.
- The many other autorun locations (Winlogon Shell/Userinit, IFEO, AppInit_DLLs, Active Setup) are different sub-techniques and are not matched.
- Allowlisting by image name is evadable by renaming a payload to msiexec.exe.
- If Sysmon's registry filtering excludes these keys for performance, there is no telemetry.
- Deletion of a value is excluded, so an attacker's cleanup is not flagged.

References: <https://attack.mitre.org/techniques/T1547/001/>

---

## Burst of distinct discovery commands from one host

- **Techniques:** [T1087.001](https://attack.mitre.org/techniques/T1087/001), [T1087.002](https://attack.mitre.org/techniques/T1087/002), [T1069.001](https://attack.mitre.org/techniques/T1069/001), [T1069.002](https://attack.mitre.org/techniques/T1069/002), [T1082](https://attack.mitre.org/techniques/T1082), [T1018](https://attack.mitre.org/techniques/T1018), [T1016](https://attack.mitre.org/techniques/T1016), [T1049](https://attack.mitre.org/techniques/T1049), [T1135](https://attack.mitre.org/techniques/T1135)
- **Tactics:** Discovery
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/discovery/T1087_recon_command_burst.yml`
- **Validated against:** SDWIN-190319023812, LSASS_campaign_01

**1. The behaviour**

A single host ran several different reconnaissance commands - account, group, host, share and network enumeration - inside a short window. Any one of these is unremarkable; a cluster of distinct ones in minutes is the hallmark of an operator orienting themselves after gaining access.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Security EventID 4688 (ProcessCreate)

**3. Why the query catches it**

min_distinct_categories = 2 with a 15m window is tuned so the rule is provable on this corpus; on production telemetry start at 3 or 4. The bin()-based bucketing is a cheap approximation of a sliding window: an operator whose commands straddle a bucket boundary can be split across two rows, which is an accepted tradeoff for cost. The single most effective tuning step is excluding known logon-script parent processes and service accounts, then baselining DistinctCategories per host role. Alerting on the burst rather than on individual commands is the whole point - individual discovery commands are far too common to be actionable.

Known false positives:

- Logon scripts and GPO startup scripts commonly run ipconfig, hostname and net commands together on every boot.
- Helpdesk and support staff troubleshooting connectivity produce genuine bursts.
- Inventory, monitoring and asset-management agents enumerate the same information on a schedule.
- Vulnerability scanners and compliance tooling will trip this reliably.
- Developer and admin workstations show far higher baselines than user endpoints.
- IMPORTANT EVIDENCE LIMITATION: OTRF *atomic* datasets each capture a single technique in isolation, so by construction they contain only ONE discovery category and can never satisfy a 2-category threshold. This rule is therefore validated against the multi-stage captures (SDWIN-190319023812 reaches 5 categories, LSASS_campaign_01 reaches 4). That is a property of the test data, not of the rule - but it does mean the burst logic has a thinner evidence base than the single-event rules in this repo.
- VERIFIED IN THIS CORPUS: whoami.exe alone (T1033) appears in 17 datasets as incidental post-exploitation noise. A 1-category threshold would therefore fire almost everywhere, which is exactly why the threshold is 2.

**4. How to evade it**

- Discovery via .NET, LDAP or WMI APIs (SharpHound, PowerView in-memory, ADSI) spawns no child process and is completely invisible to this rule.
- An operator who paces commands wider than the 15m window, or runs only one category, stays under the threshold.
- Renamed binaries evade the process-name gate; only the command-line regexes would still match.
- Interactive discovery typed into an existing shell still creates child processes, but discovery done inside a single PowerShell session using cmdlets does not.
- bin() bucketing means a burst spanning a bucket edge may be halved and fall below the threshold.

References: <https://attack.mitre.org/techniques/T1087/>, <https://attack.mitre.org/techniques/T1069/>

---

## Credential-protection registry downgrade (WDigest, LSA PPL or NTLM)

- **Techniques:** [T1112](https://attack.mitre.org/techniques/T1112)
- **Tactics:** Defense Impairment, Persistence
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/defense_impairment/T1112_wdigest_credential_downgrade.yml`
- **Validated against:** SDWIN-190518201922, SDWIN-191225045202

**1. The behaviour**

The WDigest UseLogonCredential registry value was set to 1, which makes LSASS cache plaintext passwords in memory again. Attackers set this and then wait for users to log on, so that a later LSASS dump yields passwords rather than only hashes.

**2. The telemetry**

- Sysmon EventID 13 (registry value set)

**3. Why the query catches it**

The WeakensSecurity logic is the heart of this rule: alerting on any write to these keys would flag hardening as an attack. UseLogonCredential=1 and RunAsPPL=0 are the two that matter most. The value is parsed out of Sysmon's rendered Details string (which looks like 'DWORD (0x00000001)') with a regex, so verify that parse if your Sysmon version renders it differently. Highest-value correlation: a credential downgrade followed within hours by an LSASS access event (the T1003.001 rule) is a near-certain credential-theft sequence and worth a dedicated correlation rule.

Known false positives:

- Some legacy applications and older RDP/SSO configurations genuinely require WDigest, and an administrator may enable it deliberately.
- Disabling RunAsPPL is occasionally needed for compatibility with older EDR or debugging tools.
- Hardening rollbacks and troubleshooting can set these values legitimately.
- Configuration-management tooling that enforces a baseline will rewrite these values on every run, including to their secure state - which is why the direction of the change is evaluated rather than just the key.

**4. How to evade it**

- Setting the value via the registry API from inside an already-running process still produces EventID 13, but if Sysmon's registry filter excludes these paths there is no telemetry.
- An attacker who dumps LSASS without a downgrade still gets hashes, which are enough for pass-the-hash - so this rule is about password recovery, not about preventing credential theft.
- Does not detect the subsequent logon that actually populates the cleartext cache.
- The value can be set, used and reverted quickly; if the revert is all you see, the window may be missed.
- Group Policy can set WDigest without a local registry write event in some configurations.

References: <https://attack.mitre.org/techniques/T1112/>

---

## DCSync - directory replication rights used by a non-machine account

- **Techniques:** [T1003.006](https://attack.mitre.org/techniques/T1003/006)
- **Tactics:** Credential Access
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/credential_access/T1003.006_dcsync_replication.yml`
- **Validated against:** SDWIN-200805020926, SDWIN-190301174830

**1. The behaviour**

An account requested one of the Active Directory replication extended rights (DS-Replication-Get-Changes and friends) against the domain object. Domain controllers do this constantly between themselves, but a user account doing it is DCSync: pulling password hashes straight out of AD without touching NTDS.dit on disk.

**2. The telemetry**

- Security EventID 4662 (directory service object operation)

**3. Why the query catches it**

Requires audit of 'Directory Service Access' to be enabled on domain controllers, which is off by default - without it this rule has no telemetry at all. The '$' suffix test is a cheap proxy for 'is a computer account'; on a real estate prefer an explicit allowlist of sync service accounts plus the DCs' own SIDs, because an attacker can create a user whose name ends in '$'. Escalate when DistinctRights is 2 or more, since Get-Changes plus Get-Changes-All is the combination mimikatz lsadump::dcsync requests.

Known false positives:

- Azure AD Connect / Entra Connect sync accounts hold replication rights by design and must be allowlisted by name.
- Some backup, migration and identity-governance products legitimately replicate directory changes.
- VERIFIED IN THIS CORPUS: dataset SDWIN-190403133337 shows MORDORDC$ (a DC computer account) requesting the same rights as normal DC-to-DC replication. The '$' filter is what removes it.
- A read-only domain controller's account also appears here if the '$' filter is removed.

**4. How to evade it**

- An attacker who grants replication rights to a computer account they control evades the '$' filter entirely.
- This fires on the rights being USED, not granted; the DACL modification that enabled it is a separate event (T1222.001 / T1098).
- Only visible on the domain controller that served the request - if that DC's logs are not collected, nothing is seen.
- Replication against a specific user object rather than the domain root may use a different ObjectType and would be missed by the domainDNS class filter.

References: <https://attack.mitre.org/techniques/T1003/006/>

---

## Kerberoasting - RC4 service tickets requested for multiple SPNs

- **Techniques:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
- **Tactics:** Credential Access
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/credential_access/T1558.003_kerberoasting.yml`
- **Validated against:** SDWIN-201022042947

**1. The behaviour**

A single source requested Kerberos service tickets (TGS) encrypted with RC4-HMAC for one or more user-account SPNs. RC4 tickets are offline-crackable, and modern domains default to AES, so a deliberate RC4 request - especially a burst across several distinct services - is the signature of Kerberoasting.

**2. The telemetry**

- Security EventID 4769 (Kerberos service ticket request)

**3. Why the query catches it**

min_distinct_spns is set to 1 so the rule is provable on this corpus, where the PurpleSharp dataset requests 5 SPNs. In production set it to 3 or higher and keep the burst_window at 10m - that combination is what separates a sweep from one legacy app. Status is filtered to 0x0 so failed requests do not inflate the count. Also consider baselining per-account: an account that has never requested a service ticket before is far more interesting than one that does so hourly.

Known false positives:

- Legacy applications and appliances that only support RC4 request these tickets normally; allowlist those SPNs.
- Domain functional levels or account flags (msDS-SupportedEncryptionTypes) can force RC4 for genuine services.
- Vulnerability scanners and AD hygiene tools deliberately enumerate SPNs and will trip this.
- A single RC4 ticket for one SPN is weak evidence; the burst across distinct SPNs is the real signal.

**4. How to evade it**

- An attacker who requests AES tickets instead (where the SPN supports it) is invisible to this rule - the tradeoff is they are much harder to crack.
- Slow-and-low roasting, one SPN per hour, defeats the burst window.
- Requires 'Audit Kerberos Service Ticket Operations' on domain controllers.
- Targeted roasting of a single known high-value SPN produces DistinctSpns = 1 and is indistinguishable here from a legacy app.

References: <https://attack.mitre.org/techniques/T1558/003/>

---

## LOLBin proxy execution - mshta, regsvr32, rundll32 or similar

- **Techniques:** [T1218.005](https://attack.mitre.org/techniques/T1218/005), [T1218.010](https://attack.mitre.org/techniques/T1218/010), [T1218.011](https://attack.mitre.org/techniques/T1218/011), [T1218.003](https://attack.mitre.org/techniques/T1218/003), [T1218.004](https://attack.mitre.org/techniques/T1218/004)
- **Tactics:** Stealth
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/stealth/T1218_lolbin_proxy_execution.yml`
- **Validated against:** SDWIN-201022022144, SDWIN-200721232741

**1. The behaviour**

A signed Microsoft binary was used to execute code supplied from elsewhere: mshta running script, regsvr32 loading a scriptlet, rundll32 invoking an exported function, or similar. The binary is trusted and allowlisted, so attackers use it as a proxy to run their own code without dropping an unsigned executable.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Security EventID 4688 (ProcessCreate)

**3. Why the query catches it**

Deliberately one rule across several sub-techniques, because the behaviour and the tuning are shared; the Technique column preserves which sub-technique fired, and tools/make_layer.py colours all of the listed IDs. The script-handler indicator is the highest fidelity (a signed binary being handed script is rarely legitimate), the user-path indicator is the weakest - consider requiring two indicators for rundll32 specifically. Baseline the parent process: mshta.exe under winword.exe is an incident, mshta.exe under explorer.exe may be a user double-clicking an .hta.

Known false positives:

- rundll32.exe is invoked constantly by Windows and by installers with DLLs under user paths; the user-path indicator alone is weak for it.
- Legitimate software updaters fetch content over HTTP via these binaries.
- msbuild.exe and installutil.exe are normal on developer workstations.
- certutil.exe is used legitimately for certificate management, sometimes with URLs.
- Control-panel applets and shell extensions produce rundll32 command lines with user paths.

**4. How to evade it**

- A LOLBin executing content from a non-user, non-remote path with no script marker (for example a DLL planted in system32) matches nothing here.
- The LOLBin list is finite; the LOLBAS project tracks over a hundred binaries and this covers eleven.
- Renaming the LOLBin defeats the process-name match entirely - detecting that needs OriginalFileName, which Sysmon provides and this rule does not yet use.
- COM-based execution of the same payloads produces no LOLBin process.
- Command-line auditing must be enabled for the 4688 arm.

References: <https://attack.mitre.org/techniques/T1218/>, <https://lolbas-project.github.io/>

---

## LSASS process handle opened with credential-dump access mask

- **Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
- **Tactics:** Credential Access
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/credential_access/T1003.001_lsass_handle_access.yml`
- **Validated against:** SDWIN-190518202151, SDWIN-201018195009

**1. The behaviour**

A process other than a known-good caller opened a handle to lsass.exe with a right combination that permits reading process memory (PROCESS_VM_READ plus PROCESS_QUERY_INFORMATION). This is the common final step for Mimikatz-style credential theft regardless of the tool used to deliver it.

**2. The telemetry**

- Sysmon EventID 10 (ProcessAccess)

**3. Why the query catches it**

The 3650d lookback exists only because these public datasets were captured between 2019 and 2023. In production use 1d-7d. GrantedAccess is matched on an exact allowlist of masks rather than a bitwise test because Sysmon reports it as a hex string; a bitwise alternative is binary_and(toint(GrantedAccess), 0x0410) == 0x0410, which is more robust but costs a conversion on every row. Tighten by also requiring UnbackedCallTrace, which indicates the caller executed from unbacked memory.

Known false positives:

- EDR and AV agents (MsMpEng.exe, MsSense.exe) read LSASS routinely; allowlisted above by image name.
- Backup, DLP and performance-monitoring agents may open LSASS with 0x1410.
- Crash-dump tooling (WerFault.exe) opens LSASS legitimately after a fault.
- Allowlisting by image NAME only is weak: an attacker who renames their binary to msmpeng.exe evades it. In production, allowlist by signer plus path.

**4. How to evade it**

- Handle-duplication: an attacker who duplicates an existing LSASS handle produces no new EventID 10.
- Kernel-mode or driver-based reads (BYOVD) do not surface as ProcessAccess.
- Masks outside the allowlist are missed by design; a tool requesting only 0x0010 slips through.
- If Sysmon excludes lsass.exe from ProcessAccess logging (a common performance tweak) there is no telemetry at all.
- Does not detect dumping via MiniDumpWriteDump invoked from an already-privileged signed process.

References: <https://attack.mitre.org/techniques/T1003/001/>, <https://github.com/OTRF/Security-Datasets>

---

## NTDS.dit extraction via ntdsutil, shadow copy or direct copy

- **Techniques:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
- **Tactics:** Credential Access
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/credential_access/T1003.003_ntds_extraction.yml`
- **Validated against:** SDWIN-230718151900, SDWIN-230718150800

**1. The behaviour**

The Active Directory database NTDS.dit was copied or staged for extraction, using ntdsutil IFM, a volume shadow copy, or a direct file copy. NTDS.dit contains every domain account hash, so this is one of the highest-impact credential-access actions available on a domain controller.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Security EventID 4688 (ProcessCreate)

**3. Why the query catches it**

Tradecraft is tagged rather than collapsed so an analyst can triage by arm: NtdsutilIFM and DirectFileCopy are high-fidelity, ShadowCopy is the noisy one and is a good candidate to downgrade to Medium or to require a pairing with ntds.dit access. On a real estate, allowlist your backup service accounts and scheduled windows rather than the tool names, since the tools are legitimate.

Known false positives:

- Legitimate AD backup and disaster-recovery jobs use ntdsutil IFM and shadow copies on a schedule.
- Installing an additional domain controller via IFM media is a supported workflow.
- Backup agents (Veeam, DPM, Windows Server Backup) create shadow copies constantly - the ShadowCopy arm is the noisiest of the three.
- Shadow-copy creation alone is weak evidence; correlate with a later read of the NTDS path.

**4. How to evade it**

- DCSync replication steals the same hashes over the network and never touches NTDS.dit on disk - that is a separate detection (T1003.006).
- Third-party or custom VSS clients that call the API directly produce no command line.
- An attacker renaming ntdsutil.exe still trips the command-line markers, but renaming AND obfuscating the arguments would evade this.
- Copying the file from an already-mounted shadow path with a generic tool (xcopy, robocopy) only matches if 'ntds.dit' appears literally.

References: <https://attack.mitre.org/techniques/T1003/003/>

---

## Obfuscated or encoded PowerShell execution

- **Techniques:** [T1059.001](https://attack.mitre.org/techniques/T1059/001)
- **Tactics:** Execution
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/execution/T1059.001_powershell_obfuscation.yml`
- **Validated against:** SDWIN-190518182022, SDWIN-200721232741

**1. The behaviour**

PowerShell was invoked with a combination of encoding, download-and-execute, stealth-flag and indirect-execution patterns that together indicate intent to hide from command-line inspection. Scored across four independent marker categories and across three telemetry sources, then aggregated per host, account and marker set so one campaign produces one alert rather than thousands.

**2. The telemetry**

- PowerShell EventID 4104 (script block)
- PowerShell EventID 800 (classic pipeline)
- Sysmon EventID 1 (ProcessCreate)

**3. Why the query catches it**

min_score >= 2 is the pivot: single markers are far too common to alert on, two independent categories is strongly anomalous. Score 4 clusters in this corpus are all Empire launchers. The aggregation is as important as the scoring - pre-aggregation this rule produced 10,519 rows, post-aggregation 100. Keep the has_any gate ahead of the marker evaluation as a cost control. In production, baseline per parent process: a scored script block under a CI agent is routine, the same under winword.exe is not.

Known false positives:

- Deployment and configuration tooling (SCCM, Intune, Chocolatey, CI agents) routinely combines -nop -ep bypass with a download and will score 2.
- Administrator one-liners that fetch and run an internal script score 2 legitimately.
- Base64 is used benignly to pass structured arguments to PowerShell.
- EventID 4104 logs the script block AFTER de-obfuscation, so decoded content may merely mention these strings without being malicious.
- This rule fires on 23 of 39 datasets in this corpus. That is NOT noise: the Empire PowerShell launcher (-nop -w hidden -enc) is present in most OTRF datasets, so those are genuine true positives. max_cross_dataset_rate is raised to 0.95 for that reason, and the ceiling would be meaningless on production telemetry.

**4. How to evade it**

- A payload with no encoding, no download and no stealth flags - a plain local script - scores 0 and is invisible.
- String concatenation and format-operator obfuscation defeats the literal markers in the Sysmon and 800 arms.
- PowerShell v2 downgrade (-version 2) suppresses script-block logging entirely.
- Unmanaged PowerShell (hosting System.Management.Automation directly) creates no powershell.exe process.
- Script-block logging is off by default below Windows 10 / Server 2016.
- Aggregation hides per-event timing, so a slow drip and a burst look alike apart from FirstSeen/LastSeen.

References: <https://attack.mitre.org/techniques/T1059/001/>

---

## Pass-the-hash / overpass-the-hash - NTLM network logon with explicit credentials

- **Techniques:** [T1550.002](https://attack.mitre.org/techniques/T1550/002)
- **Tactics:** Lateral Movement
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/lateral_movement/T1550.002_pass_the_hash.yml`
- **Validated against:** SDWIN-190319131123

**1. The behaviour**

An NTLM logon occurred that bears the hallmarks of a passed hash rather than a typed password: a NewCredentials (type 9) logon created by credential-injection tooling, or an explicit-credential event whose process is not a normal logon surface. Correlates 4624 with 4648 on the same logon session.

**2. The telemetry**

- Security EventID 4624 (logon)
- Security EventID 4648 (explicit credentials)

**3. Why the query catches it**

Arm 1 is the discriminating one. Restricting LogonType 9 to the seclogo/Advapi logon processes is what separates credential injection from ordinary service logons, and is the closest thing to a reliable pass-the-hash signature available from Windows audit data alone. The strongest available confirmation is a NEGATIVE: a type-9 logon whose TargetLogonId never appears in a preceding 4624 type-2/type-10 for that user means the credentials were not typed on this host. Pair with the T1003.001 LSASS rule: a hash dumped here and used there within the same session is a complete attack chain.

Known false positives:

- runas /netonly is a legitimate administrative pattern and produces exactly the LogonType 9 shape this rule looks for.
- Scheduled tasks and services configured with stored credentials raise 4648 routinely.
- Backup, monitoring and deployment agents that authenticate to remote hosts generate explicit-credential events constantly.
- RDP with saved credentials and credential-manager-backed SSO both raise 4648.
- Arm 2 is the weaker arm: the allowlist of expected processes is estate specific and will need extending before deployment.

**4. How to evade it**

- Kerberos pass-the-ticket and overpass-the-hash that requests a TGT look like normal Kerberos authentication and are largely invisible to this rule.
- Hashes used directly over SMB from a non-Windows host (Impacket from Linux) produce a type-3 network logon on the target that is indistinguishable from legitimate authentication.
- Requires logon auditing including 4648, which is enabled by default but frequently filtered out of collection for volume.
- The rule sees the host where credentials were INJECTED, not necessarily where they were stolen or ultimately used.
- An attacker who obtains a plaintext password and simply types it produces no anomaly here at all.

References: <https://attack.mitre.org/techniques/T1550/002/>

---

## Password spraying - failed logons across many distinct accounts

- **Techniques:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
- **Tactics:** Credential Access
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/credential_access/T1110.003_password_spraying.yml`
- **Validated against:** SDWIN-201022042947

**1. The behaviour**

A single host saw failed logons for several distinct accounts inside a short window. Spraying one common password across many users keeps per-account failure counts below lockout thresholds, so the signal is the breadth of accounts rather than the depth of attempts against any one of them.

**2. The telemetry**

- Security EventID 4625 (logon failure)
- Security EventID 4624 (logon success)

**3. Why the query catches it**

min_distinct_accounts = 5 with a 30m window is the classic shape, and is also what this corpus can prove (the PurpleSharp AD playbook dataset fails 7 distinct accounts). AttemptsPerAccount is the most useful triage column: close to 1 means one password tried against many users (spray), much higher means brute force against few users. On a real estate, run this per source IP as well as per target host, because the source is what you block. Baseline DCs separately from endpoints. Consider also alerting on the inverse signal - a spray that SUCCEEDS produces a 4624 for an account that just failed, which is a much higher-confidence event.

Known false positives:

- A service account whose password expired can generate many failures, but against ONE account - the AttemptsPerAccount column is what separates that from a spray.
- After a password change, cached credentials on phones, mapped drives and scheduled tasks produce bursts of failures.
- Misconfigured applications or load balancers retrying with stale credentials.
- Vulnerability scanners and authentication testing tools will trip this deliberately.
- On a domain controller all domain authentication failures aggregate to that host, so a DC's baseline is far higher than a workstation's.

**4. How to evade it**

- Password spraying against cloud identity (Entra ID) never touches a Windows Security log and needs sign-in logs instead.
- Slow sprays paced wider than the 30m window fall below the threshold - a deliberate evasion against exactly this rule shape.
- Spraying with a valid password that succeeds first time produces no 4625 at all.
- Kerberos pre-authentication failures surface as 4771, not 4625, and are not read here.
- bin() bucketing can split a spray across two buckets and halve the count.
- This corpus contains only 9 4625 events in total, so the rule is validated on a single thin dataset.

References: <https://attack.mitre.org/techniques/T1110/003/>

---

## Process spawned by WMI provider host

- **Techniques:** [T1047](https://attack.mitre.org/techniques/T1047)
- **Tactics:** Execution
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/execution/T1047_wmi_process_execution.yml`
- **Validated against:** SDWIN-200806035621, SDWIN-190518213907

**1. The behaviour**

A process was created with WmiPrvSE.exe as its parent, or wmic.exe was used to invoke process creation. WMI is a legitimate management channel, which is exactly why attackers use it for local and remote execution: the payload inherits a trusted parent.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)

**3. Why the query catches it**

ChildIsInterpreter is surfaced rather than filtered on, so an analyst can triage: an interpreter under WmiPrvSE is far more suspicious than an arbitrary binary. Promote to High when ChildIsInterpreter is true and the account is not a known management service account. Build the expected_wmi_children allowlist from your own estate's baseline - it is highly environment specific.

Known false positives:

- Monitoring, inventory and software-deployment agents drive WMI heavily; their children must be allowlisted.
- SCCM/Intune remote actions and Group Policy scripts legitimately execute via WMI.
- Some installers legitimately appear beneath WmiPrvSE.exe, which is why msiexec and TiWorker are excluded.
- The allowlist is image-name based and therefore evadable by renaming.

**4. How to evade it**

- WMI event-subscription persistence executes via scrcons.exe, not WmiPrvSE - that is the separate T1546.003 rule.
- WMI used only to query information (no process creation) is not execution and is intentionally not covered here.
- Remote WMI shows the child on the TARGET host, so without that host's telemetry the execution is unseen.
- An attacker whose payload is named conhost.exe or wermgr.exe is allowlisted away.

References: <https://attack.mitre.org/techniques/T1047/>

---

## PsExec-style remote execution - suspicious service correlated with named pipe

- **Techniques:** [T1021.002](https://attack.mitre.org/techniques/T1021/002), [T1569.002](https://attack.mitre.org/techniques/T1569/002)
- **Tactics:** Execution, Lateral Movement
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/lateral_movement/T1021.002_psexec_service_and_pipe.yml`
- **Validated against:** SDWIN-190518210125, SDWIN-210611210814

**1. The behaviour**

A service whose image path runs an interpreter, lives in a user-writable directory or redirects to a named pipe was installed, and named-pipe activity occurred on the same host within seconds. Correlating the two is what separates PsExec-style lateral movement from an ordinary service install. Arm A matches the exact pipe named in the service's own image path; arm B matches service-control and known remote-execution pipes.

**2. The telemetry**

- Security EventID 4697 / System 7045 (service installed)
- Sysmon EventID 17/18 (named pipe)

**3. Why the query catches it**

Arm A is the one to trust: a service whose image path names a pipe, where that exact pipe then appears in telemetry, is essentially a signature for Cobalt Strike's and APT-Simulator's PsExec implementations, and it works even though the pipe name is randomised per run - which is precisely why a static pipe-name list cannot catch it. Arm B needs the suspicious-image-path gate to be usable at all. ClosestSeconds in this corpus is 0-3s, so tightening correlation_seconds from 120 to 30 costs nothing and raises precision. The join is declared kind=inner explicitly so the semantics are obvious rather than relying on Kusto's default.

Known false positives:

- Legitimate administrative use of PsExec is common; the tool is Microsoft-signed and widely used by real admins.
- Software deployment and remote-support products use the same service-plus-pipe pattern.
- Arm B is the noisier arm: \ntsvcs and \atsvc are traversed by ordinary local service and scheduled-task operations, so it relies on the suspicious-image-path gate to stay quiet.
- Sysmon's own install creates a service and a pipe, so a Sysmon upgrade can correlate.
- VERIFIED IN THIS CORPUS: without the suspicious-image-path gate this rule matched boot-time per-user svchost services against routine \ntsvcs traffic in 3 unrelated datasets (36-40 rows each). The gate removes all of them.

**4. How to evade it**

- WMI, WinRM, DCOM and scheduled-task lateral movement create no service and no pipe; each needs its own rule.
- Requires BOTH service-install auditing and Sysmon pipe events; pipe events are often disabled for volume.
- A service pointing at a signed binary in a normal path passes the suspicious-image-path gate untouched and is never evaluated.
- Fileless remote execution that reuses an existing service is invisible.
- The rule identifies the TARGET host only. Attributing the source needs Security 5145 share access or network telemetry.
- Arm A depends on the pipe name surviving into the image path; tooling that creates the pipe without naming it in the service command line only reaches arm B.

References: <https://attack.mitre.org/techniques/T1021/002/>

---

## Remote thread created in another process

- **Techniques:** [T1055](https://attack.mitre.org/techniques/T1055), [T1055.002](https://attack.mitre.org/techniques/T1055/002)
- **Tactics:** Privilege Escalation, Stealth
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/privilege_escalation/T1055_remote_thread_injection.yml`
- **Validated against:** SDWIN-201023031210, SDWIN-201019232515

**1. The behaviour**

A process created a thread inside a different process. This is the classic CreateRemoteThread injection primitive used to run code in a trusted process's address space, for credential access, defence evasion or privilege escalation.

**2. The telemetry**

- Sysmon EventID 8 (CreateRemoteThread)

**3. Why the query catches it**

AnyUnbacked is the most valuable column: a remote thread whose entry point is not in a named module is almost always shellcode. Promote to critical when AnyUnbacked is true or TargetIsLsass is true. Aggregating by source/target pair keeps a noisy injector to one row. Only 254 EventID 8 events exist across this corpus, so volume is modest - on production telemetry expect EDR agents to dominate and allowlist them by signer rather than by name.

Known false positives:

- EDR and AV products inject monitoring threads into user processes by design and must be allowlisted.
- Application compatibility shims, accessibility tools and some debuggers legitimately create remote threads.
- Software protection and licensing wrappers (DRM) use injection.
- Browser sandboxing and some installers create threads cross-process during startup.
- The allowlist is image-name based, so renaming a payload to csrss.exe evades it.

**4. How to evade it**

- The stealthier injection families produce no EventID 8 at all: APC queuing, thread hijacking (SetThreadContext on an existing thread), process hollowing and Early Bird all avoid CreateRemoteThread.
- Mapping-based injection (NtMapViewOfSection) plus an existing thread is invisible here.
- Sysmon EventID 8 is often disabled or heavily filtered in production because of volume.
- Only the creation is seen, not what the thread did - correlate with the target process's subsequent behaviour.
- Injection within the same process (self-injection, reflective loading) is not cross-process and is intentionally excluded.

References: <https://attack.mitre.org/techniques/T1055/>, <https://attack.mitre.org/techniques/T1055/002/>

---

## SAM or SYSTEM registry hive exported to disk

- **Techniques:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
- **Tactics:** Credential Access
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/credential_access/T1003.002_sam_hive_extraction.yml`
- **Validated against:** SDWIN-190625133822, SDWIN-230718150800

**1. The behaviour**

A command line saved or exported the SAM, SECURITY or SYSTEM registry hive root to a file. Offline, those hives together yield local account password hashes, so exporting the hive root is a reliable credential-access signal. Exports of individual subkeys underneath a hive are normal administration and are excluded.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Security EventID 4688 (ProcessCreate)

**3. Why the query catches it**

Two filters do the de-noising: the hive-root regex (so subkey exports are ignored) and dropping computer accounts. Keep the cheap has_any("hklm") prefilter ahead of the regex so the regex only evaluates on candidate rows. To raise fidelity further, join to Sysmon EventID 11 to confirm the output file appeared, and escalate when two or more different hives are exported by the same account within a short window.

Known false positives:

- Backup, imaging and migration tooling exports the SYSTEM hive legitimately.
- Support engineers export hives for diagnostics; SAM/SECURITY export is far rarer than SYSTEM.
- VERIFIED IN THIS CORPUS: dataset SDWIN-190319023812 contains WORKSTATION5$ (a computer account) running 'reg export HKLM\SYSTEM\CurrentControlSet\...'. That is benign OS activity and is the reason this rule matches only hive roots and drops accounts ending in '$'.
- A single hive export without the other two is less conclusive; hash cracking needs SAM plus SYSTEM.

**4. How to evade it**

- In-memory hive reads through registry APIs create no child process and no command line.
- Volume-shadow-copy access to the hive files bypasses reg.exe entirely (covered by the T1003.003 rule).
- Command-line auditing must be on for the 4688 arm; without it only Sysmon works.
- An attacker who exports to a subkey path repeatedly could stitch a hive together and evade the root-only match.
- Renaming esentutl.exe defeats the process-name arm, though the command-line arm still fires.

References: <https://attack.mitre.org/techniques/T1003/002/>

---

## Scheduled task created or modified with a suspicious action

- **Techniques:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
- **Tactics:** Execution, Persistence, Privilege Escalation
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/persistence/T1053.005_scheduled_task_creation.yml`
- **Validated against:** SDWIN-190319024742, SDWIN-200921175806

**1. The behaviour**

A scheduled task was registered or updated. Correlates the Security audit event for task registration with schtasks.exe command lines so the rule works whether or not task-scheduler auditing is enabled, and flags tasks whose action runs an interpreter or lives in a user-writable path.

**2. The telemetry**

- Security EventID 4698/4702 (scheduled task)
- Sysmon EventID 1 (ProcessCreate)

**3. Why the query catches it**

Deliberately returns all registrations with the indicators surfaced rather than filtering, because task names and paths are so estate-specific that any allowlist here would be fiction. The first tuning step in a real environment is to exclude task names under \Microsoft\Windows\ and then alert only where ActionUsesInterpreter is true. The two arms overlap on purpose: 4698 gives you the action XML, schtasks.exe gives you the invoking process and parent, and having both lets you spot a task created by a process rather than by an administrator.

Known false positives:

- Windows itself registers and updates many scheduled tasks; software installers add more.
- Patch management, backup and monitoring agents create tasks that run interpreters legitimately.
- GPO-delivered scheduled tasks appear as task registrations on every host in scope.
- This rule does not threshold or allowlist task names, so on production telemetry it needs a baseline of expected task paths (for example anything under \Microsoft\Windows\) before it is deployable.

**4. How to evade it**

- Tasks created through the Task Scheduler COM API directly (schtasks.exe never runs) are only caught by the 4698 arm.
- Registering a task on a REMOTE host via /s shows the task on the target but the command line on the source, so neither arm sees the whole action alone.
- 4698 requires 'Audit Other Object Access Events', which is off by default.
- Dropping a task XML straight into C:\Windows\System32\Tasks and creating the matching registry entry can bypass the scheduler service's audit event.
- TaskName extraction from the command line is regex-based and will be empty for unusual quoting.

References: <https://attack.mitre.org/techniques/T1053/005/>

---

## Service installed with an interpreter, temp path or named-pipe image path

- **Techniques:** [T1543.003](https://attack.mitre.org/techniques/T1543/003), [T1569.002](https://attack.mitre.org/techniques/T1569/002)
- **Tactics:** Execution, Persistence, Privilege Escalation
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/persistence/T1543.003_suspicious_service_install.yml`
- **Validated against:** SDWIN-190518210125, SDWIN-210611210814

**1. The behaviour**

A Windows service was created whose image path runs a command interpreter, points into a user-writable directory, or writes to a named pipe. Service creation is a privileged persistence and lateral-movement primitive, and these image-path shapes are what remote-execution tooling such as PsExec and SMBExec leave behind.

**2. The telemetry**

- Security EventID 4697 (service installed)
- System EventID 7045 (service installed)

**3. Why the query catches it**

The three indicators are OR-ed because each alone is a strong shape for a service image path - services normally point at a signed binary in Program Files or system32. The named-pipe indicator is the highest fidelity of the three and is essentially a PsExec/SMBExec signature. RandomLookingName is surfaced as a triage aid rather than a filter because legitimate per-user services also carry random suffixes. Excluding the 'svchost.exe -k' prefix removes the single largest benign population (62 rows in this corpus collapse to 7).

Known false positives:

- Some legitimate products install services that shell out through cmd.exe wrappers.
- Development and build agents install services from user-writable paths.
- Driver and antimalware definition updates can create services under ProgramData (for example MpKslDrv under Windows Defender Definition Updates, present in this corpus).
- Per-user svchost services (names ending in a random-looking suffix like _b0b5d) are an OS behaviour, which is why the svchost -k shape is excluded.

**4. How to evade it**

- A service pointing at a signed binary in a normal path - the quiet, patient approach - matches none of the three indicators.
- Service MODIFICATION (changing an existing service's binary) does not raise 4697/7045; it is a registry write under CurrentControlSet\Services.
- Requires either 'Audit Security System Extension' (4697) or System-log collection (7045); many estates have neither.
- Driver services (type kernel) are matched only if their path is unusual.
- An attacker who installs the service remotely still shows it on the target host only.

References: <https://attack.mitre.org/techniques/T1543/003/>, <https://attack.mitre.org/techniques/T1569/002/>

---

## UAC bypass via hijacked shell-open registry handler

- **Techniques:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
- **Tactics:** Privilege Escalation
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/privilege_escalation/T1548.002_uac_bypass_registry.yml`
- **Validated against:** SDWIN-200904032946

**1. The behaviour**

A registry value was written under a shell-open command or DelegateExecute key for a protected handler such as ms-settings or mscfile. Auto-elevating Windows binaries (fodhelper.exe, computerdefaults.exe, sdclt.exe, eventvwr.exe) read these keys, so hijacking them yields a high-integrity process with no consent prompt.

**2. The telemetry**

- Sysmon EventID 12/13 (registry)

**3. Why the query catches it**

This is one of the highest-fidelity rules in the set because the key paths are so specific. Restricting to HKU/HKCU matters: the machine-hive equivalents are legitimate OS state, and alerting on them would be noisy and wrong. The DelegateExecute arm catches the fodhelper variant that sets an empty DelegateExecute value to force the shell-open path. Correlate the write with a subsequent high-integrity child of fodhelper.exe to confirm the bypass actually ran.

Known false positives:

- Almost none in practice: user-hive writes to these specific handler keys are not something normal software does.
- Some file-association repair utilities and shell extensions touch exefile and Folder handlers.
- Security research, red-team tooling and UAC-bypass test harnesses will trip this legitimately.
- An empty DelegateExecute value is part of the technique rather than a benign state, so it is flagged rather than excluded.

**4. How to evade it**

- Only covers registry-hijack UAC bypasses. Token-duplication, DLL-hijack and COM-elevation-moniker bypasses look nothing like this.
- A bypass using an auto-elevating binary whose handler key is not in the list is missed; there are dozens of known variants.
- If the attacker cleans up the key before Sysmon flushes, the write is still logged, but correlation to the elevated child may be lost.
- Requires Sysmon registry auditing to include the user hives, which some configurations exclude for volume reasons.
- Does not confirm the elevation succeeded - it detects the setup, not the outcome.

References: <https://attack.mitre.org/techniques/T1548/002/>

---

## Unsigned or user-path DLL loaded by a service or system binary

- **Techniques:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
- **Tactics:** Execution, Stealth
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/stealth/T1574.001_dll_search_order_hijack.yml`
- **Validated against:** SDWIN-190403133337

**1. The behaviour**

A module was loaded from a user-writable directory, or loaded unsigned into a process running from system32. DLL search-order and phantom-DLL hijacking exploit the loader's path resolution to get attacker code into a trusted, often auto-starting, process.

**2. The telemetry**

- Sysmon EventID 7 (image load)

**3. Why the query catches it**

Treat this as a hunt, not an alert. The usable signal is HostIsSensitive combined with user-writable-path: an unsigned DLL under AppData loaded by svchost.exe is an incident, the same DLL loaded by an Electron app is Tuesday. The correct production approach is a rarity baseline - alert on (process, module) pairs not seen in the last 30 days - rather than the static path and signature heuristics used here, because a static rule cannot distinguish 'unusual' from 'merely unsigned'. Aggregation by process and indicator set keeps a chatty application to one row.

Known false positives:

- Enormously noisy without tuning: legitimate applications installed under %LOCALAPPDATA% (Teams, Slack, VS Code, Chrome) load their own unsigned DLLs constantly.
- Developer machines load freshly built, unsigned DLLs all day.
- Installers and updaters stage DLLs in Temp and load them from there.
- Signature status can read as invalid simply because the host could not reach a CRL/OCSP endpoint, not because the file is untrusted.
- This is the lowest-precision rule in this repo; it is included because DLL hijacking is important, and it is explicitly a hunting rule rather than an alerting rule.

**4. How to evade it**

- A signed-but-malicious DLL (stolen or abused certificate) in a legitimate path matches nothing here.
- Hijacking that replaces a DLL in system32 (requires admin) is neither in a user path nor unsigned-in-system32 if properly signed.
- Phantom DLL hijacking of a module that never loads successfully may not raise EventID 7 at all.
- Sysmon EventID 7 is frequently disabled in production because of its volume, which is the single biggest limitation.
- Reflectively loaded DLLs never touch the loader and produce no image-load event.
- SignatureStatus depends on the host's ability to validate the chain, so results vary with network conditions.

References: <https://attack.mitre.org/techniques/T1574/001/>

---

## WMI permanent event subscription created

- **Techniques:** [T1546.003](https://attack.mitre.org/techniques/T1546/003)
- **Tactics:** Persistence, Privilege Escalation
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/persistence/T1546.003_wmi_event_subscription.yml`
- **Validated against:** SDWIN-190518184306

**1. The behaviour**

A WMI event filter, consumer or filter-to-consumer binding was created. Together these three objects form a permanent event subscription that runs code when a trigger condition is met, surviving reboots and living entirely in the WMI repository rather than on disk or in the registry's usual autorun locations.

**2. The telemetry**

- Sysmon EventID 19/20/21 (WMI eventing)

**3. Why the query catches it**

Any permanent WMI subscription creation is rare enough to review, which is why this rule does not threshold. ConsumerIsExecuting separates inert filters from code-executing bindings - alert on the binding (EventID 21) and treat filter-only events as context. In this corpus the full three-object sequence (filter, consumer, binding) appears within about one second, so correlating all three by Computer within a short window is a reliable high-confidence pattern. Build an allowlist of your management tooling's consumer names rather than suppressing the technique.

Known false positives:

- Monitoring and systems-management products (SCCM, SCOM, antivirus) legitimately register permanent event subscriptions.
- Some OEM and power-management software uses WMI eventing for hardware triggers.
- Dell, HP and Lenovo management agents are common benign sources in enterprise estates.
- Because legitimate subscriptions are created once at install time, a baseline of expected consumer names is very effective here.

**4. How to evade it**

- Sysmon's WMI events cover permanent subscriptions only; temporary (session-scoped) subscriptions are not logged and die with the process anyway.
- Subscriptions created before Sysmon was installed are invisible - enumerate existing ones with a hunt query instead of relying on this rule.
- Only 3 such events exist in this entire 420k-event corpus, so this rule is validated on a single dataset; that is a thin evidence base.
- A subscription created in a non-default WMI namespace may not be captured depending on Sysmon configuration.
- The execution itself happens via scrcons.exe, which is better caught as a process-creation anomaly.

References: <https://attack.mitre.org/techniques/T1546/003/>

---

## WinRM remote execution - process spawned by WinRM host

- **Techniques:** [T1021.006](https://attack.mitre.org/techniques/T1021/006)
- **Tactics:** Lateral Movement
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/lateral_movement/T1021.006_winrm_remote_execution.yml`
- **Validated against:** SDWIN-190518211456

**1. The behaviour**

A process was created with wsmprovhost.exe (the WinRM/PowerShell Remoting host) as its parent, or a WinRM network connection preceded local execution. PowerShell Remoting is a legitimate management channel and therefore a favoured lateral-movement path that blends into administrative traffic.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Sysmon EventID 3 (network)
- Security EventID 4624 (logon)

**3. Why the query catches it**

Two arms answer two different questions: wsmprovhost children tell you a host was the TARGET, outbound 5985/5986 tells you it was the SOURCE. Keeping Evidence as a group-by key preserves that distinction instead of blurring it. The highest-value tuning is an allowlist of (source host, account) pairs for your admin tooling, after which anything remaining is genuinely interesting. Alert harder when the child of wsmprovhost is an interpreter running encoded content, or when the source is a user workstation rather than a jump host.

Known false positives:

- PowerShell Remoting is a standard administration tool; in estates that use it, this rule describes normal operations and must be baselined per source host and account.
- Configuration management (DSC, Ansible for Windows, Puppet) drives WinRM constantly.
- Monitoring and patching agents connect to 5985 routinely.
- Exchange and other Microsoft products use WinRM internally between roles.

**4. How to evade it**

- WinRM over a non-default port is missed by the network arm, though the wsmprovhost arm still fires on the target.
- WinRM used only to read information (Get-* cmdlets inside the remote session) spawns no child process and so produces no arm-1 hit.
- Session-internal activity in PowerShell Remoting is only visible via script-block logging, not process creation.
- If Sysmon network events are disabled, source attribution is lost entirely.
- Does not distinguish an authorised admin from an attacker using stolen admin credentials - that requires identity context this rule has no access to.

References: <https://attack.mitre.org/techniques/T1021/006/>

---

## Windows Script Host execution of a script from a user-writable path

- **Techniques:** [T1059.005](https://attack.mitre.org/techniques/T1059/005)
- **Tactics:** Execution
- **Severity:** Medium | **Status:** validated
- **Rule file:** `detections/execution/T1059.005_wsh_script_execution.yml`
- **Validated against:** SDWIN-190518182022

**1. The behaviour**

cscript.exe or wscript.exe executed a VBScript, JScript or WSF file, or was launched by a document or mail application. Windows Script Host is a legacy execution channel that remains enabled by default and is a common first-stage loader.

**2. The telemetry**

- Sysmon EventID 1 (ProcessCreate)
- Security EventID 4688 (ProcessCreate)

**3. Why the query catches it**

The document-parent indicator is by far the highest fidelity: winword.exe spawning wscript.exe is a phishing payload almost without exception, and is worth alerting on alone at High severity. The user-path and script-file indicators are context. On estates that still depend on VBScript logon scripts, allowlist by the script's full path rather than disabling the rule, and consider whether WSH can simply be disabled by policy - that is a stronger control than any detection here.

Known false positives:

- Legacy enterprise applications and logon scripts still ship VBScript, often from network or ProgramData paths.
- Some installers and management agents use WSH for setup tasks.
- Printer, driver and OEM utilities occasionally call cscript.
- The explorer.exe parent is included as a 'document parent' because a user double-clicking a script is worth seeing, but on some estates that is routine and should be removed.

**4. How to evade it**

- Script content executed from stdin or via a COM host (not a file argument) has no extension to match.
- A script run from a path not in the user-writable list, by an ordinary parent, with no recognised extension, matches nothing.
- Renaming cscript.exe defeats the process-name gate; OriginalFileName would be more robust.
- WSH invoked through a scheduled task shows the task as the parent rather than the real originator.
- Command-line auditing must be enabled for the 4688 arm.

References: <https://attack.mitre.org/techniques/T1059/005/>

---

## Windows Security audit log cleared

- **Techniques:** [T1685.005](https://attack.mitre.org/techniques/T1685/005)
- **Tactics:** Defense Impairment
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/defense_impairment/T1685.005_security_log_cleared.yml`
- **Validated against:** SDWIN-201021204544

**1. The behaviour**

The Security event log was cleared, raising EventID 1102. This is a loud, deliberate anti-forensic action: the event cannot be suppressed, so its presence is reliable, and the account that did it is recorded in the event message.

**2. The telemetry**

- Security EventID 1102 (audit log cleared)

**3. Why the query catches it**

No thresholds or filters are appropriate: 1102 is rare and always worth reviewing. The value of this rule is entirely in the response, not the tuning - correlate the LogonId with the preceding 4624 to identify the session, and treat the gap in the log as the investigative lead. Note this rule carries a raised max_cross_dataset_rate because the harness artefact described above makes it fire across 6 unrelated datasets.

Known false positives:

- Administrators clear logs during troubleshooting, and some log-management or imaging workflows clear them deliberately.
- Reimaging and sysprep clear logs as part of normal provisioning.
- CRITICAL CAVEAT FOR THIS CORPUS: all 6 of the 1102 events here were generated by the OTRF collection harness resetting the Security log before each capture, on the same host (WORKSTATION5) under the same built-in Administrator SID (-500). They are genuine 1102 events and the rule is correct, but they are a LAB ARTEFACT, not adversary behaviour. This is the clearest example in this repo of why 'the test passes' and 'the detection found an attack' are different claims.
- Because the clear wipes prior events, the log will not show what the actor did beforehand - absence of evidence here is itself the signal.

**4. How to evade it**

- Only the Security log is covered here. Clearing the System, Application or PowerShell logs raises EventID 104 in those logs instead, which this rule does not read.
- Selective record deletion (for example the DanderSpritz eventlogedit technique) removes individual records without raising 1102 at all.
- Stopping the service first (see T1685.001) then tampering offline avoids 1102.
- The event records the account but not the process that did the clearing.
- If log forwarding is not in place, the 1102 event itself can be destroyed by a subsequent clear.

References: <https://attack.mitre.org/techniques/T1685/005/>

---

## Windows event logging disabled or audit policy weakened

- **Techniques:** [T1685.001](https://attack.mitre.org/techniques/T1685/001)
- **Tactics:** Defense Impairment
- **Severity:** High | **Status:** validated
- **Rule file:** `detections/defense_impairment/T1685.001_event_logging_tampering.yml`
- **Validated against:** SDWIN-220630130349, SDWIN-220705170038, SDWIN-220708104215

**1. The behaviour**

Audit policy was modified, the EventLog service's start type was changed, or the Security log's file path was redirected. Each is a way to blind defenders before or after the noisy part of an intrusion, without the obvious tell of clearing the log.

**2. The telemetry**

- Security EventID 4719 (audit policy change)
- Sysmon EventID 12/13 (registry)
- Sysmon EventID 1 (ProcessCreate)

**3. Why the query catches it**

The three arms are unioned because each can be missing: 4719 needs audit-policy auditing enabled, the registry arm needs Sysmon to be watching these keys, and the tool arm needs command-line logging. Aggregating by host and account keeps a GPO refresh to one row instead of dozens. The single highest-value refinement is to inspect the VALUE rather than the key: EnableScriptBlockLogging set to 0 is an attack, set to 1 is hardening, and this rule currently reports both. Allowlist your GPO service accounts and your baseline-deployment windows first.

Known false positives:

- Group Policy refresh legitimately rewrites audit policy and can raise 4719 on every host in scope, repeatedly.
- Hardening and compliance baselines (CIS, STIG, SCM) deliberately change audit policy at deployment.
- Log-size and retention tuning by administrators touches the MaxSize and File values.
- Enabling script-block logging is a defensive action that matches the same registry path as disabling it - the VALUE matters, not just the key.
- 4719 is noisy by nature; arm 1 alone is not deployable without GPO allowlisting.

**4. How to evade it**

- An attacker with SYSTEM can patch the running EventLog service in memory (for example the Invoke-Phant0m thread-killing technique) and stop logging without touching the registry, a tool or the audit policy.
- Tampering that happens before Sysmon or audit policy is enabled is invisible by definition.
- Clearing the log entirely is a different, louder action - see the T1685.005 rule.
- Many other logging controls exist (ETW patching, AMSI bypass, WMI subscription removal) and are not covered.
- Renaming auditpol.exe or wevtutil.exe defeats arm 3's process-name match.

References: <https://attack.mitre.org/techniques/T1685/001/>

