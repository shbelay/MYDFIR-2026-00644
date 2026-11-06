# KCD-Web Potential Malware / Ransomware Activity

**Case ID:** `MYDFIR-2026-00644`  
**Alert:** Potential Malware Detected on an Endpoint  
**Investigation date:** August 28, 2026  
**Affected host:** `KCD-Web` (`172.16.1.7`)  
**Account:** `KCD-Web\administrator`  
**Severity:** High  
**Conclusion:** True Positive  
**Tools / evidence:** Splunk, Sysmon, Windows Security logs  
**Time zone:** UTC (investigation timeline)

## Executive Summary

On August 28, 2026, an external system at `91.99.176.42` connected to `KCD-Web` over RDP (TCP/3389), followed by successful `administrator` logons, including a RemoteInteractive (Type 10) logon at approximately 08:58:26 UTC. At 08:59:40, `dControl.exe` appeared in the administrator's Pictures directory and executed at 09:00:04. The process modified Microsoft Defender service and policy registry settings and was followed by activity involving `screenconnect.exe` and `Stub.exe`.

At 09:00:55, `Stub.exe` ran defense evasion commands that included Volume Shadow Copy deletion and Windows boot recovery configuration changes. It also modified Defender protection settings, targeted Recycle Bin contents, and set a Run-key persistence value. At 09:01:00, it created `C:\PerfLogs\DataRecovery.txt` that may have been a ransom/recovery note.

## Investigation Timeline

| Time (UTC), Aug 28, 2026 | Evidence / event | Significance |
|---|---|---|
| 08:58:18 | TCP connection from `91.99.176.42:58209` to `172.16.1.7:3389` | External RDP connectivity |
| 08:58:21 | Successful `administrator` network logon (Type 3) | Authenticated network access |
| 08:58:26 | Successful `administrator` RemoteInteractive logon (Type 10) | RDP session established |
| 08:59:40 | `dControl.exe` created | Suspicious executable staged shortly after RDP |
| 09:00:04 | `dControl.exe` executed, with `explorer.exe` as parent | Interactive-session-associated execution |
| ~09:00:08–09:00:11 | Temporary files, Defender registry modifications, `Registry.pol` activity | Defense evasion / policy modification |
| 09:00:13 | `dControl.exe` terminated | End of observed process instance |
| ~09:00:20 | `screenconnect.exe` created/executed | Additional suspicious executable activity |
| ~09:00:38 | `Stub.exe` created | Next-stage payload staged |
| 09:00:55 | `Stub.exe` executed; shadow-copy deletion, recovery and Defender changes | Ransomware-associated recovery inhibition |
| 09:00:57 | User Run-key value set to `Stub.exe` | Persistence |
| 09:01:00 | `C:\PerfLogs\DataRecovery.txt` created | Possible ransom/recovery note |

## Detailed Findings

### 1. External RDP Access

Sysmon network telemetry showed a connection from `91.99.176.42` to `KCD-Web` on TCP/3389. Windows Security Event ID **4624** showed successful logons for `administrator` that were Type 3 and Type 10 events.

```spl
index=* host=KCD-Web earliest="8/28/2026:08:00:00" latest="8/28/2026:09:00:00" src_ip=91.99.176.42
| sort + _time
| table _time host EventCode user src_ip dest_ip dest_port Logon_Type
```

### 2. Staging and Execution of `dControl.exe`

Sysmon Event ID **11** recorded creation of:

```text
C:\Users\administrator\Pictures\dcontrol\dControl.exe
```

The executable appeared at approximately **08:59:40** and executed at **09:00:04**, with `C:\Windows\Explorer.EXE` as its parent.

```spl
index=* host="KCD-Web" earliest="8/28/2026:08:00:00" dControl.exe EventCode=11
| table UtcTime host User TargetFilename action process_path process_guid
| sort + UtcTime
```

The investigation pivoted on Sysmon `ProcessGuid` to follow related process, file, and registry events rather than relying only on filenames:

```spl
index=* {587438d6-4db8-6a91-dc20-000000000a00}
| table _time EventCode EventDescription ParentImage process_path TargetFilename action
| sort + _time
```

### 3. Microsoft Defender Tampering

Registry events associated with `dControl.exe` showed service/driver `Start` values set to `4` (Disabled) for:

```text
HKLM\System\CurrentControlSet\Services\WdFilter\Start
HKLM\System\CurrentControlSet\Services\WdNisSvc\Start
HKLM\System\CurrentControlSet\Services\WinDefend\Start
```

Defender policy values `DisableAntiVirus` and `DisableAntiSpyware` were set to `1` (Enabled / True) under:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\
```

There was several creation of temporary files in `C:\Windows\Temp`, creation/modification of `C:\Windows\System32\GroupPolicy\Machine\Registry.pol`, and an Image File Execution Options (IFEO) `Debugger` value for `MpCmdRun.exe` pointing to `C:\Windows\System32\systray.exe`. Together, these were strong indicators of attempted security-control impairment.

```spl
index=* {587438d6-4e18-6a91-3021-000000000a00}
| table UtcTime EventCode EventDescription User process_path process_name CommandLine TargetFilename registry_path registry_value_name registry_value_data action
| sort + UtcTime
```

### 4. Additional Executables

Subsequent events identified:

```text
C:\Users\administrator\Pictures\dcontrol\screenconnect.exe
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

`screenconnect.exe` was created/executed, but the investigation did not establish its functionality or further activity. `Stub.exe` was created around **09:00:38** and executed around **09:00:55**.

### 5. `Stub.exe`: Recovery Inhibition and Defense Evasion

`Stub.exe` was associated with commands including:

```cmd
vssadmin Delete Shadows /All /Quiet
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No
```

These commands target Windows Volume Shadow Copies and boot recovery behavior, which can make recovery from an attack more difficult. Additional activity included shadow-copy-related `wmic` usage and `rd /s /q` targeting `$RECYCLE.BIN` / `Recycler` directories. Registry modifications targeted Defender settings including:

- `DisableIOAVProtection`
- `DisableOnAccessProtection`
- `DisableScanOnRealtimeEnable`
- `DisableBehaviorMonitoring`
- `DisableRealtimeMonitoring`

These behaviors, considered together, strongly support a ransomware-related preparation or execution stage.

```spl
index=* host="KCD-Web" "Stub.exe" earliest="8/28/2026:09:00:30" latest="8/28/2026:09:10:00" (EventCode=1 OR EventCode=5 OR EventCode=11 OR EventCode=13)
| sort + _time
| table _time EventCode EventDescription User ParentImage process_name process_path CommandLine TargetFilename registry_path registry_value_name registry_value_data action
```

### 6. Persistence

At 09:00:57, a Run-key value was configured to point to `Stub.exe`:

```text
HKU\S-1-5-21-3772984715-3855048566-1297946058-1001\Software\Microsoft\Windows\CurrentVersion\Run\61E52490E32E7D80
```

This is a persistence mechanism designed to launch the executable at a user logon.

### 7. Suspected Ransom/Recovery Note

At approximately **09:01:00**, Sysmon Event ID **11** associated `Stub.exe` with creation of:

```text
C:\PerfLogs\DataRecovery.txt
```

The filename and timing, after shadow-copy deletion and recovery changes, make it a suspected ransom/recovery note. 

## Attack Sequence

```text
91.99.176.42 → TCP/3389 → KCD-Web (172.16.1.7)
    └── administrator successful RDP logon (Type 10)
         └── explorer.exe → dControl.exe
              ├── Defender service/policy tampering
              ├── Registry.pol / temporary-file activity
              ├── screenconnect.exe observed
              └── Stub.exe
                   ├── Volume Shadow Copy deletion
                   ├── Windows recovery configuration changes
                   ├── Defender real-time protection tampering
                   ├── Recycle Bin deletion activity
                   ├── Run-key persistence
                   └── C:\PerfLogs\DataRecovery.txt
```

## Indicators and Artifacts for Hunting

| Type | Value | Context |
|---|---|---|
| External source IP | `91.99.176.42` | RDP source observed in this case |
| Destination IP | `172.16.1.7` | KCD-Web |
| Port | `3389/TCP` | RDP |
| Executable | `C:\Users\administrator\Pictures\dcontrol\dControl.exe` | Initial suspicious executable |
| Executable | `C:\Users\administrator\Pictures\dcontrol\screenconnect.exe` | Additional observed executable; identity unverified |
| Executable | `C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe` | Recovery-inhibition and persistence activity |
| File | `C:\PerfLogs\DataRecovery.txt` | Suspected ransom/recovery note |
| File | `C:\Windows\System32\GroupPolicy\Machine\Registry.pol` | Legitimate file modified in suspicious context |
| Registry value | `61E52490E32E7D80` | Per-user Run-key persistence |
| Registry target | `MpCmdRun.exe` IFEO `Debugger` | Potential Defender utility interference |

## MITRE ATT&CK Mapping

| Technique | ID | Observed basis |
|---|---|---|
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | External RDP access; exposure context not independently validated |
| Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Successful RDP logon |
| Impair Defenses | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender service, policy, and real-time protection tampering |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Defender and persistence registry modifications |
| Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | User Run-key pointing to `Stub.exe` |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | `vssadmin` and `bcdedit` activity |
| System Binary Proxy Execution: Image File Execution Options Injection | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | IFEO Debugger modification affecting `MpCmdRun.exe`; intent/function requires validation |

## Additional Threat Hunting Queries

**Find the RDP source across indexed hosts**

```spl
index=* src_ip="91.99.176.42"
| sort + _time
| table _time host EventCode user src_ip dest_ip dest_port Logon_Type action
```

**Search for related executable activity**

```spl
index=* ("dControl.exe" OR "Stub.exe" OR "screenconnect.exe")
| sort + _time
| table _time host EventCode User ParentImage process_name process_path CommandLine TargetFilename Hashes
```

**Find recovery-inhibition commands**

```spl
index=* ("vssadmin" OR "wmic SHADOWCOPY" OR "recoveryenabled No" OR "ignoreallfailures")
| sort + _time
| table _time host User ParentImage process_name process_path CommandLine
```

**Find the persistence value**

```spl
index=* "61E52490E32E7D80"
| sort + _time
| table _time host EventCode User process_name process_path registry_path registry_value_data
```

**Test for broader file activity (not a confirmed finding)**

```spl
index=* host="KCD-Web" earliest="8/28/2026:09:00:30" latest="8/28/2026:09:30:00" (EventCode=11 OR EventCode=23)
| timechart span=1m count by EventCode
```

**Check for network/DNS activity from the affected host (not a confirmed finding)**

```spl
index=* host="KCD-Web" earliest="8/28/2026:08:45:00" latest="8/28/2026:09:30:00" (EventCode=3 OR EventCode=22)
| table _time EventCode process_name process_path src_ip dest_ip dest_port QueryName process_guid
| sort + _time
```

## Recommended Response Actions

**Containment:** Isolate `KCD-Web`; investigate and restrict the external RDP path; block `91.99.176.42` where appropriate; disable/reset affected administrator credentials and invalidate relevant sessions. Preserve volatile and disk evidence before destructive actions when feasible.

**Eradication:** Quarantine suspicious executables after evidence collection; remove unauthorized Run-key persistence; inspect the IFEO Debugger value and `Registry.pol`; restore Defender service, policy, and real-time protection settings; hunt for the same artifacts across other systems.

**Recovery:** Validate backup integrity and Windows recovery settings; rebuild the host if its integrity cannot be trusted; monitor the affected account and other hosts for recurrence.

## Final Assessment

**Conclusion: True Positive / Malicious.** Successful external RDP access was followed within minutes by suspicious executable activity, Defender impairment attempts, Run-key persistence, and recovery-inhibition commands. This is consistent with ransomware activity.
