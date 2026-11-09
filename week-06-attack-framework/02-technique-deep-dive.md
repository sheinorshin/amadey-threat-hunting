# 2. T1053.005 Scheduled Task

Data from ATT&CK v19.2: [`data/attack_profile.json`](data/attack_profile.json).

## Basic facts

- Name: T1053.005 Scheduled Task (part of T1053 Scheduled Task/Job)
- Tactics: Execution, Persistence, Privilege Escalation
- Platform: Windows
- Used by: 190 (115 malware, 54 groups, 12 campaigns, 9 tools), e.g. APT29, APT41, Kimsuky
- Amadey (S1025): **not listed**, even though ASEC, Splunk, Trellix and Microsoft describe it
- Mitigations: M1018, M1026, M1028, M1047
- Detection: DET0441 / AN1221

## How it works

Windows Task Scheduler runs programs at a time, at logon or again and again. The attacker just creates a task that runs their program. No exploit is needed.

A task can be created in different ways:
- `schtasks.exe` — everything is visible on the command line (event 4688)
- PowerShell `Register-ScheduledTask` — no `schtasks.exe` process
- COM API — only the malware process itself

Whatever way is used, Windows logs event **4698** (task created) and TaskScheduler **106**. When the task runs, its process has parent `svchost.exe`.

## Why attackers use it

- Execution — Windows starts the program for them
- Persistence — survives reboot; every-minute repeat restarts the malware
- Privilege Escalation — a task can run as another account

## Amadey's procedure

| Version | What it does |
|---|---|
| v3/v4 | `schtasks.exe` task named like the EXE, every minute (ASEC, Splunk) |
| v5.70 | task `Yfgfwb`, every minute, old `.job` file (Trellix, my VirusTotal check) |
| v5.x | task made through the COM API, no `schtasks.exe` (Microsoft, binaryanalys.is) |

## What I found

1. Amadey is missing from T1053.005 in ATT&CK.
2. My Week 3 Sigma rule only checks the `schtasks.exe` command line, so it would miss Amadey v5. Event 4698 catches both ways.

## Can my lab see it?

- Security 4698 / 4702 — yes (needs "Audit Other Object Access Events")
- Process creation — yes, 4688 instead of Sysmon 1
- Sysmon 11 / 13 — no, Sysmon is not installed

The ATT&CK mitigations are about admin rights, so they don't stop Amadey's normal-user task. Better: block programs in user folders (AppLocker) and alert on 4698.
