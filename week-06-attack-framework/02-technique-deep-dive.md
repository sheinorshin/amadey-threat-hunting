# 2. Technique deep-dive — T1053.005 Scheduled Task

> **Syllabus task 1:** *Study one specific technique (e.g. T1059).*
> Facts in the tables are generated from the ATT&CK v19.2 STIX bundle → [`data/attack_profile.json`](data/attack_profile.json). The Amadey and lab parts link back to Weeks 1–5.

## 2.1 Identity card

| Field | Value (ATT&CK v19.2) |
|---|---|
| ID / name | **T1053.005 Scheduled Task** — sub-technique of **T1053 Scheduled Task/Job** |
| Tactics | **Execution** (TA0002) · **Persistence** (TA0003) · **Privilege Escalation** (TA0004) |
| Platform | Windows |
| Object version | 1.8 — created 2019-11-27, last modified 2026-05-12 |
| Procedure examples | **190** = 115 malware · 54 groups · 12 campaigns · 9 tools |
| Mitigations | M1018 User Account Management · M1026 Privileged Account Management · M1028 Operating System Configuration · M1047 Audit |
| Detection | **DET0441** *Detection of Suspicious Scheduled Task Creation and Execution on Windows* → analytic **AN1221** |
| Amadey (S1025) listed? | **No** — although four vendor reports and my own sandbox review document it (see 2.5) |

**Siblings under T1053:** T1053.002 At (Windows/Linux/macOS), T1053.003 Cron, T1053.006 Systemd Timers, T1053.007 Container Orchestration Job. T1053.001 *At (Linux)* is revoked (merged into .002) and T1053.004 *Launchd* is deprecated. T1053 itself was called *Scheduled Task* until v7; the old *Local Job Scheduling* technique (T1168) was revoked into it.

## 2.2 What the technique is

Windows has a built-in service — **Task Scheduler** (the `Schedule` service, hosted in `svchost.exe`) — that starts programs at a time, at logon/boot, on an event, or repeatedly. A task is a definition (trigger + action + account) stored as XML under `C:\Windows\System32\Tasks\` and indexed in the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`). The adversary does not need an exploit: they register a task whose **action** is their program.

**Ways a task gets created** — and why it matters for detection:

| Interface | Creating process the SIEM sees | Notes |
|---|---|---|
| `schtasks.exe` | `schtasks.exe` with the full definition on its **command line** | easiest to detect from 4688 / Sysmon 1 |
| PowerShell `ScheduledTasks` module (`Register-ScheduledTask`) | `powershell.exe` — **no `schtasks.exe`** | visible in PowerShell 4104 script blocks |
| Task Scheduler COM API (2.0, or the legacy 1.0 API) | the program itself — **no helper process at all** | legacy 1.0 also leaves a `.job` file in `C:\Windows\Tasks\` |
| WMI / CIM, .NET wrappers, GUI | `WmiPrvSE.exe`, the program, `mmc.exe` | |

Whatever the interface, the **Task Scheduler service** registers the task — so the service-side events (Security **4698**, TaskScheduler/Operational **106**) and the task's later runs (**200/201**, process with parent `svchost.exe`) appear **regardless of how it was created**. That is the key insight for the Week 6 lab exercise.

## 2.3 Why adversaries use it — one technique, three tactics

| Tactic | How a scheduled task serves it |
|---|---|
| **Execution** | run code now or at a chosen moment, launched by a trusted Windows service rather than by the attacker's process |
| **Persistence** | the task survives reboots and logoffs; a short repetition interval also *restarts* the implant if it is killed |
| **Privilege Escalation** | a task can run as another account (e.g. SYSTEM) if the creator has the rights |

## 2.4 Who uses it (procedure examples)

ATT&CK lists **190** users of T1053.005 — one of the most widely used persistence techniques. The **54 groups** include APT29 and APT41 (Week 10's case studies) and Kimsuky (one of Amadey's own users per S1025). Reading the procedure text shows recurring patterns:

- a **short repetition interval** (13 descriptions mention minutes, typically every 1–10 minutes) as a watchdog that restarts the implant — exactly Amadey's choice;
- task **names imitating legitimate software updates** to blend in;
- the creation interface is often **not stated**: `schtasks` is named in only 22 of the 190 procedure descriptions (PowerShell in 5, the COM API in 1) — so a detection cannot assume that every malicious task comes from a `schtasks.exe` command line.

## 2.5 Amadey's procedure — and the gap in ATT&CK

| Version | Procedure (documented) | Source |
|---|---|---|
| v3.21 (2022) | task named after the dropped EXE, repeating **every minute**, created with `schtasks.exe` | AhnLab ASEC |
| v3.83 (2023) | scheduled task for persistence (`metado.exe` in Splunk's lab test); can run with higher privileges if task permissions are misconfigured | Splunk Threat Research |
| v5.70 (2025) | task `Yfgfwb`, every minute; legacy `.job` file `C:\Windows\Tasks\Yfgfwb.job` (confirmed in my VirusTotal sandbox review, Week 2) | Trellix + VirusTotal |
| v5.x (2025–26) | task created through the Task Scheduler **COM interface (v1.0 API)**; removed again by the self-uninstall command | binaryanalys.is, Microsoft |

**Gap 1 — in ATT&CK:** S1025 lists 17 techniques; T1053.005 is not among them, even though it is Amadey's most stable behaviour across versions. A procedure entry for S1025 (citing ASEC, Splunk, Trellix, Microsoft) would be a legitimate ATT&CK contribution.

**Gap 2 — in my own detections:** my Week 3 Sigma rule matches the `schtasks.exe` command line — that fits v3/v4, but **v5 creates the task through COM, with no `schtasks.exe` process**. Only service-side evidence (4698 / 106 / the every-minute runs) sees both. The lab exercise tests exactly this with two creation methods.

## 2.6 Detection — what ATT&CK recommends vs what my lab has

**AN1221** (Windows): *creation, modification or deletion of scheduled tasks through Task Scheduler, WMI, PowerShell or API-based methods, followed by execution from svchost.exe/taskeng.exe; includes hidden or anomalous tasks.*

| AN1221 log source | Data component | My lab today |
|---|---|---|
| Security **4698** (task created) | DC0001 Scheduled Job Creation | ✅ needs *Audit Other Object Access Events* |
| Security **4702** (task updated) | DC0012 Scheduled Job Modification | ✅ same audit setting |
| Sysmon **1** (process creation) | DC0032 Process Creation | ⚠️ no Sysmon — Security **4688** with command line instead |
| Sysmon **11** (file created, e.g. task XML / `.job`) | DC0039 File Creation | ⚠️ needs Sysmon |
| Sysmon **13/14** (registry, TaskCache) | DC0063 Windows Registry Key Modification | ⚠️ needs Sysmon |

Extra telemetry not named in AN1221 but useful: **TaskScheduler/Operational** 106 (registered), 140 (updated), 141 (deleted), 200/201 (action started/completed) — collected by my Custom Windows Event Log integration once the log is enabled; Security **4699** (deleted).

**AN1221's tunable elements, applied to Amadey:**

| Tunable | My setting for Amadey |
|---|---|
| `TimeWindow` | task creation → first run within ~1–2 minutes (every-minute trigger) |
| `UserContext` | task created by a normal user, action in a **user-writable path** |
| `TaskNamePattern` | random lowercase name that **equals the action's EXE name** |
| `CommandLineEntropyThreshold` | not needed — Amadey's action is a plain EXE path |

## 2.7 Mitigations (ATT&CK) — and what actually helps against Amadey

| ID | ATT&CK guidance (summary) | Effect on Amadey |
|---|---|---|
| M1018 User Account Management | only authorised admins may create tasks on *remote* systems | low — Amadey creates a local task as the user |
| M1026 Privileged Account Management | restrict *Increase scheduling priority* to Administrators (GPO) | low |
| M1028 Operating System Configuration | force tasks to run as the authenticated account, not SYSTEM (`SubmitControl`) | low — Amadey doesn't need SYSTEM |
| M1047 Audit | audit tasks for permission weaknesses (e.g. PowerUp) | medium — periodic task inventory finds every-minute tasks |

The listed mitigations target **privilege abuse**; Amadey's user-level persistence slips past them. What works better (from Week 4's Courses of Action): **block execution from user-writable folders** (AppLocker/WDAC) so the task's action cannot start, plus **detection** on 4698/106 and a regular **task inventory** (every-minute repetition + action in `%TEMP%`/`%APPDATA%`/`C:\Users\Public` = review).

## 2.8 Summary

| Question | Answer |
|---|---|
| What is it? | abuse of Windows Task Scheduler to run code on a schedule / at logon |
| Why does Amadey use it? | cheap, built-in, survives reboots; the every-minute interval restarts it if killed |
| Best evidence? | service-side: **4698** / **106** + task runs with parent `svchost.exe` — independent of the creation interface |
| My blind spot? | command-line-only detection misses API-created tasks (Amadey v5) → tested in [`03-lab-exercise.md`](03-lab-exercise.md) |

### Sources
- MITRE ATT&CK T1053.005 (v1.8), DET0441 / AN1221, M1018 / M1026 / M1028 / M1047 — https://attack.mitre.org/techniques/T1053/005/
- AhnLab ASEC (2022) — https://asec.ahnlab.com/en/36634/ · Splunk (2023) — https://www.splunk.com/en_us/blog/security/amadey-threat-analysis-and-detections.html
- Trellix (Dec 2025) — https://www.trellix.com/blogs/research/amadey-exploiting-self-hosted-gitlab-to-distribute-stealc/ · binaryanalys.is — https://www.binaryanalys.is/posts/amadey · Microsoft (Jun 2026) — https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/
- Microsoft Learn — *schtasks create*, *Audit Other Object Access Events* (4698–4702), Task Scheduler event log
