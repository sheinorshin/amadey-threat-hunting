# 4. Results and ATT&CK mapping

> **Status:** the analysis, the expected mapping and the tooling are complete. The **observed** results come from one run of the lab exercise on my Windows VM ([`03-lab-exercise.md`](03-lab-exercise.md) §3.5); `scripts/map_results.py` then writes `results/w6_results.md` and the observed Navigator layer. Nothing in this file is presented as observed until that run exists.

## 4.1 ATT&CK mapping of the simulated attack (expected)

| Step of the exercise | Tactic(s) | Technique | Sub-technique | Evidence I expect in the SIEM |
|---|---|---|---|---|
| Operator runs the exercise script | Execution | T1059 Command and Scripting Interpreter | **T1059.001 PowerShell** | 4688 `powershell.exe`, 4104 script block |
| Task created with `schtasks.exe` (Method A) | Execution · Persistence · Privilege Escalation | T1053 Scheduled Task/Job | **T1053.005 Scheduled Task** | 4688 `schtasks.exe /Create …`, 4698, 106 |
| Task created with `Register-ScheduledTask` (Method B) | Execution · Persistence · Privilege Escalation (+ Execution via PowerShell) | T1053 + T1059 | **T1053.005** + **T1059.001** | 4104, 4698, 106 — **no** `schtasks.exe` |
| Task fires every minute | Execution · Persistence | T1053 + T1059 | **T1053.005** + **T1059.003 Windows Command Shell** | 200/201, 4688 `cmd.exe` with parent `svchost.exe` |
| Cleanup | — | — | — | 4699, 141 (not mapped: defender-side housekeeping) |

**3 techniques, 3 tactics** — the same techniques Amadey uses in Kill Chain phase 5 (Week 4), minus the malicious payload. Navigator: [`navigator/t1053_005_lab_exercise_layer.json`](navigator/t1053_005_lab_exercise_layer.json) ([open in the Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fsheinorshin%2Famadey-threat-hunting%2Fmain%2Fweek-06-attack-framework%2Fnavigator%2Ft1053_005_lab_exercise_layer.json)).

## 4.2 Predictions to confirm or reject

| # | Prediction (from the deep-dive) | Confirmed if … |
|---|---|---|
| P1 | Service-side events (4698, 106, 200/201) appear for **both** methods | both method sections in `w6_results.md` list them |
| P2 | `schtasks.exe` appears **only** for Method A | no `4688 schtasks.exe /Create` under Method B |
| P3 | Week 3 Sigma + Week 5 H2b fire on A, **not** on B | detection matrix: A ✅, B — |
| P4 | Week 5 H2c (4698 + `PT1M`) fires on **both** | detection matrix: A ✅, B ✅ |
| P5 | The task's runs are child processes of `svchost.exe` | `4688 cmd.exe started by Task Scheduler` under both methods |

If **P3** holds, it confirms *Gap 2* from the deep-dive with real telemetry: a command-line rule alone would miss an Amadey v5-style (API-created) task, and the 4698-based logic must become a standing detection.

## 4.3 Observed results

*Filled from `results/w6_results.md` after the lab run:*

| | Method A | Method B |
|---|---|---|
| Events captured | — | — |
| Techniques observed | — | — |
| Detections fired | — | — |
| Predictions P1–P5 | — | — |

## 4.4 What happens next with the results

| If … | Then … | Week |
|---|---|---|
| P3 + P4 confirmed | promote the 4698/`PT1M` hunt to a Sigma rule (logsource `windows/security`, EventID 4698) next to the Week 3 command-line rule | 7 (CAR → SIEM) |
| 106/200 missing | TaskScheduler/Operational not collected → fix the Custom Windows Event Log integration | now |
| 4698 missing | audit policy not applied → `auditpol` / GPO | now |
| all as predicted | reuse the exercise as the persistence step of the emulation plan | 8, 9 |

Week 7's CAR analytic and Week 9's Atomic Red Team tests for T1053.005 will run against the same logging, so this exercise doubles as the **baseline** for those weeks.
