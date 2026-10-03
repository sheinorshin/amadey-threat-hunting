# 3. Lab exercise — simulate T1053.005 and record what the SIEM sees

> **Syllabus task 2:** *Simulate an attack and map results to ATT&CK tactics and techniques.*
> Script: [`lab/ith-w6-task-exercise.ps1`](lab/ith-w6-task-exercise.ps1) · export query: [`queries/w6_exercise_events.esql`](queries/w6_exercise_events.esql) · mapper: [`scripts/map_results.py`](scripts/map_results.py)

## 3.1 Goal and research questions

The exercise reproduces the **technique** (a scheduled task that re-runs every minute from a user-writable folder) with a **harmless action**, so I can see the telemetry my lab produces and map it to ATT&CK. It is a *purple-team* style test: I know exactly what was done and when (ground truth), so every event and every detection result can be checked against it.

| # | Question | Answered by |
|---|---|---|
| RQ1 | Which events does my lab record when a scheduled task is created, runs and is deleted? | observation table per method |
| RQ2 | Do my detections fire for **both** ways of creating the task — `schtasks.exe` (Amadey v3/v4 style) and an API/cmdlet (no `schtasks.exe`, like Amadey v5's COM call)? | detection matrix |
| RQ3 | Does the telemetry map to the ATT&CK techniques I expect (T1053.005, T1059.001, T1059.003)? | expected vs observed Navigator layer |

## 3.2 Safety and scope

- **Lab VM only** (the Windows Server VM that ships logs to my Elastic stack). Nothing is downloaded; no malware is involved.
- The task's action is a one-line `.cmd` that appends a timestamp to `C:\Users\Public\ITH-W6\heartbeat.log`.
- Everything is named **`ITH-W6`** — easy to find, impossible to confuse with real activity.
- **Cleanup is automatic** (in a `finally` block): both tasks are unregistered and the folder is deleted, even if the script is interrupted with an error.
- The script only **checks** logging settings; it never changes system configuration.

## 3.3 What the script does

| Step | Method A — `schtasks.exe` | Method B — PowerShell cmdlets |
|---|---|---|
| setup | write `C:\Users\Public\ITH-W6\ith-w6-heartbeat.cmd` | (same file) |
| create | `schtasks /Create /SC MINUTE /MO 1 /TN ITH-W6-Exercise-A /TR "cmd.exe /c …heartbeat.cmd" /F` | `Register-ScheduledTask ITH-W6-Exercise-B` — trigger once + repeat every 1 min for 10 min |
| fire | wait 150 s → the task runs ≥ 2 times | wait 150 s → the task runs ≥ 2 times |
| delete | `schtasks /Delete /TN ITH-W6-Exercise-A /F` | `Unregister-ScheduledTask ITH-W6-Exercise-B` |
| ground truth | every step → UTC start/end + ATT&CK ID in `w6_run_log_<host>_<time>.csv` | |

## 3.4 Before you run it (one-time logging settings, admin)

| Setting | Why | Command |
|---|---|---|
| Audit *Other Object Access Events* (success) | Security **4698** created / **4699** deleted / **4702** updated | `auditpol /set /subcategory:"Other Object Access Events" /success:enable` |
| TaskScheduler/Operational log enabled | **106 / 140 / 141 / 200 / 201** | `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true` |
| Command line in 4688 | `schtasks.exe` command line for the Week 3 Sigma rule | GPO *Include command line in process creation events* (already on in my lab) |
| PowerShell Script Block Logging | **4104** for Method B | already on in my lab (Week 2) |
| Elastic Agent collects TaskScheduler/Operational | events reach `logs-*` | Custom Windows Event Log integration (Week 2) |

The script warns if the first two are missing.

## 3.5 Run → export → map

```powershell
# on the lab VM, in an elevated PowerShell
cd <repo>\week-06-attack-framework\lab
powershell -ExecutionPolicy Bypass -File .\ith-w6-task-exercise.ps1      # ~6 min, prints the run-log path
```

1. Kibana → Discover → **ES|QL** → paste [`queries/w6_exercise_events.esql`](queries/w6_exercise_events.esql) → set the time range to cover the run → export the result as **CSV** (Discover's CSV export, or `POST /_query?format=csv` with the same query).
2. Copy the CSV and the `w6_run_log_*.csv` next to the repo, then:

```bash
cd week-06-attack-framework/scripts
python map_results.py --events <export.csv> --runlog <w6_run_log_HOST_TIME.csv>
# -> results/w6_results.md, results/w6_results.json, navigator/t1053_005_observed_layer.json
```

3. Screenshots for the defense (save in `evidence/`): the script output, Kibana with the ES|QL results, the 4698 event with its `TaskContent` (`PT1M`), and the observed layer in the Navigator.

`python map_results.py --selftest` checks the mapping logic on built-in sample events (6 checks) without touching any files.

## 3.6 Expected telemetry (prediction, written before the run)

| Event | Source | Method A | Method B | Maps to |
|---|---|---|---|---|
| 4688 `powershell.exe … ith-w6-task-exercise.ps1` | Security | ✓ | ✓ | T1059.001 |
| 4104 script block (the whole `.ps1`, incl. `Register-ScheduledTask`) | PowerShell/Operational | ✓ (logged once at start) | ✓ | T1059.001 |
| 4688 `schtasks.exe /Create /SC MINUTE /MO 1 …` | Security | **✓** | **✗ — no schtasks.exe** | T1053.005 |
| **4698** task created, `TaskContent` with `<Interval>PT1M</Interval>` | Security | ✓ | ✓ | T1053.005 |
| **106** task registered | TaskScheduler/Operational | ✓ | ✓ | T1053.005 |
| 200 / 201 action started / completed (×2–3) | TaskScheduler/Operational | ✓ | ✓ | T1053.005 |
| 4688 `cmd.exe /c …heartbeat.cmd`, **parent `svchost.exe`** (×2–3) | Security | ✓ | ✓ | T1053.005 (Execution) + T1059.003 |
| 4699 / 141 task deleted | Security / TaskScheduler | ✓ | ✓ | cleanup (no technique) |

## 3.7 Mapping rules used by `map_results.py`

| Rule | Technique | Tactic(s) |
|---|---|---|
| `schtasks.exe` with `/Create`; 4698; 4702; 106; 140; 100/102/129/200/201 for an `ITH-W6` task | T1053.005 Scheduled Task | Execution, Persistence, Privilege Escalation |
| `cmd.exe` running the heartbeat with parent `svchost.exe` (Task Scheduler) | T1053.005 + T1059.003 Windows Command Shell | Execution (+ the three above) |
| `powershell.exe` 4688; 4104 script blocks | T1059.001 PowerShell (+ T1053.005 if the block contains `Register-ScheduledTask`) | Execution |
| deletes (4699, 141, `schtasks /Delete`, `Unregister-ScheduledTask`) | — (cleanup) | — |

Events are assigned to Method A or B by **task name** first, then by the **time window** from the ground-truth log — exactly how a purple team lines up red-team notes with blue-team logs.

## 3.8 Detections tested

| ID | Detection | Logic | Prediction |
|---|---|---|---|
| W3-SIGMA | Week 3 Sigma `proc_creation_win_amadey_schtasks_every_minute` | 4688 `schtasks.exe` + `/Create` `/SC MINUTE` `/MO 1` `/TR` + user-writable path | A ✅ · **B ✗** |
| W5-H2b | Week 5 hunt H2, query (2) | 4688 `schtasks.exe` with `/sc minute` and `/mo 1` | A ✅ · **B ✗** |
| W5-H2c | Week 5 hunt H2, query (3) | **4698** whose `TaskContent` contains `PT1M` | A ✅ · B ✅ |

The Week 5 H2 *confirmation* (hex-named EXE + every-minute task on one host) is not expected to fire — the exercise deliberately has no hex-folder EXE, so it tests the task part on its own.
