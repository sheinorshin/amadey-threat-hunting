# 3. Lab test — simulate T1053.005

Script: [`lab/ith-w6-task-exercise.ps1`](lab/ith-w6-task-exercise.ps1)

## Goal

Create a scheduled task like Amadey's (every minute, from a user folder), but harmless. Then check which events my SIEM records and if my rules fire.

## Safety

- Runs only on the lab VM, no malware, nothing downloaded.
- The task only writes a timestamp to `C:\Users\Public\ITH-W6\heartbeat.log`.
- Everything is named `ITH-W6` and is deleted at the end automatically.

## What the script does

- Method A: creates task `ITH-W6-Exercise-A` with `schtasks /Create /SC MINUTE /MO 1`
- Method B: creates task `ITH-W6-Exercise-B` with `Register-ScheduledTask` (no `schtasks.exe`)
- Waits 150 s so each task runs 2–3 times, then deletes it
- Saves a log of every step with time and ATT&CK ID (`w6_run_log_<host>_<time>.csv`)

## Before running (once, as admin)

```
auditpol /set /subcategory:"Other Object Access Events" /success:enable
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

Command line in 4688 and PowerShell logging (4104) are already on from Week 2.

## Run and map

1. On the VM, PowerShell as admin: `powershell -ExecutionPolicy Bypass -File .\ith-w6-task-exercise.ps1` (about 6 min).
2. Kibana → Discover → ES|QL → run [`queries/w6_exercise_events.esql`](queries/w6_exercise_events.esql) for the run's time → export CSV.
3. `python scripts/map_results.py --events <export.csv> --runlog <w6_run_log.csv>`

## Expected events

| Event | A | B |
|---|---|---|
| 4688 `schtasks.exe /Create` | yes | no |
| 4698 task created (with `PT1M`) | yes | yes |
| TaskScheduler 106 / 200 / 201 | yes | yes |
| 4688 `cmd.exe` with parent `svchost.exe` | yes | yes |
| 4104 PowerShell script | yes | yes |

## Rules I test

- Week 3 Sigma rule (schtasks command line) — expected: A yes, B no
- Week 5 H2 query on schtasks — expected: A yes, B no
- Week 5 H2 query on 4698 with `PT1M` — expected: A yes, B yes
