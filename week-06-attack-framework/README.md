# Week 6 — MITRE ATT&CK Framework

Syllabus tasks:
1. Study one ATT&CK technique (example: T1059).
2. Simulate an attack and map the results to ATT&CK.

I picked **T1053.005 Scheduled Task**, because Amadey uses an every-minute scheduled task to stay on the PC (also used in my Week 3 rule and Week 5 hunt). T1059 is covered too.

## Files

- [`01-attack-framework.md`](01-attack-framework.md) — ATT&CK basics, T1059, Navigator
- [`02-technique-deep-dive.md`](02-technique-deep-dive.md) — task 1: T1053.005
- [`03-lab-exercise.md`](03-lab-exercise.md) — task 2: the lab test
- [`04-results-and-mapping.md`](04-results-and-mapping.md) — ATT&CK mapping and results
- [`lab/ith-w6-task-exercise.ps1`](lab/ith-w6-task-exercise.ps1) — lab script (harmless task, deletes itself)
- [`queries/w6_exercise_events.esql`](queries/w6_exercise_events.esql) — Kibana export query
- [`scripts/`](scripts/) — `build_attack_profile.py` (ATT&CK data), `map_results.py` (maps results)
- [`navigator/`](navigator/) — expected layer (observed layer comes after the lab run)

## Short summary

- T1053.005 has 3 tactics: Execution, Persistence, Privilege Escalation.
- ATT&CK lists 190 users of it, but not Amadey.
- My Week 3 rule only catches tasks made with `schtasks.exe`. Amadey v5 makes its task through COM, so I also need event 4698.
- Ran on Kali: the scripts (self-test 6/6 PASS) and, in Elasticsearch, the T1053.005 telemetry (the 4698 event with `PT1M`) on the synthetic dataset. The Windows task test (`ith-w6-task-exercise.ps1`) is out of scope — no Windows host.

## How to run

```bash
cd week-06-attack-framework/scripts
python build_attack_profile.py
python map_results.py --selftest
python map_results.py --events <export.csv> --runlog <w6_run_log.csv>   # after the lab run
```

← [Project overview](../README.md) · previous: [Week 5](../week-05-threat-hunting/) · next: [Week 7](../week-07-mitre-car/)
