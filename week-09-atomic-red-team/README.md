# Week 9 — Atomic Red Team · Assignment 5

Syllabus tasks:
1. Run selected atomic tests (example: T1059, T1003).
2. Record and analyse the results in a SIEM.

I installed Red Canary's Invoke-AtomicRedTeam on my Kali VM, looked up the real atomic tests for my techniques and ran the Linux ones (T1105, T1082, T1136.001). I also planned 14 Windows tests for Amadey's techniques plus the syllabus examples.

## Files

- [`01-atomic-red-team.md`](01-atomic-red-team.md) — what Atomic Red Team is, how I installed it, safety rules
- [`02-test-plan.md`](02-test-plan.md) — the 14 Windows tests and predictions
- [`03-siem-analysis.md`](03-siem-analysis.md) — how I export and score Windows results
- [`04-results.md`](04-results.md) — task 1 + 2: the real Kali run and its analysis
- [`data/w9-exec-log.csv`](data/w9-exec-log.csv) — Invoke-AtomicTest execution log
- [`evidence/`](evidence/) — screenshots of the install, `-ShowDetails` and the runs
- [`queries/`](queries/) — `w9_run_events.esql`, `w9_alerts.esql`
- [`scripts/`](scripts/) — `build_test_plan.py`, `score_atomic_run.py`
- [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv) — fill by hand if needed
- [`navigator/w9_test_plan_layer.json`](navigator/w9_test_plan_layer.json) — predicted layer

## Short summary

- Real run on Kali: T1105-27, T1082-3, T1082-8, T1136.001-1 all worked (exit 0) and were cleaned up. T1105-1 failed (needs a remote host).
- SIEM result: None. My Elastic lab only gets Windows logs, so the Kali runs never reached it. Linux log collection is the fix.
- Windows plan: 14 tests, predicted 5 detected at technique level, 9 only seen in logs. Not run (no Windows host).
- Scorer self-test: 12/12 pass.

## How to run

```bash
cd week-09-atomic-red-team/scripts
python build_test_plan.py
python score_atomic_run.py --selftest
python score_atomic_run.py --runlog <ExecutionLog.csv> --events <events.csv> --alerts <alerts.csv>   # after the lab run
```

← [Project overview](../README.md) · previous: [Week 8](../week-08-adversary-emulation/) · next: [Week 10](../week-10-apt-techniques/)
