# Week 9 — Atomic Red Team · Assignment 5

Syllabus tasks:
1. Run selected atomic tests (example: T1059, T1003).
2. Record and analyse the results in a SIEM.

I planned 14 atomic tests for Amadey's techniques plus the syllabus examples. I run them on my lab VM; this folder has the plan, the export queries and a script that scores the results.

## Files

- [`01-atomic-red-team.md`](01-atomic-red-team.md) — what Atomic Red Team is, safety rules
- [`02-test-plan.md`](02-test-plan.md) — task 1: the 14 tests and predictions
- [`03-siem-analysis.md`](03-siem-analysis.md) — task 2: how I export and score the results
- [`04-results.md`](04-results.md) — results (after the lab run)
- [`queries/`](queries/) — `w9_run_events.esql`, `w9_alerts.esql`
- [`scripts/`](scripts/) — `build_test_plan.py`, `score_atomic_run.py`
- [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv) — fill by hand if needed
- [`navigator/w9_test_plan_layer.json`](navigator/w9_test_plan_layer.json) — predicted layer

## Short summary

- 14 tests, all on techniques also used by APT29 or APT41 (Week 10).
- Prediction: 5 detected at technique level, 9 only seen in logs, 0 missed.
- Scorer self-test: 12/12 pass.
- Ran on Kali: the scorer self-test (12/12 PASS) and the test plan. Detonating the atomic tests needs a Windows host, so the real run is out of scope.

## How to run

```bash
cd week-09-atomic-red-team/scripts
python build_test_plan.py
python score_atomic_run.py --selftest
python score_atomic_run.py --runlog <ExecutionLog.csv> --events <events.csv> --alerts <alerts.csv>   # after the lab run
```

← [Project overview](../README.md) · previous: [Week 8](../week-08-adversary-emulation/) · next: [Week 10](../week-10-apt-techniques/)
