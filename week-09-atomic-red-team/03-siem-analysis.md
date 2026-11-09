# 3. Analysing the results in the SIEM

## Before the run

- Process creation with command line (4688) and PowerShell logging (4104) — on since Week 2.
- 4698 auditing and TaskScheduler log — see Week 6 lab test, file 03.
- 4720/4732 (accounts) and 4946 (firewall) are logged.
- Week 7 Kibana rules imported and enabled.
- VM clock correct (`w32tm /query /status`).

## Export after the run

1. Invoke-AtomicTest writes `%TEMP%\Invoke-AtomicTest-ExecutionLog.csv` (time, technique, test, PID). If you run tests by hand, fill [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv) instead.
2. Kibana → Discover → ES|QL → [`queries/w9_run_events.esql`](queries/w9_run_events.esql), time from 1 min before the first test to 5 min after the last, your host name → export CSV.
3. Same with [`queries/w9_alerts.esql`](queries/w9_alerts.esql) (end time +10 min).
4. Run:

```bash
python scripts/score_atomic_run.py --runlog Invoke-AtomicTest-ExecutionLog.csv --events w9_events.csv --alerts w9_alerts.csv
```

## What the scorer does

- Links each event to its test by time window and process tree (the test's PID).
- Maps each event to ATT&CK (e.g. 4698 → T1053.005, 4720 → T1136.001, 4946 → T1686).
- Re-checks my Week 3, 5 and 7 rules on the events and compares with real Kibana alerts.
- Gives each test a grade: None (nothing in SIEM), Telemetry (logs, no alert), General / Tactic (alert, but not for this technique), Technique (alert for this technique).
- Writes `results/w9_results.md` and the observed Navigator layer.

`python scripts/score_atomic_run.py --selftest` checks the scorer on sample events: 12/12 pass.

## What to keep

The execution log, the two CSV exports, screenshots of the ES|QL result and the alerts, and the results file.
