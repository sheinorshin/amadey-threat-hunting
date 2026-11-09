# 4. Results

Waiting for the lab run. After it, `score_atomic_run.py` writes `results/w9_results.md`, and I fill this table.

| ID | Technique | Predicted | Real |
|---|---|---|---|
| A1 | T1059.001 PowerShell | Telemetry | |
| A2 | T1059.003 Windows Command Shell | Telemetry | |
| A3 | T1053.005 Scheduled Task | Technique | |
| A4 | T1105 Ingress Tool Transfer | Telemetry | |
| A5 | T1136.001 Local Account | Technique | |
| A6 | T1686 Firewall rule | Technique | |
| A7 | T1218.011 Rundll32 | Telemetry | |
| A8 | T1082 System Information Discovery | Telemetry | |
| B1 | T1059.007 JavaScript | Technique | |
| B2 | T1218.005 Mshta | Technique | |
| B3 | T1547.001 Run key | Telemetry | |
| B4 | T1112 Modify Registry | Telemetry | |
| C1 | T1003.002 SAM | Telemetry | |
| C2 | T1003.001 LSASS | Telemetry | |

Predicted: 14/14 visible, 5/14 (36 %) detected at technique level.

## What I do with the results

- A test with no logs → fix the logging first (audit policy, log not collected).
- A rule fires in the scorer but not in Kibana → the rule is off or uses the wrong index/field.
- Predictions 6 and 8 true → install Sysmon and run B3, B4, C2 again.
- C1 only Telemetry → add a rule for `reg save hklm\sam` (APT29 and APT41 use it).
