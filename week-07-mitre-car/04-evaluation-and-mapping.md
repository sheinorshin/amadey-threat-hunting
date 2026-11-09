# 4. Testing and ATT&CK mapping

Results from [`scripts/evaluate_car.py`](scripts/evaluate_car.py) → [`data/evaluation.json`](data/evaluation.json).

## Week 5 data (976 events, 1 Amadey task)

| Version | Alerts | False alarms | Amadey found |
|---|---|---|---|
| CAR-2013-08-001 (baseline) | 1 | 0 | yes |
| CAR-2021-12-001 original | 16 | 14 | yes |
| CAR's Elastic query | 15 | 14 | yes |
| My version | 2 | 0 | yes |

## Test cases (6 should alert, 4 normal)

| Version | Caught | False alarms |
|---|---|---|
| CAR-2013-08-001 | 3/6 | 1/4 |
| CAR-2021-12-001 original | 6/6 | 3/4 |
| CAR's Elastic query | 4/6 | 3/4 |
| My version | 6/6 | 0/4 |

- The baseline misses Amadey v5 and both 4698-only cases.
- The Elastic query misses lowercase `schtasks.exe` (Amadey v3/v4, Week 6 method A).
- These tests are my own data, so the real check is the 30-day query in my lab.

## ATT&CK mapping

- Technique: T1053.005 Scheduled Task
- Tactics: Execution, Persistence, Privilege Escalation
- It can also show T1059 (PowerShell, cmd) and T1218 (mshta, rundll32) when the task runs those
- Amadey Kill Chain phase: 5 Installation
- It uses 3 of the 5 log sources from ATT&CK's AN1221 (4698, 4702, process creation); the other 2 need Sysmon

## Lab steps (pending)

1. Import the rules, screenshot them with the MITRE mapping.
2. Run the 30-day noise query.
3. Turn rules on, run the Week 6 test: both rules should fire on method A, only the 4698 rule on method B.
