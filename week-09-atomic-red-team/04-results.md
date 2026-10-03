# 4. Results

> **Status:** the plan, the predictions and the analysis tooling are complete, and the scorer passes its self-test (12/12). The **observed** results come from one run of the planned atomics on my lab VM ([`03`](03-siem-analysis.md) §3.4); `scripts/score_atomic_run.py` then writes `results/w9_results.md` and `navigator/w9_observed_layer.json`. Nothing in this file is presented as observed until that run exists.

## 4.1 Predicted vs observed

| ID | Technique | Predicted | Observed | Detections fired | Tested technique seen | Flags |
|---|---|---|---|---|---|---|
| W9-A1 | T1059.001 PowerShell | Telemetry | ⏳ | | | |
| W9-A2 | T1059.003 Windows Command Shell | Telemetry | ⏳ | | | |
| W9-A3 | T1053.005 Scheduled Task (schtasks + cmdlets) | Technique | ⏳ | | | |
| W9-A4 | T1105 Ingress Tool Transfer | Telemetry | ⏳ | | | |
| W9-A5 | T1136.001 Local Account | Technique | ⏳ | | | |
| W9-A6 | T1686 Disable or Modify System Firewall | Technique | ⏳ | | | |
| W9-A7 | T1218.011 Rundll32 | Telemetry | ⏳ | | | |
| W9-A8 | T1082 System Information Discovery | Telemetry | ⏳ | | | |
| W9-B1 | T1059.007 JavaScript | Technique | ⏳ | | | |
| W9-B2 | T1218.005 Mshta | Technique | ⏳ | | | |
| W9-B3 | T1547.001 Run Keys / Startup Folder | Telemetry | ⏳ | | | |
| W9-B4 | T1112 Modify Registry (RDP) | Telemetry | ⏳ | | | |
| W9-C1 | T1003.002 Security Account Manager | Telemetry | ⏳ | | | |
| W9-C2 | T1003.001 LSASS Memory | Telemetry | ⏳ | | | |

## 4.2 Summary metrics

| Metric | Predicted | Observed |
|---|---|---|
| Visibility (any telemetry) | 14/14 (100 %) | ⏳ |
| Technique-level detection | 5/14 (36 %) | ⏳ |
| Any detection | 5/14 (36 %) | ⏳ |
| Median time to Kibana alert | 1–6 min (P9) | ⏳ |
| Predictions as / better / worse | — | ⏳ |

## 4.3 Predictions P1–P9

| # | Prediction ([`02`](02-test-plan.md) §2.4) | Result |
|---|---|---|
| P1 | tier A/B all visible | ⏳ |
| P2 | Week 7 rules catch both task-creation methods; Week 3 only `schtasks` | ⏳ |
| P3 | H3 correlation on new admin + firewall rule | ⏳ |
| P4 | rundll32 seen, not detected (nominal coverage) | ⏳ |
| P5 | H1 only when the script host starts PowerShell | ⏳ |
| P6 | registry change itself invisible without Sysmon | ⏳ |
| P7 | command-line discovery visible ≠ Amadey's API discovery visible | ⏳ |
| P8 | no technique-level LSASS evidence without Sysmon 10 | ⏳ |
| P9 | Kibana alerts after minutes, not seconds | ⏳ |

## 4.4 What happens next with the results

| If … | Then … | Where |
|---|---|---|
| a tier A/B test is **None** | find the missing log first (audit policy, channel not collected, agent policy). It's a logging gap, not a detection gap. | Week 2 data-source map, Week 6 §3.4 |
| W9-A3 cmdlet test is not detected | the 4698 branch of the Week 7 rule failed → check that 4698 is audited and the rule is enabled | Week 7 |
| a rule fires in the scorer but **not** in Kibana | deployment problem: rule disabled, index pattern, field mapping, look-back | Kibana rule settings |
| P4 confirmed | rewrite the Week 3 rundll32 rule generically after Sysmon (Week 10 P6) and re-run W9-A7 | Week 3 → Week 10 §4.6 |
| P6 / P8 confirmed | install Sysmon (Week 10's priority #1), re-run B3, B4, C2 with the Sysmon lines of the export query switched on | Week 4 / 10 |
| W9-C1 Telemetry (as predicted) | add a `reg.exe save hklm\sam\|system\|security` rule: data already there, used by APT29 and APT41 | Week 10 §4.6 |
| Week 10 P1–P5 rules are built | add one atomic per new rule to this plan and re-score; the same tooling measures the improvement | this week |

The run also gives Week 8 (emulation plan) its **per-technique baseline**: for each step of an emulated chain, these results show whether my lab sees it and which detection should fire.
