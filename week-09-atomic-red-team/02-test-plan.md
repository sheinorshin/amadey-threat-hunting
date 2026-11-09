# 2. Test plan

Data: [`data/test_plan.json`](data/test_plan.json) (IDs checked against ATT&CK v19.2). Written before the run.

## How I chose the tests

- The technique is in Amadey's chain (Week 4) or is a syllabus example (T1059, T1003).
- APT29 or APT41 also use it (Week 10).
- My lab collects logs for it, so I can see if it's detected.
- It is safe to run on the VM.

## The 14 tests

| ID | Technique | Expected logs | Prediction |
|---|---|---|---|
| A1 | T1059.001 PowerShell | 4688, 4104 | Telemetry |
| A2 | T1059.003 Windows Command Shell | 4688 | Telemetry |
| A3 | T1053.005 Scheduled Task (schtasks + PowerShell) | 4688, 4698, TaskScheduler | Technique |
| A4 | T1105 Ingress Tool Transfer (from a lab server) | 4688, 4104 | Telemetry |
| A5 | T1136.001 Local Account | 4720, 4732 | Technique |
| A6 | T1686 Firewall rule (within 30 min of A5) | 4946 | Technique |
| A7 | T1218.011 Rundll32 (harmless DLL) | 4688 | Telemetry |
| A8 | T1082 System Information Discovery | 4688 | Telemetry |
| B1 | T1059.007 JavaScript that starts PowerShell | 4688 | Technique |
| B2 | T1218.005 Mshta that starts PowerShell | 4688 | Technique |
| B3 | T1547.001 Run key | 4688, 4104 | Telemetry |
| B4 | T1112 Modify Registry (RDP setting, restored) | 4688, 4104 | Telemetry |
| C1 | T1003.002 SAM (optional, snapshot first) | 4688 | Telemetry |
| C2 | T1003.001 LSASS (optional, snapshot first) | 4688, Defender | Telemetry |

Total prediction: 5 Technique, 9 Telemetry, 0 None.

To pick the exact atomic: `Invoke-AtomicTest T1053.005 -ShowDetailsBrief`, then choose a Windows test with `cmd`/`powershell`, no internet, with a cleanup command.

## Predictions

1. All A and B tests show up in the SIEM.
2. Week 7 rules catch both ways of making a task; Week 3 rule only `schtasks`.
3. New admin + firewall rule within 30 min trigger the Week 5 H3 correlation.
4. Rundll32 is seen but not detected (my Week 3 rule is Amadey-specific).
5. Week 5 H1 fires only when the script starts PowerShell.
6. Without Sysmon the registry change itself is not visible.
7. Seeing `systeminfo` doesn't mean Amadey's API-based discovery is visible.
8. LSASS access gives no technique-level alert without Sysmon.
9. Kibana alerts come after minutes, not seconds (rules run every 5 min).
