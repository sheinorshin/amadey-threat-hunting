# 3. Expected detections, run order, cleanup

## What my lab should catch at each step

| Step | ATT&CK | Logs expected | Rule / hunt that should fire |
|---|---|---|---|
| 1 Run script | T1059.001 | 4688 `powershell.exe`, 4104 | Week 5 H1 if the script downloads/decodes |
| 2 Download | T1105 | 4688 `certutil`/`powershell` with URL, 4104 | Week 5 H1 (PowerShell download cradle) |
| 3 Scheduled task | T1053.005 | 4688 `schtasks`, **4698** | Week 3 Sigma + Week 7 CAR rules |
| 4 Stage file | T1074.001 | 4688 `copy`/`xcopy`/PowerShell | — (no rule; logged only) |
| 5 Exfiltrate | T1041 / T1048.003 | 4688 of the sending process; network only with Sysmon/proxy | — (blind: no proxy in lab) |

**Expected result:** the strongest detection is at step 3 (persistence) — the technique my Weeks 3/5/7 work targets. Steps 4 and 5 are mostly a blind spot, which matches the Week 4 finding that my lab is weak on collection and exfiltration (no proxy, no Sysmon). That gap is the point of the exercise: an emulation plan shows **where in the chain I would still miss the attacker.**

## Run order

1. Snapshot the VM. Make sure Week 3/5/7 rules are enabled (same as Week 9).
2. Create the dummy file and start the lab web server (file 02, setup).
3. Run steps 1–5 in order, one at a time, ~2 min apart.
4. Export events and alerts with the Week 9 queries (`w9_run_events.esql`, `w9_alerts.esql`) over the run time.
5. Screenshot per step: the test running, the events in Kibana, any alert. Save in `evidence/`.

Because the techniques overlap with Week 9, you can run this plan **in the same lab session** as the Week 9 atomics and reuse the same exports.

## Cleanup

- Run each test's cleanup command (removes the scheduled task, downloaded files, staging copy).
- Delete `C:\ith-lab\` and stop the lab web server.
- Revert the VM to the snapshot.

## What this adds over Week 9

Week 9 grades each technique on its own. Week 8 shows the **whole chain** and answers one question: if an Amadey-style attacker ran all five steps, where would I catch them and where would they slip through? Answer (predicted): caught at persistence, blind at exfiltration.
