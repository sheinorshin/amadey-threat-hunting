# 4. Results and ATT&CK mapping

## Mapping

| What happens | ATT&CK |
|---|---|
| I run the PowerShell script | T1059.001 PowerShell (Execution) |
| Task is created (A and B) | T1053.005 Scheduled Task (Execution, Persistence, Privilege Escalation) |
| Task runs `cmd.exe` every minute | T1053.005 + T1059.003 Windows Command Shell |

So the test covers 3 techniques and 3 tactics — the same as Amadey's installation step (Week 4), without the malware.

## Predictions

1. 4698 and 106 appear for both methods.
2. `schtasks.exe` appears only for method A.
3. Week 3 rule fires only on A — this proves the gap from file 02.
4. The 4698 query fires on both.

## Results

Waiting for the lab run. After it, `map_results.py` writes `results/w6_results.md` and the observed Navigator layer, and I fill in:

| | Method A | Method B |
|---|---|---|
| Events seen | | |
| Rules that fired | | |

## Next step

If prediction 3 is true, I need a rule on event 4698 — this is done in Week 7.
