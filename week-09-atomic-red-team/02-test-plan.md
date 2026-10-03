# 2. Test plan — which techniques, why, and what I predict

> Generated data: [`data/test_plan.json`](data/test_plan.json) (from [`scripts/build_test_plan.py`](scripts/build_test_plan.py), every ID checked against ATT&CK v19.2) · expected layer: [`navigator/w9_test_plan_layer.json`](navigator/w9_test_plan_layer.json) · run sheet: [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv).
> **Written before the run.** The plan names each technique and the behaviour a test must show. The concrete atomic (test number + GUID) is chosen on the lab VM from the public library and recorded automatically in the execution log.

## 2.1 Selection criteria

| # | Criterion | Source |
|---|---|---|
| C1 | The technique is in **Amadey's chain** (Week 4) or is the **syllabus example** (T1059, T1003) | Week 4 kill chain, syllabus |
| C2 | Preferably **shared with APT29 / APT41** too, so one result says something about several actors | Week 10 §4.3 ("commodity core") |
| C3 | My lab **collects data** for it today, so the result can tell *detected* from *only seen*. A test in a blind spot predictably says "None" and teaches little. | Week 2 data-source map, Week 10 §4.5 |
| C4 | Safe and reversible on the isolated VM (§1.4 of [`01`](01-atomic-red-team.md)) | |

## 2.2 The plan

**Tier A**: the commodity core, visible today. **Tier B**: the rest of Amadey's own chain. **Tier C** (optional, snapshot first): the syllabus example T1003, taken from the APT side.

| ID | Technique | Why | The chosen atomic must … | Expected telemetry | Detection expected | Predicted |
|---|---|---|---|---|---|---|
| W9-A1 | T1059.001 PowerShell | Amadey KC4 + KC7; all 5 actors | run a script block; one variant with an encoded command | 4688 `powershell.exe`, 4104 | W5-H1b only with a download keyword | **Telemetry** |
| W9-A2 | T1059.003 Windows Command Shell | syllabus T1059; APT29, APT41, TA505, Kimsuky | run a batch file / `cmd /c` | 4688 `cmd.exe` | — | **Telemetry** |
| W9-A3 | T1053.005 Scheduled Task | Amadey KC5 (Weeks 3, 5, 6, 7) | create a task with `schtasks.exe` **and** (second test) with PowerShell cmdlets | 4688 `schtasks`, **4698**, TaskScheduler 106/200/201, 4104 | W7 CAR rules if the action is user-writable / every-minute interpreter; W3 + W5-H2b only for `/SC MINUTE /MO 1`; W5-H2c only for `PT1M` | **Technique** |
| W9-A4 | T1105 Ingress Tool Transfer | Amadey KC3/KC7; all 5 actors | download with a built-in tool from a **lab-local** web server | 4688 `certutil` / `bitsadmin` / `powershell` with URL, 4104 | W5-H1b for the PowerShell variant | **Telemetry** |
| W9-A5 | T1136.001 Local Account | Amadey v5 hidden admin; APT41, Kimsuky | create a local user, add it to Administrators | **4720**, **4732**, 4688 `net.exe` / 4104 | W5-H3 | **Technique** |
| W9-A6 | T1686 Disable or Modify System Firewall | Amadey v5 RDP rule; APT29, Kimsuky | add an inbound firewall rule, **within 30 min of W9-A5** | **4946**, 4688 `netsh` / 4104 | W5-H3 confirmation | **Technique** |
| W9-A7 | T1218.011 Rundll32 | Amadey plugins; all 5 actors | run an export of a harmless DLL from a user-writable folder | 4688 `rundll32.exe` | W3-RUNDLL32 should **not** fire | **Telemetry** |
| W9-A8 | T1082 System Information Discovery | Amadey check-in; APT41, Kimsuky | command-line discovery (`systeminfo`, `hostname`) | 4688 | — | **Telemetry** |
| W9-B1 | T1059.007 JavaScript | Amadey KC4 (Emmenhtal) | run a local `.js` with wscript/cscript that **starts PowerShell** | 4688 `wscript` → `powershell` | W5-H1a | **Technique** |
| W9-B2 | T1218.005 Mshta | Amadey KC4 | run a local `.hta`/inline script that **starts PowerShell** | 4688 `mshta` → `powershell` | W5-H1a | **Technique** |
| W9-B3 | T1547.001 Run Keys / Startup Folder | Amadey KC5 | add a Run-key value (reg.exe or PowerShell) | 4688 `reg.exe` / 4104 | W3-STARTUP-REG needs Sysmon 13 | **Telemetry** |
| W9-B4 | T1112 Modify Registry | Amadey v5 enables RDP | set `fDenyTSConnections` = 0, restore it in cleanup | 4688 `reg.exe` / 4104 | W3-RDP-REG needs Sysmon 13 | **Telemetry** |
| W9-C1 | T1003.002 Security Account Manager | syllabus T1003; APT29 + APT41 (`reg save`) | export the SAM/SYSTEM hives to a file, then delete it | 4688 `reg.exe save` | — (gap) | **Telemetry** |
| W9-C2 | T1003.001 LSASS Memory | syllabus T1003; APT41, Kimsuky, APT1 | an LSASS access test using built-in Windows components only | 4688 of the accessing process; Defender 1116/1117 | needs Sysmon 10 | **Telemetry** (or General via Defender) |

**Predicted totals:** 14 tests → **Technique 5**, **Telemetry 9**, None 0. A visibility rate of 100 % and a technique-level detection rate of **36 %** (5/14) is the hypothesis to test.

## 2.3 How to pick the atomic for each row

For each technique, list its tests on the VM (`Invoke-AtomicTest T1053.005 -ShowDetailsBrief`) and pick the one that:

1. supports **Windows** and uses the `command_prompt` or `powershell` executor;
2. matches the "must …" column above (e.g. for W9-B1 the script has to start PowerShell, or H1 has nothing to look at);
3. needs no internet, or takes the URL as an input argument that can point at the lab-local server;
4. has a `cleanup_command`, and for tiers A/B needs no third-party binary.

The test number and GUID are logged automatically. If you run tests by hand instead, fill [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv) (ISO UTC times). Two tests for one technique (as in W9-A3) are fine: the scorer reports each test and the best result per technique.

## 2.4 Predictions to confirm or reject

| # | Prediction | Confirmed if … | Tests |
|---|---|---|---|
| P1 | Every tier A/B test reaches the SIEM (visibility 12/12) | no tier A/B test scores *None* (unless FAILED) | all |
| P2 | My Week 7 rules catch **both** ways of creating a task when the action is user-writable or an every-minute interpreter. The Week 3 rule catches only the `schtasks.exe` way. | detection matrix for the two W9-A3 tests | A3 |
| P3 | A new admin + a firewall rule within 30 min trigger the **H3 correlation** | `W5-H3-confirmed` on W9-A6 | A5, A6 |
| P4 | rundll32 with a non-Amadey DLL is **seen but not detected**, so Week 3's T1218.011 tag is nominal (Week 10 §4.5) | W9-A7 = Telemetry, W3-RUNDLL32 not fired | A7 |
| P5 | H1 fires only when the script host **starts PowerShell** | B1/B2 = Technique with `W5-H1a` | B1, B2 |
| P6 | Without Sysmon only the process that edits the registry is seen, not the change itself | B3/B4 observations list 4688/4104 only | B3, B4 |
| P7 | Command-line discovery is visible, but that **does not** prove Amadey's API-based discovery is (Week 10 §4.5) | A8 = Telemetry; noted as a procedure difference | A8 |
| P8 | LSASS access leaves no technique-level evidence without Sysmon 10; Defender may block it | C2 = Telemetry/None or General with AV flag; `tested technique observed` = no | C2 |
| P9 | Kibana alerts arrive **minutes**, not seconds, after the event (rule interval 5 min, look-back 6 min) | median time to Kibana alert between 60 and 360 s | rules from Week 7 |

## 2.5 The predicted layer

[`navigator/w9_test_plan_layer.json`](navigator/w9_test_plan_layer.json) colours the 14 techniques by predicted result (green = Technique, yellow = Telemetry). After the run, `score_atomic_run.py` writes `navigator/w9_observed_layer.json` on the same scale. Comparing the two layers in the Navigator shows exactly where my lab did better or worse than I expected.
