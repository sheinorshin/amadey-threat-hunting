# 4. Evaluation and ATT&CK mapping

> **Syllabus task 2:** *Map the analytic to related ATT&CK techniques* — plus the evidence that the implementation works.
> Numbers: [`data/evaluation.json`](data/evaluation.json), produced by [`scripts/evaluate_car.py`](scripts/evaluate_car.py) (same logic as the Sigma rules and queries).

## 4.1 Four versions compared

| Version | What it is |
|---|---|
| CAR-2013-08-001 | baseline: any `schtasks.exe` process |
| CAR-2021-12-001 | the published logic, case-insensitive (pseudocode / Splunk semantics) |
| CAR-2021-12-001-elastic | the published **Elastic** query, with Elastic's case-sensitive wildcard semantics |
| **TUNED** | my implementation (03, §3.2) |

### On the Week 5 dataset (976 events, 16 task-related, 1 planted Amadey task = 2 events)

| Version | Alerts | On the Amadey task | False positives | Amadey task detected |
|---|---|---|---|---|
| CAR-2013-08-001 | 1 | 1 | 0 | yes |
| CAR-2021-12-001 | 16 | 2 | **14** | yes |
| CAR-2021-12-001-elastic | 15 | 1 | **14** | yes |
| **TUNED** | **2** | **2** | **0** | yes |

The baseline looks perfect here only because the dataset has a single `schtasks.exe` call; any admin running `schtasks /Query` would alert (see the test cases).

### On 11 labelled test cases (one event each)

| Test case | Should alert | CAR-2013-08-001 | CAR-2021-12-001 | …-elastic | TUNED |
|---|---|---|---|---|---|
| CAR unit test 1 (calc.exe from System32, every minute) | n/a (demo) | ✅ | ✅ | ✅ | — |
| CAR unit test 2 (cmd ping every minute) | yes (high) | ✅ | ✅ | ✅ | ✅ |
| Amadey v3/v4 — schtasks, `%TEMP%\<hex>` | yes (high) | ✅ | ✅ | **—** | ✅ |
| Amadey v3/v4 — its 4698 event | yes (high) | — | ✅ | ✅ | ✅ |
| **Amadey v5 — COM API, 4698 only** (Win10/11 path) | yes (high) | **—** | ✅ | ✅ | ✅ |
| Week 6 Method A — schtasks.exe | yes (high) | ✅ | ✅ | **—** | ✅ |
| Week 6 Method B — cmdlet, 4698 only | yes (high) | **—** | ✅ | ✅ | ✅ |
| Benign — admin `schtasks /Query` | no | ✅ | — | — | — |
| Benign — Google Update task | no | — | ✅ | ✅ | — |
| Benign — Office ClickToRun task (hourly) | no | — | ✅ | ✅ | — |
| Benign — Windows Defender task (ProgramData) | no | — | ✅ | ✅ | — |
| **Score** | | 3/6 · 1/4 false alarms | 6/6 · **3/4** false alarms | **4/6** · 3/4 false alarms | **6/6 · 0/4** false alarms |

**What the numbers say**

1. **The baseline (CAR-2013-08-001) is blind to Amadey v5**, which creates its task through COM — exactly the Week 6 "Gap 2". The 4698 branch of CAR-2021-12-001 is what closes it.
2. **The published CAR-2021-12-001 catches everything and drowns it** — 14 false positives out of 15 benign tasks — because `.exe` and `cmd` count as suspicious on their own. As a detection it would be switched off within a day; as a *situational-awareness* analytic it is fine.
3. **CAR's own Elastic query is broken for the most common case**: case-sensitive `*SCHTASKS*` / `*/CREATE*` miss the lower-case `schtasks.exe /Create` that Amadey (and my Week 6 exercise) use.
4. **The tuned version keeps all 6 detections and drops all false alarms** in these tests. Honest limit: the tests and the Week 5 data are mine, so this is *in-sample*. The real measure is the 30-day noise query on my lab (§4.4).

## 4.2 ATT&CK mapping of the analytic

| | CAR-2021-12-001 (tuned) | CAR-2013-08-001 (baseline) |
|---|---|---|
| Technique / sub-technique | **T1053 Scheduled Task/Job → T1053.005 Scheduled Task** | T1053 → T1053.005 |
| Tactics (as in CAR, valid in ATT&CK v19.2) | **TA0002 Execution · TA0003 Persistence · TA0004 Privilege Escalation** | TA0003 Persistence only |
| CAR coverage level | Medium | Moderate |
| Related techniques it also surfaces | **T1059.001 / T1059.003 / T1218.x** — when the task's action is `powershell`, `cmd`, `mshta`, `rundll32` … (the interpreter list); **T1204.002** — the dropped EXE the task runs | — |
| Amadey kill-chain phase (Week 4) | **5 Installation** | 5 |
| D3FEND | D3-PSA Process Spawn Analysis | D3-SJA Scheduled Job Analysis |

**CAR vs ATT&CK's own analytic for T1053.005 (Week 6):**

| ATT&CK DET0441 / AN1221 log source | Used by the tuned CAR analytic? |
|---|---|
| Security 4698 (Scheduled Job Creation) | ✅ Task Scheduler branch |
| Security 4702 (Scheduled Job Modification) | ✅ Task Scheduler branch |
| Sysmon 1 (Process Creation) | ✅ process branch (4688 today, Sysmon 1 later) |
| Sysmon 11 (File Creation — task XML / `.job`) | ❌ — candidate: CAR-2020-09-001 once Sysmon is installed |
| Sysmon 13/14 (TaskCache registry) | ❌ — needs Sysmon |

So the implementation covers **3 of AN1221's 5 log sources** — all three that my lab has today.

Navigator: [`navigator/amadey_car_coverage_layer.json`](navigator/amadey_car_coverage_layer.json) — the 40 Amadey techniques coloured by CAR coverage (green = implemented this week, blue = a CAR analytic exists, amber = parent only, grey = none). [Open in the Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fsheinorshin%2Famadey-threat-hunting%2Fmain%2Fweek-07-mitre-car%2Fnavigator%2Famadey_car_coverage_layer.json).

## 4.3 Limitations

- **In-sample evaluation** — the tuned rule was designed with the Week 5 data and the test cases in view; real false-positive rates need my own lab data (§4.4).
- **Per-user updaters** under `AppData` (some browsers, chat clients) will trigger the writable-path condition — allow-list by task name + signer, never by folder.
- **4698 must be audited** (*Audit Other Object Access Events*) and `TaskContent` must be searchable (03, §3.5 step 4), otherwise only the process branch works — and that one misses Amadey v5.
- CAR's interpreter list includes very short words (`cmd`, `wmic`) that also appear inside longer words; acceptable here because they only count together with `PT1M`.

## 4.4 Lab steps (to run with the other weeks)

| Step | Output |
|---|---|
| Import `rules/car_2021_12_001_tuned.ndjson` (disabled), screenshot the rule with its MITRE mapping | evidence |
| Run `queries/car_noise_last_30_days.esql` over the last 30 days | real alert counts for the 3 versions |
| Enable the rules, run the Week 6 exercise (`week-06-attack-framework/lab/`) | both rules should alert on Method A; only the Task Scheduler rule on Method B |
| `python scripts/evaluate_car.py --week6-events <Week 6 export.csv>` | the same comparison on real telemetry |
