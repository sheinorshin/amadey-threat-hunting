# Week 6 — MITRE ATT&CK Framework

**Lifecycle stage:** Analysis\
**Syllabus tasks:** (1) study one specific ATT&CK technique (e.g. T1059 – Command-Line Interface) · (2) simulate an attack and map the results to ATT&CK tactics and techniques · lecture: tactics, techniques, procedures (attack.mitre.org) · reading: *MITRE ATT&CK Navigator documentation*

**What this week does:** studies **T1053.005 Scheduled Task** — Amadey's every-minute persistence and the technique behind my Week 3 Sigma rule and Week 5 hunt H2 — straight from the official ATT&CK v19.2 data, finds two gaps (one in ATT&CK, one in my own detections), and builds a **benign lab exercise** that creates the same kind of task in two ways so the SIEM telemetry can be mapped to ATT&CK and my detections tested against it. T1059 (the syllabus example) is covered as the reference technique and is exercised by the lab too.

## Deliverables

| File | Content |
|---|---|
| [`01-attack-framework.md`](01-attack-framework.md) | ATT&CK v19.2 in numbers, TTP hierarchy, object model (v18+ detection strategies → analytics → log sources), **T1059** ("Command-Line Interface" → *Command and Scripting Interpreter*, 13 sub-techniques), **Navigator** layers |
| [`02-technique-deep-dive.md`](02-technique-deep-dive.md) | **Task 1** — T1053.005: identity card, how Task Scheduler works, creation interfaces, 3 tactics, 190 procedure examples, Amadey's procedure across versions, DET0441/AN1221 vs my lab, mitigations |
| [`03-lab-exercise.md`](03-lab-exercise.md) | **Task 2** — research questions, safety, steps, logging prerequisites, run → export → map, expected telemetry, mapping rules, detections tested |
| [`04-results-and-mapping.md`](04-results-and-mapping.md) | ATT&CK mapping of the simulated attack, predictions P1–P5, observed-results table (filled after the lab run), next steps |
| [`lab/ith-w6-task-exercise.ps1`](lab/ith-w6-task-exercise.ps1) | the benign exercise: one harmless `ITH-W6` task via `schtasks.exe`, one via `Register-ScheduledTask`, automatic cleanup, ground-truth CSV |
| [`queries/w6_exercise_events.esql`](queries/w6_exercise_events.esql) | Kibana ES\|QL export of every event the exercise produced |
| [`scripts/build_attack_profile.py`](scripts/build_attack_profile.py) | reads ATT&CK v19.2 → [`data/attack_profile.json`](data/attack_profile.json) + expected Navigator layer |
| [`scripts/map_results.py`](scripts/map_results.py) | Kibana export + ground truth → ATT&CK mapping, detection matrix, observed Navigator layer; `--selftest` |
| [`navigator/`](navigator/) | [`t1053_005_lab_exercise_layer.json`](navigator/t1053_005_lab_exercise_layer.json) (expected); `t1053_005_observed_layer.json` is added by the lab run |

## Results in numbers (technique study)

| Metric | Value |
|---|---|
| Technique | **T1053.005 Scheduled Task** (v1.8, modified 2026-05-12) — Execution · Persistence · Privilege Escalation |
| Procedure examples in ATT&CK | **190** (115 malware, 54 groups, 12 campaigns, 9 tools) — **Amadey not among them** |
| ATT&CK detection | DET0441 → AN1221: Security 4698 / 4702, Sysmon 1 / 11 / 13-14 — my lab has **2 of 5** log sources without Sysmon (4688 stands in for Sysmon 1) |
| Mitigations | 4 (M1018, M1026, M1028, M1047) — all aimed at privilege abuse, **low effect** on Amadey's user-level task |
| Gap found in my detections | Week 3 Sigma rule only sees `schtasks.exe`; Amadey v5 creates its task through COM → needs the 4698-based logic |
| Lab exercise | 2 creation methods · 3 techniques (T1053.005, T1059.001, T1059.003) · 3 detections tested · self-test **6/6 PASS** |
| Observed lab results | ⏳ pending one run on the lab VM (~6 min) — see [`03`](03-lab-exercise.md) §3.5 |

## How to reproduce

```bash
cd week-06-attack-framework/scripts
python build_attack_profile.py     # ATT&CK v19.2 facts -> ../data/attack_profile.json + expected layer
python map_results.py --selftest   # mapping logic check, writes nothing
# after the lab run (see 03-lab-exercise.md):
python map_results.py --events <export.csv> --runlog <w6_run_log.csv>
```

---

## Defense notes (7–8 min)

| Time | Point | Show |
|---|---|---|
| 0:00–1:00 | ATT&CK = matrix of *why* × *how* from real observations; v19.2 numbers; TTP hierarchy on one example | `01`, §1.1–1.2 |
| 1:00–2:00 | T1059 in the syllabus is the old name; why I chose T1053.005 (Amadey's core persistence, Weeks 3 + 5) | `01`, §1.4 |
| 2:00–4:00 | Deep-dive: how Task Scheduler works, creation interfaces, 3 tactics, 190 procedures, Amadey **not listed** | `02`, §2.1–2.5 |
| 4:00–5:00 | Detection: DET0441/AN1221 log sources vs my lab; Gap 2 (command-line rule misses API-created tasks) | `02`, §2.6 |
| 5:00–6:30 | Lab exercise: two methods, ground truth, expected telemetry, predictions P1–P5; results + observed layer | `03`, `04`, Navigator |
| 6:30–7:30 | What changes: 4698-based rule, logging fixes, baseline for Weeks 7–9 | `04`, §4.4 |

**Likely questions**

- *Tactic vs technique vs procedure?* — Tactic = the goal (Persistence). Technique = the general method (T1053 Scheduled Task/Job), sub-technique = the specific variant (T1053.005, Windows Task Scheduler). Procedure = how one actor did it (Amadey: a task named after its EXE, every minute).
- *Why does T1053.005 have three tactics?* — The same task can run code (Execution), come back after reboot (Persistence) or run as a more privileged account (Privilege Escalation). ATT&CK lists a technique under every goal it can serve.
- *The syllabus says T1059 "Command-Line Interface" — is that wrong?* — It's the pre-2020 name. Since ATT&CK v7 the same ID is *Command and Scripting Interpreter* with sub-techniques; e.g. the old T1086 PowerShell was revoked into T1059.001.
- *What's new in how ATT&CK describes detection?* — Since v18, *data sources* are replaced by **detection strategies → analytics → data components with concrete log sources** (e.g. `Security EventCode=4698`). For T1053.005 that is DET0441 / AN1221.
- *Why is your simulation "safe"?* — The task runs a one-line script that writes a timestamp to a log; everything is named `ITH-W6`, runs only on the lab VM and is removed automatically. The point is the **technique's telemetry**, not malware behaviour.
- *Why two creation methods?* — Amadey v3/v4 used `schtasks.exe`; v5 uses the COM API, so there is no `schtasks.exe` process. Method B (cmdlets) reproduces "no schtasks.exe" safely and shows whether my detections depend on that process.
- *Why isn't Amadey listed under T1053.005?* — ATT&CK only adds procedures that someone submits with sources. Four public reports document it, so it's a valid contribution — S1025's page has 17 techniques and misses its most stable one.
- *What's a Navigator layer?* — A JSON file with per-technique scores, colours and comments that the Navigator draws on the matrix. I have an *expected* layer and, after the lab run, an *observed* one; comparing them shows what my lab missed.

← [Project overview](../README.md) · previous: [Week 5](../week-05-threat-hunting/) · next: Week 7 (MITRE CAR)
