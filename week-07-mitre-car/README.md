# Week 7 — MITRE CAR (Cyber Analytics Repository)

**Lifecycle stage:** Detection engineering\
**Syllabus tasks:** (1) select an analytic model from CAR and implement it in a SIEM · (2) map the analytic to related ATT&CK techniques · lecture: analytics vs detections (car.mitre.org) · reading: *MITRE CAR documentation*

**What this week does:** maps all 102 CAR analytics onto the 40 Amadey techniques from Week 4, selects **CAR-2021-12-001** (suspicious scheduled task creation/modification) for Amadey's every-minute persistence — the technique studied in Week 6 — reviews it critically, implements a tuned version in Elastic (Sigma → EQL → importable Kibana rules + ES\|QL hunt), and measures it against the published analytic, CAR's own Elastic query and the simple CAR-2013-08-001 baseline.

## Deliverables

| File | Content |
|---|---|
| [`01-car-concepts.md`](01-car-concepts.md) | CAR in numbers, anatomy of an analytic, the CAR data model (13 objects) → ECS mapping, **analytics vs detections**, CAR vs ATT&CK analytics vs Sigma vs D3FEND |
| [`02-analytic-selection.md`](02-analytic-selection.md) | **Task 1a** — Amadey × CAR coverage (14 exact / 4 parent / 22 none), the 6 CAR analytics for T1053.005, decision |
| [`03-implementation.md`](03-implementation.md) | **Task 1b** — 5 findings in the published analytic, the tuned logic, field mapping, build chain, Kibana import, hunting version |
| [`04-evaluation-and-mapping.md`](04-evaluation-and-mapping.md) | **Task 2** — 4 versions on the Week 5 data and 11 test cases, ATT&CK mapping, comparison with ATT&CK AN1221, limitations, lab steps |
| [`sigma/`](sigma/) | 2 Sigma rules (Task Scheduler branch + process branch) + Elastic Agent field pipeline |
| [`queries/`](queries/) | generated EQL for both rules, ES\|QL hunt, ES\|QL 30-day noise comparison |
| [`rules/car_2021_12_001_tuned.ndjson`](rules/car_2021_12_001_tuned.ndjson) | 2 Kibana detection rules (EQL), import-ready, with MITRE mapping and investigation guide |
| [`scripts/`](scripts/) | `car_coverage.py` (CAR catalogue + coverage layer), `build_rules.py` (Sigma → EQL → Kibana), `evaluate_car.py` (comparison) |
| [`data/`](data/) | `car_analytics.json` (102 analytics), `amadey_car_coverage.json`, `evaluation.json` |
| [`navigator/amadey_car_coverage_layer.json`](navigator/amadey_car_coverage_layer.json) | Amadey techniques coloured by CAR coverage |

## Results in numbers

| Metric | Value |
|---|---|
| CAR analytics catalogued | **102** (last update Mar 2022; 5 technique IDs now outdated in ATT&CK v19.2) |
| Amadey techniques with a CAR analytic | **14 / 40** exact · 4 parent only · 22 none (all of C2 has none) |
| Selected analytic | **CAR-2021-12-001** (T1053.005 · Execution, Persistence, Privilege Escalation) · baseline CAR-2013-08-001 |
| Findings in the published analytic | 5 — over-broad terms, **case-sensitive Elastic query**, `Task` object missing from the CAR data model, user-profile path missing, Defender false positives |
| Week 5 data: false positives | published **14** → tuned **0**, Amadey task still detected |
| Test cases (6 malicious / 4 benign) | baseline 3/6 · published 6/6 with 3/4 false alarms · CAR's Elastic query 4/6 · **tuned 6/6, 0/4** |
| Catches Amadey v5 (task via COM, no schtasks.exe) | baseline ❌ · tuned ✅ |
| Sigma validation | 2 rules, **0 issues** (incl. ATT&CK v19 + CAR tags) |
| Lab | ⏳ import + 30-day noise query + Week 6 exercise pending ([`04`](04-evaluation-and-mapping.md) §4.4) |

## How to reproduce

```bash
cd week-07-mitre-car/scripts
pip install pyyaml sigma-cli pySigma-backend-elasticsearch
python car_coverage.py      # CAR catalogue, Amadey coverage, Navigator layer (downloads 102 YAML files once)
python build_rules.py       # Sigma -> EQL -> Kibana rule NDJSON
python evaluate_car.py      # 4 versions on the Week 5 dataset + test cases
```

---

## Defense notes (7–8 min)

| Time | Point | Show |
|---|---|---|
| 0:00–1:00 | CAR = MITRE's analytics library: hypothesis + data model + implementations + unit tests; 102 analytics, frozen 2022 | `01`, §1.1–1.2 |
| 1:00–2:00 | **Analytics vs detections** — portable hypothesis vs tuned, owned alert | `01`, §1.4 |
| 2:00–3:00 | CAR × Amadey: 14/40 covered, C2 blind; why CAR-2021-12-001 (4698 branch sees Amadey v5) | `02`, coverage layer |
| 3:00–4:30 | Reviewing the analytic: `.exe` = everything, case-sensitive Elastic query, no `Task` object in the data model | `03`, §3.1 |
| 4:30–6:00 | Tuned version → Sigma → EQL → Kibana rule; evaluation table: 14 → 0 false positives, v5 caught | `03`, `04`, Kibana |
| 6:00–7:30 | ATT&CK mapping (T1053.005, 3 tactics, related T1059/T1218), 3/5 of AN1221's log sources; limits + lab plan | `04`, §4.2–4.4 |

**Likely questions**

- *Analytic vs detection?* — An analytic is a portable hypothesis on an abstract data model (CAR); a detection is that idea tuned to my data, with severity, schedule, allow-lists, a triage guide and an owner. CAR-2021-12-001 as published is a fine analytic and a bad detection (14/15 benign tasks flagged).
- *Why CAR-2021-12-001 and not "Execution with schtasks"?* — Amadey v5 creates its task through the COM API: no `schtasks.exe` process exists, so CAR-2013-08-001 never fires. The 4698/4702 branch sees the task whatever created it.
- *What's the CAR data model?* — `(object, action, field)` coordinates such as `process/create/command_line`, 13 objects. I map each to an ECS field. Notably there's no task object, so the 4698 branch had to be mapped by hand.
- *Why was CAR's Elastic query wrong?* — Wildcard queries on ECS keyword/wildcard fields are case-sensitive; `*SCHTASKS*` doesn't match `schtasks.exe`. Splunk is case-insensitive, so the Splunk version works and the Elastic port silently doesn't. I used EQL (`:`/`like~`/`regex~` are case-insensitive).
- *How do you know the tuned rule isn't over-fitted?* — I don't yet: the evaluation is in-sample. That's why the plan includes the 30-day noise query on my real lab and the Week 6 exercise as a live test.
- *Which ATT&CK techniques does it map to?* — T1053.005 under Execution, Persistence and Privilege Escalation; via the interpreter list it also surfaces T1059.001/.003 and T1218 when those are the task's action. It covers 3 of the 5 log sources ATT&CK's own AN1221 recommends.

← [Project overview](../README.md) · previous: [Week 6](../week-06-attack-framework/) · next: Week 8 (Adversary Emulation Plan)
