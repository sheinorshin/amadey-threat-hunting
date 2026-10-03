# Week 9 — Atomic Red Team · Assignment 5

**Lifecycle stage:** Validation\
**Syllabus tasks:** run selected atomic tests (e.g. T1059, T1003), then record and analyse the results in a SIEM · reading: Atomic Red Team wiki / GitHub

**What this week does:** plans **14 atomic tests** for Amadey's techniques and the syllabus examples. They are chosen so that each result also says something about APT29 and APT41 (Week 10's "commodity core"), and every one has a prediction **written before the run**. I run the atomics myself on the isolated lab VM. This repository holds the SIEM side: ES|QL exports for events and alerts, a scorer that ties every event to the test that caused it (time window + process tree), maps it to ATT&CK, re-runs my Week 3/5/7 detections on it and grades each test None / Telemetry / General / Tactic / Technique, plus predicted and observed Navigator layers.

## Deliverables

| File | Content |
|---|---|
| [`01-atomic-red-team.md`](01-atomic-red-team.md) | What Atomic Red Team is, structure of an atomic, Invoke-AtomicRedTeam, atomics vs emulation (Week 8) vs ATT&CK Evaluations, the validation loop, **safety rules** |
| [`02-test-plan.md`](02-test-plan.md) | **Task 1** — selection criteria, the 14-test plan (tiers A/B/C) with expected telemetry and detections, how to pick each atomic, **predictions P1–P9** |
| [`03-siem-analysis.md`](03-siem-analysis.md) | **Task 2** — checklist, ground truth (execution log), export, attribution rules, ATT&CK mapping, detections scored, result categories and metrics, evidence to keep |
| [`04-results.md`](04-results.md) | predicted vs observed table, metrics, P1–P9, what each outcome changes (filled after the lab run) |
| [`queries/w9_run_events.esql`](queries/w9_run_events.esql) | Kibana ES\|QL export of every relevant event on the lab VM during the run |
| [`queries/w9_alerts.esql`](queries/w9_alerts.esql) | Kibana ES\|QL export of the Security alerts raised during the run |
| [`scripts/build_test_plan.py`](scripts/build_test_plan.py) | plan → [`data/test_plan.json`](data/test_plan.json) + predicted layer; checks every ID against ATT&CK v19.2 |
| [`scripts/score_atomic_run.py`](scripts/score_atomic_run.py) | execution log + exports → ATT&CK mapping, detection matrix, categories, metrics, observed layer; `--selftest` |
| [`templates/w9_run_sheet.csv`](templates/w9_run_sheet.csv) | manual ground truth if the execution log isn't used |
| [`navigator/`](navigator/) | [`w9_test_plan_layer.json`](navigator/w9_test_plan_layer.json) (predicted); `w9_observed_layer.json` is added by the lab run |

## Results in numbers

| Metric | Value |
|---|---|
| Planned tests | **14** on 14 techniques — tier A 8 (commodity core), tier B 4 (Amadey chain), tier C 2 (syllabus T1003, optional) |
| Also used by APT29 or APT41 | **all 14** techniques (Week 10); 11 of them are also in Amadey's Week 4 chain |
| Predicted results | **Technique 5** (T1053.005, T1136.001, T1686, T1059.007, T1218.005) · **Telemetry 9** · None 0 |
| Predicted detection rate | 36 % technique-level; the gaps are expected exactly where Weeks 4 and 10 found them (no Sysmon, Amadey-specific rules) |
| Detections scored | 11 of mine (Weeks 3, 5, 7) + Defender; Week 7 logic imported, not copied |
| Scorer self-test | **12/12 PASS** |
| Observed lab results | ⏳ pending one run on the lab VM (~45 min incl. export) — [`03`](03-siem-analysis.md) §3.4 |

## How to reproduce

```bash
cd week-09-atomic-red-team/scripts
python build_test_plan.py            # plan + predicted layer (ATT&CK v19.2 cached in ~/.cache/attack)
python score_atomic_run.py --selftest
# after the lab run (see 03-siem-analysis.md):
python score_atomic_run.py --runlog <Invoke-AtomicTest-ExecutionLog.csv> --events <events.csv> [--alerts <alerts.csv>]
```

---

## Defense notes (7–8 min)

| Time | Point | Show |
|---|---|---|
| 0:00–1:00 | Atomic = one technique, one test, mapped to ATT&CK; where it sits next to emulation and ATT&CK Evaluations | `01`, §1.1–1.2 |
| 1:00–2:30 | Why these 14: Amadey chain + syllabus T1059/T1003 + shared with APT29/APT41 + visible today; safety rules | `02`, §2.1–2.2, `01` §1.4 |
| 2:30–3:30 | Predictions before the run (P1–P9), predicted layer | `02`, §2.4, Navigator |
| 3:30–5:00 | SIEM side: export → attribution (window + process tree) → ATT&CK mapping → re-run my detections → category | `03`, §3.5–3.8 |
| 5:00–6:30 | Results: predicted vs observed layer, detection matrix, time to alert | `04`, `results/w9_results.md` |
| 6:30–7:30 | What changes: logging gaps vs detection gaps, generic rules, Sysmon, re-test loop | `04`, §4.4 |

**Likely questions**

- *Why only analyse — who runs the tests?* — I run them myself on my isolated lab VM with Invoke-AtomicRedTeam. Its execution log is the ground truth the scorer reads. The repository keeps what is reusable: plan, predictions, queries, scorer, results.
- *Why T1003 only as optional?* — It is the syllabus example, but Amadey steals **browser** credentials (T1555.003), not LSASS. I kept T1003 from the APT side (APT29 and APT41 both save the SAM hive), behind a snapshot. Without Sysmon 10 my lab is predicted to see almost nothing of LSASS access, which is itself the finding.
- *How do you know an event belongs to a test?* — Time window plus the process tree from the executor's PID in the execution log. Service-side events (4698, 4720, 4946) are joined by window, and task runs only by a task name created in the same test. Framework script blocks are dropped. The self-test checks that an unrelated process and an unrelated task run in the same minutes are ignored.
- *What do None / Telemetry / Technique mean?* — The ATT&CK Evaluations scale. None: nothing reached the SIEM. Telemetry: data, no detection. General / Tactic: a detection, but not for this technique. Technique: a detection that names this technique.
- *Why re-implement rules in Python if Kibana already has them?* — The re-implementation shows what *should* fire; the alerts export shows what *did* fire. A difference is a deployment problem (rule off, wrong index pattern, field mapping), and you only see it by having both.
- *An atomic was detected — does that mean Amadey would be?* — Not necessarily. An atomic is *a* procedure. Amadey does discovery through API calls, so a visible `systeminfo` test (P7) says nothing about it. That's the Week 10 lesson: visibility belongs to the procedure.
- *Why is time to alert minutes, not seconds?* — Kibana rules run on a schedule (5 min, 6 min look-back). Against CrowdStrike's 29-minute average breakout time (Week 10) that's acceptable for persistence. It's too slow for anything that must stop an operator in phase 7.

← [Project overview](../README.md) · previous: [Week 8](../week-08-adversary-emulation/) · next: [Week 10](../week-10-apt-techniques/)
