# Week 5 — Threat Hunting Concept · Assignment 3

**Lifecycle stage:** Proactive detection\
**Syllabus tasks:** (1) build a hypothesis-driven hunting scenario (e.g. suspicious PowerShell activity) · (2) execute hunt queries in Splunk or ELK · lecture sources: hunting models (intel-driven, hypothesis-driven), SANS Threat Hunting Summit, *Practical Threat Hunting* · reading: Microsoft Threat Hunting guidance, Costa-Gazcón *Data-Driven Threat Hunting*

**What this week does:** turns the Week 4 kill-chain gap analysis into three hypothesis-driven hunts for Amadey, writes them as real Kibana queries (ES\|QL / EQL / KQL), and **proves** they find a planted Amadey→StealC intrusion inside a day of benign Windows logs while rejecting benign near-misses. Built on data sources my Elastic SIEM lab already collects.

## Deliverables

| File | Content |
|---|---|
| [`01-hunting-concept.md`](01-hunting-concept.md) | What hunting is; intel-driven vs hypothesis-driven; Pyramid of Pain, HMM, Hunting Loop, **PEAK**; the ABLE test; Splunk vs ELK |
| [`02-hunt-plan.md`](02-hunt-plan.md) | **Task 1** — 3 hypotheses in PEAK/Prepare form: hypothesis, ATT&CK, data, scope, queries, triage, success criteria |
| [`03-hunt-execution.md`](03-hunt-execution.md) | **Task 2** — the queries run, funnel numbers, the hits, triage proof, self-checks, reconstructed timeline |
| [`04-findings-and-detections.md`](04-findings-and-detections.md) | Findings, 2 new detections + 2 validated, metrics, limitations, real-lab plan, feed-forward |
| [`queries/`](queries/) | 7 Kibana queries (ES\|QL / EQL / KQL) + how-to, index `logs-*` |
| [`data/dataset.ndjson`](data/dataset.ndjson) | 976-event synthetic ECS dataset (benign noise + 1 planted intrusion + near-misses) |
| [`data/hunt_results.json`](data/hunt_results.json) | Machine-readable hunt output (funnel counts, confirmed hits, self-checks) |
| [`scripts/`](scripts/) | `gen_dataset.py` (build data), `run_hunt.py` (execute + self-check), `make_figures.py` |
| [`figures/`](figures/) | `hunt_funnel.png`, `incident_timeline.png` |

## The three hypotheses

| | Hypothesis | Kill-chain phase | ATT&CK v19 | Lab data |
|---|---|---|---|---|
| **H1** | A script host spawned PowerShell that pulled/ran remote content | 4 Exploitation | T1059.001/.007, T1218.005, T1105 | 4688 + 4104 |
| **H2** | A hex-named EXE in a user folder got a 1-minute scheduled task | 5 Installation | T1053.005, T1204.002 | 4688 + 4698 |
| **H3** | A new local admin + a firewall rule on one host within minutes | 7 Actions on Objectives | T1136.001, T1021.001, T1686 | 4720/4732 + 4946 |

H1 is the syllabus's own example ("suspicious PowerShell activity"), reached by analysis in Week 4 — not picked at random.

## Results in numbers

| Metric | Value |
|---|---|
| Events hunted | **976** across 5 hosts (2026-10-01) |
| Hypotheses confirmed on the planted intrusion | **3 / 3** |
| False positives after triage | **0** (3 near-misses rejected) |
| H1 specificity | naive content search **27** → behavioural hunt **1**, no false negatives |
| New detections produced | **2** (H1 rule, H3 correlation rule) |
| Week-3 Sigma rules validated | **2** (hex-folder EXE, 1-minute task) |
| Self-checks | **6 / 6 PASS** (`run_hunt.py` exit 0) |

![Hunt funnel](figures/hunt_funnel.png)

## How to reproduce

```bash
cd week-05-threat-hunting/scripts
python gen_dataset.py     # -> ../data/dataset.ndjson   (deterministic, 976 events)
python run_hunt.py        # executes the 3 hunts + self-checks -> ../data/hunt_results.json
pip install matplotlib && python make_figures.py
```

In the real lab, load `data/dataset.ndjson` into Elasticsearch (or point at `logs-*`) and run the [`queries/`](queries/) in Kibana — see [`04-findings-and-detections.md`](04-findings-and-detections.md) §4.5.
