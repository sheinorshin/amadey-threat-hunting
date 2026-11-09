# Week 7 — MITRE CAR

Syllabus tasks:
1. Pick an analytic from CAR and implement it in a SIEM.
2. Map it to ATT&CK.

I picked **CAR-2021-12-001** (suspicious scheduled task) for Amadey's every-minute task from Week 6, fixed its problems and put it into Elastic as Kibana rules.

## Files

- [`01-car-concepts.md`](01-car-concepts.md) — what CAR is, analytics vs detections
- [`02-analytic-selection.md`](02-analytic-selection.md) — CAR vs Amadey, which analytic
- [`03-implementation.md`](03-implementation.md) — problems found, my version, Kibana
- [`04-evaluation-and-mapping.md`](04-evaluation-and-mapping.md) — test results, ATT&CK mapping
- [`sigma/`](sigma/) — 2 Sigma rules
- [`queries/`](queries/) — EQL + ES|QL queries
- [`rules/car_2021_12_001_tuned.ndjson`](rules/car_2021_12_001_tuned.ndjson) — Kibana rules to import
- [`scripts/`](scripts/) — `car_coverage.py`, `build_rules.py`, `evaluate_car.py`

## Short summary

- CAR has 102 analytics; 14 of Amadey's 40 techniques have one.
- CAR-2021-12-001 also checks event 4698, so it sees Amadey v5's COM-made task.
- The original was too noisy (14 false alarms out of 15 normal tasks) and its Elastic query was case-sensitive.
- My version: 0 false alarms in my tests, still catches Amadey.
- Ran on Kali: the scripts, and in Elasticsearch the tuned CAR query flagged the Amadey task on the synthetic dataset. Importing the packaged Kibana detection rule is out of scope (no Kibana).

## How to run

```bash
cd week-07-mitre-car/scripts
pip install pyyaml sigma-cli pySigma-backend-elasticsearch
python car_coverage.py
python build_rules.py
python evaluate_car.py
```

← [Project overview](../README.md) · previous: [Week 6](../week-06-attack-framework/) · next: [Week 8](../week-08-adversary-emulation/)
