# Week 3 — Data Processing and Exploitation  ·  Assignment 1

**Lifecycle stage:** Processing → Exploitation\
**Syllabus tasks:** (1) deploy MISP and import IOCs · (2) apply filtering and normalization techniques to collected data · tools: MISP, Elastic Stack, Sigma · reading: MISP Training Documentation

## Deliverables

| File | Content |
|---|---|
| [`01-misp-deployment.md`](01-misp-deployment.md) | MISP 2.5.48 via official `misp-docker` on Docker Desktop: config ([`misp/env.example`](misp/env.example)), setup script ([`misp/setup-misp.ps1`](misp/setup-misp.ps1)), Windows fix ([`misp/docker-compose.override.yml`](misp/docker-compose.override.yml)), post-install config, real deployment log + troubleshooting |
| [`02-ioc-import.md`](02-ioc-import.md) | 3 import methods (MISP JSON, Freetext, PyMISP) + STIX 2.1 import for correlation |
| [`03-filtering-normalization.md`](03-filtering-normalization.md) | 10-step pipeline, results, before/after, insights |
| [`04-exploitation-elastic-sigma.md`](04-exploitation-elastic-sigma.md) | MISP → Elastic, indicator-match rule, 8 Sigma rules + EQL conversion |
| [`scripts/`](scripts/) | `normalize_iocs.py`, `build_misp_event.py`, `build_pivot_event.py`, `push_to_misp.py`, `to_elastic_ndjson.py`, `gen_sigma_ioc_rules.py`, `convert_sigma.py` |
| [`sigma/`](sigma/) | 6 behavioural rules + 2 generated IOC rules + Elastic Agent field-mapping pipeline |
| [`output/`](output/) | Normalised IOCs (CSV/JSON), rejected list, blocklists, MISP events (consolidated + VT-pivot extension), ECS NDJSON, converted queries, pipeline report |
| [`evidence/`](evidence/) | **15 screenshots** from my running MISP 2.5.48: Docker stack, events, correlation graph, ATT&CK matrix, feeds, taxonomies, sightings, troubleshooting |

## Results in numbers

| Metric | Value |
|---|---|
| Raw → normalised | 81 raw → 2 rejected → 66 unique → **81 normalised** (+15 derived hosts) |
| Actionable (`to_ids`) | **54** (28 hashes, 12 domains, 12 URLs, 1 mutex, 1 scheduled task) |
| Actionable IPs | **0 of 7** (all expired, offline or re-assigned) |
| Cross-publisher overlap | **0** indicators |
| MISP event | 81 attributes, 12 event tags/galaxies, validated with PyMISP + MISP `describeTypes` |
| MISP instance (live) | 3 events: #1 consolidated (81 attr., 54 IDS) · #2 raw Talos STIX (17) · #3 VT pivots extending #1 (7) → **13 correlations** #1↔#2, 2 sightings, 4 abuse.ch feeds cached |
| Sigma | 8 rules, `sigma check`: 0 errors / 0 issues; converted to EQL/Lucene |

## How to run (≈ 1 min, no internet needed except for MISP/Sigma install)

```bash
cd week-03-data-processing/scripts
python normalize_iocs.py --as-of 2026-10-02   # pipeline + report
python build_misp_event.py                    # MISP JSON + freetext list
python to_elastic_ndjson.py                   # Elastic bulk file
python gen_sigma_ioc_rules.py                 # IOC → Sigma
python build_pivot_event.py                   # Week 2 VT pivots → MISP extension event
pip install sigma-cli pySigma-backend-elasticsearch && python convert_sigma.py
# with MISP running:
pip install pymisp && python push_to_misp.py
```
