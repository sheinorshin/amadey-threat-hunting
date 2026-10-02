# Week 3 — Data Processing and Exploitation  ·  Assignment 1

**Lifecycle stage:** Processing → Exploitation\
**Syllabus tasks:** (1) deploy MISP and import IOCs · (2) apply filtering and normalization techniques to collected data · tools: MISP, Elastic Stack, Sigma · reading: MISP Training Documentation

## Deliverables

| File | Content |
|---|---|
| [`01-misp-deployment.md`](01-misp-deployment.md) | MISP via official `misp-docker`, lab-size config ([`misp/env.example`](misp/env.example)), post-install hardening, feeds, taxonomies, API key |
| [`02-ioc-import.md`](02-ioc-import.md) | 3 import methods (MISP JSON, Freetext, PyMISP) + STIX 2.1 import for correlation |
| [`03-filtering-normalization.md`](03-filtering-normalization.md) | 10-step pipeline, results, before/after, insights |
| [`04-exploitation-elastic-sigma.md`](04-exploitation-elastic-sigma.md) | MISP → Elastic, indicator-match rule, 8 Sigma rules + EQL conversion |
| [`scripts/`](scripts/) | `normalize_iocs.py`, `build_misp_event.py`, `push_to_misp.py`, `to_elastic_ndjson.py`, `gen_sigma_ioc_rules.py`, `convert_sigma.py` |
| [`sigma/`](sigma/) | 6 behavioural rules + 2 generated IOC rules + Elastic Agent field-mapping pipeline |
| [`output/`](output/) | Normalised IOCs (CSV/JSON), rejected list, blocklists, MISP event, ECS NDJSON, converted queries, pipeline report |

## Results in numbers

| Metric | Value |
|---|---|
| Raw → normalised | 81 raw → 2 rejected → 66 unique → **81 normalised** (+15 derived hosts) |
| Actionable (`to_ids`) | **54** (28 hashes, 12 domains, 12 URLs, 1 mutex, 1 scheduled task) |
| Actionable IPs | **0 of 7** (all expired, offline or re-assigned) |
| Cross-publisher overlap | **0** indicators |
| MISP event | 81 attributes, 12 event tags/galaxies, validated with PyMISP + MISP `describeTypes` |
| Sigma | 8 rules, `sigma check`: 0 errors / 0 issues; converted to EQL/Lucene |

## How to run (≈ 1 min, no internet needed except for MISP/Sigma install)

```bash
cd week-03-data-processing/scripts
python normalize_iocs.py --as-of 2026-10-02   # pipeline + report
python build_misp_event.py                    # MISP JSON + freetext list
python to_elastic_ndjson.py                   # Elastic bulk file
python gen_sigma_ioc_rules.py                 # IOC → Sigma
pip install sigma-cli pySigma-backend-elasticsearch && python convert_sigma.py
# with MISP running:
pip install pymisp && python push_to_misp.py
```

---

## Defense notes (7–8 min) — Assignment 1

| Time | Point | Show |
|---|---|---|
| 0:00–0:45 | Where the project is: collection (W2) → **processing + exploitation** (W3). Problem: 81 messy raw records in 4 formats. | `week-02/data/raw/` |
| 0:45–2:00 | MISP running in Docker; feeds, taxonomies, API key. | MISP dashboard, `docker compose ps` |
| 2:00–4:00 | Pipeline walk-through: refang → type → validate → dedup → derive → filter → score. Live run of `normalize_iocs.py`. | Terminal + `pipeline_report.md` |
| 4:00–5:00 | Before/after table: mutex ≠ MD5, truncated Talos hashes, dead `185.215.113.0/24`, re-used StealC IP. | `03-filtering-normalization.md` |
| 5:00–6:15 | Import into MISP (MISP JSON) → `to_ids` filter → correlation with the Talos STIX event → ATT&CK galaxy. | MISP event view |
| 6:15–7:30 | Exploitation: indicator-match rule in Kibana + Sigma behavioural rules (why TTPs > IOCs, zero overlap finding). | `04-…md`, EQL query |

**Likely questions**

- *What's the difference between filtering and normalisation?* — Normalisation makes data **consistent** (same format, type, case, refanged). Filtering decides **what is useful** (drop invalid, expired, benign, context-only).
- *Why are no IPs actionable?* — Every IP is older than its 90-day TTL; additionally the 185.215.113.0/24 range is withdrawn from BGP and one StealC IP now hosts another site — blocking would create false positives.
- *What does `to_ids` mean in MISP?* — The attribute is suitable for automatic detection (exported to IDS/SIEM). `to_ids = false` keeps it for context and analysis only.
- *Why keep expired IOCs at all?* — Retro-hunting in historical logs and attribution context; they just shouldn't fire live alerts.
- *What is MISP correlation?* — MISP automatically links attributes with identical values across events/feeds, revealing shared infrastructure.
- *Why Sigma if you already have IOCs?* — Zero overlap between vendors shows IOCs only cover known builds; Sigma rules on TTPs (1-minute task, Startup redirect, rundll32 plugins) catch new builds too.
- *How did you choose TTL values?* — Common practice in CTI platforms: IPs change fastest (≈ 30–90 d), domains/URLs slower (≈ 180 d), file hashes are permanent. Values are parameters in the script (`TTL_DAYS`).
