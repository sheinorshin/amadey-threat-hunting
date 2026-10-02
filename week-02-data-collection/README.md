# Week 2 — Data Collection Process

**Lifecycle stage:** Collection\
**Syllabus tasks:** (1) perform OSINT data collection using Shodan, VirusTotal and Maltego · (2) develop a data source mapping for analysis · reading: M. Bazzell, *Open Source Intelligence Techniques*

## Deliverables

| File / folder | Content |
|---|---|
| [`01-collection-plan.md`](01-collection-plan.md) | PIR → source mapping, open vs closed sources, 9 sources rated (Admiralty), OPSEC rules, collection counts |
| [`02-osint-collection.md`](02-osint-collection.md) | VirusTotal / Shodan / Maltego procedures, queries, results, pivot graph |
| [`03-data-source-mapping.md`](03-data-source-mapping.md) | 14 Amadey behaviours → ATT&CK → log source/event ID → ECS fields → lab coverage |
| [`data/raw/`](data/raw/) | 6 raw IOC files from Talos (TXT + STIX 2.1), Trellix, Microsoft, Splunk — unmodified, with provenance log |
| [`data/enrichment/`](data/enrichment/) | RIPEstat + Shodan InternetDB snapshot (2026-10-02) |
| [`data/maltego_graph_import.csv`](data/maltego_graph_import.csv) | 33-link graph ready for Maltego import |
| [`scripts/`](scripts/) | `vt_lookup.py`, `shodan_lookup.py`, `ripestat_enrich.py` — stdlib only, read-only/passive |
| [`evidence/`](evidence/) | Screenshot checklist |

## Results in numbers

| Metric | Value |
|---|---|
| Sources collected | 5 publishers, 6 files (2023 → 2026) |
| Raw indicators | **81** (36 hashes, 24 URLs, 8 IPs, 2 domains, 11 host artefacts) |
| IPs enriched (ASN/netblock/BGP) | 7 |
| Quality problems spotted at collection | 4 (truncated hashes, deprecated ATT&CK ID, mixed defanging, mixed malware families) |
| Data sources mapped | 14 behaviours → 8 log sources; lab covers 7/14 now, 12/14 with Sysmon |

## Key findings

1. **Amadey C2 and StealC C2 share a hosting provider** (AS202412 Omegatech) → hosting ASN is a better long-term pivot than single IPs.
2. **2025 Amadey infrastructure in `185.215.113.0/24` is dead** (prefix withdrawn 2025-05-02) → old IPs must expire.
3. **A former StealC C2 IP now serves an unrelated website** → IOC decay is real; blind blocking causes false positives.
4. My SIEM lab can't see registry, DNS or network behaviour without **Sysmon** → top recommendation.

---

## Defense notes (7–8 min)

| Time | Point |
|---|---|
| 0:00–1:00 | Recap PIRs from Week 1 → this week = *collection*. Open vs closed sources. |
| 1:00–2:30 | Collection plan: 9 sources + Admiralty ratings + OPSEC (passive only, no uploads to VT). |
| 2:30–4:00 | VirusTotal: show the Amadey 5.70 hash → label, behaviour (scheduled task), relations. |
| 4:00–5:00 | Shodan + RIPEstat table: dead range, shared ASN, re-used IP. |
| 5:00–6:00 | Maltego graph: sample → C2 → netblock → ASN → StealC C2. |
| 6:00–7:30 | Data source mapping: what my lab sees, the Sysmon gap, the data-flow diagram. |

**Likely questions**

- *Why not upload samples to VirusTotal?* — Uploaded files become available to all VT Intelligence users, including attackers checking whether their build is burned; for internal files it can leak data.
- *What's the difference between Shodan and VirusTotal?* — Shodan = internet scan data about hosts (ports, banners); VT = file/URL/domain reputation from AV engines + sandboxes + passive DNS.
- *Why is the ASN interesting?* — Operators reuse cheap/bulletproof providers; IPs rotate, providers change slower (higher on the Pyramid of Pain).
- *Why Sysmon if you already have 4688?* — 4688 = process creation only. Sysmon adds registry (13), DNS (22), network (3), image load (7), ADS (15), file creation (11).
- *Admiralty A2 meaning?* — A = completely reliable source; 2 = probably true (not independently confirmed by me yet).
