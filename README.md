# Threat Hunting Project — Amadey Loader / Botnet (MITRE S1025)

- **Course:** Introduction to Threat Hunting (ITH) · Astana IT University · 2026–2027, trimester 1
- **Group:** CS-2427
- **Author:** Sayat Abdiraiym — individual project (group assignment completed by one student)

> Weekly increments: each week applies that week's syllabus practice tasks to one real malware family — **Amadey**, a malware-as-a-service loader/botnet (2018 →) that delivers StealC, RedLine, Lumma and even LockBit, and was disrupted by Operation Endgame in June 2026.

## Progress

| Week | Syllabus topic | Practice tasks applied to Amadey | Status |
|---|---|---|---|
| 1 | Cyber Threat Intelligence Fundamentals | CTI glossary · threat & source classification · ENISA ETL 2025 · Amadey threat profile | ✅ [week-01](week-01-cti-fundamentals/) |
| 2 | Data Collection Process | OSINT with VirusTotal / Shodan / Maltego · data source mapping | ✅ [week-02](week-02-data-collection/) |
| 3 | Data Processing & Exploitation **(Assignment 1)** | MISP deployment + IOC import · filtering & normalisation · Elastic + Sigma | ✅ [week-03](week-03-data-processing/) |
| 4 | The Cyber Kill Chain **(Assignment 2)** | Real-world Amadey → StealC intrusion on the 7 phases · each phase → ATT&CK v19 TTPs · Courses of Action | ✅ [week-04](week-04-kill-chain/) |
| 5 | Threat Hunting Concept **(Assignment 3)** | Hypothesis-driven hunt (H1–H3 from Week 4) + queries in ELK | ⏳ |
| 6 | ATT&CK Framework | One technique deep-dive (T1053.005 / T1059) + simulation mapped to ATT&CK | ⏳ |
| 7 | MITRE CAR | CAR analytic → SIEM | ⏳ |
| 8 | Adversary Emulation Plan **(Assignment 4)** | Amadey-style plan: initial access → persistence → exfiltration | ⏳ |
| 9 | Atomic Red Team **(Assignment 5)** | Atomic tests for Amadey TTPs → SIEM | ⏳ |
| 10 | APT Techniques **(Assignment 6)** | APT29 / APT41 TTPs → ATT&CK (+ Amadey users TA505, Kimsuky) | ⏳ |

## Intelligence requirements driving the project

| ID | Question |
|---|---|
| PIR-1 | How does Amadey get in, and how can it be detected **before** the second-stage payload runs? |
| PIR-2 | Which current infrastructure is linked to Amadey? |
| PIR-3 | Which log sources in my SIEM lab can see Amadey's behaviour? |
| PIR-4 | How can public reports be turned into clean, usable detection content? |

## Repository layout

```
week-01-cti-fundamentals/      glossary, classification, Amadey profile
week-02-data-collection/       collection plan, OSINT, data-source mapping
  data/raw/                    IOC files exactly as published (Talos, Trellix, Microsoft, Splunk)
  data/enrichment/             RIPEstat + Shodan InternetDB snapshot
  scripts/                     vt_lookup.py, shodan_lookup.py, ripestat_enrich.py
  evidence/                    VirusTotal + Shodan screenshots
week-03-data-processing/       MISP, normalisation pipeline, Elastic, Sigma
  misp/                        .env values, setup-misp.ps1, Windows compose override
  scripts/                     normalize → MISP → Elastic → Sigma
  evidence/                    screenshots from my running MISP 2.5.48
week-04-kill-chain/            Lockheed Martin Kill Chain analysis + ATT&CK v19 mapping
  figures/ navigator/          kill-chain diagram, ATT&CK matrix, Navigator layers
  scripts/                     build_kill_chain.py (validates IDs against ATT&CK v19.2)
  sigma/                       behavioural + generated rules, Elastic Agent pipeline
  output/                      normalised IOCs, MISP event, NDJSON, converted queries
```

## Safety & sharing

- **No malware samples** are stored here — only hashes, defanged URLs in docs, and public reports.
- All intelligence comes from public sources → **TLP:CLEAR**. Every raw file keeps its source URL and dates.
- Collection was **passive** (third-party data only; no contact with attacker infrastructure).

## AI use disclosure

AI tools used (permitted by the course instructor): **Claude Opus 5.5** and **Fable 5.1**.

## Main sources

MITRE ATT&CK S1025 / v19.2 · Lockheed Martin Intelligence-Driven Defense (2011) · Cisco Talos (Jul 2025) · Trellix (Dec 2025) · Microsoft Threat Intelligence (Jun 2026) · Splunk Threat Research (Jul 2023) · AhnLab ASEC (2022) · binaryanalys.is *Unmasking Amadey 5* · ENISA Threat Landscape 2025 · Europol / Help Net Security on Operation Endgame (Jun 2026). Full links inside each week's files.
