# 1. Collection Plan

> Lifecycle stage: **Collection**. Input = the PIRs from Week 1. Output = raw data in [`data/raw/`](data/raw/) + enrichment in [`data/enrichment/`](data/enrichment/).

## 1.1 Requirements → what I collect

| PIR | Question | What I need to collect | Source |
|---|---|---|---|
| PIR-1 | How does Amadey get in / how to detect it early? | Infection-chain reports, persistence artefacts, process trees | Vendor reports, VirusTotal *Behavior* tab |
| PIR-2 | Which infrastructure is linked to Amadey? | C2 URLs, IPs, domains, ASNs, hosting patterns | Reports, Shodan, RIPEstat, Maltego pivots |
| PIR-3 | Which logs can see it? | Mapping TTP → data source → event ID | MITRE ATT&CK data sources, Sysmon docs |
| PIR-4 | Clean, usable IOCs? | Machine-readable IOC sets (TXT, STIX) | Talos IOC repo, vendor tables |

## 1.2 Open vs. closed sources

| | Open source (OSINT) | Closed source |
|---|---|---|
| Examples | Vendor blogs, Talos IOC GitHub, VirusTotal public, Shodan, RIPEstat, ATT&CK | Commercial feeds (Recorded Future, Mandiant), ISAC sharing, internal SIEM/EDR logs, dark-web access |
| Cost | Free / free tier | Paid or membership |
| Timeliness | Days–months after the campaign | Hours–days |
| Used in this project | ✅ everything in this repo | ❌ not available to students → noted as a limitation |

## 1.3 Sources selected

| # | Source | Type | Admiralty | Why |
|---|---|---|---|---|
| S1 | Cisco Talos blog + IOC repo (Jul 2025) | Vendor OSINT, STIX 2.1 | A2 | Machine-readable, recent MaaS campaign |
| S2 | Trellix ARC blog (Dec 2025) | Vendor OSINT | A2 | Full v5.70 chain incl. mutex, paths, task |
| S3 | Microsoft Threat Intelligence (Jun 2026) | Vendor OSINT | A2 | 11 Amadey builds 5.60–5.87, C2 list, takedown context |
| S4 | Splunk Threat Research (Jul 2023) | Vendor OSINT | A2 | Older v3.83 + plugin hashes → version history |
| S5 | **VirusTotal** (public API v3) | Community/sandbox | B3 | Detection ratio, names, behaviour, relations |
| S6 | **Shodan** (InternetDB + host API) | Internet scan | B3 | Is C2 infrastructure still alive? What runs on it? |
| S7 | **Maltego** (CE / free tier) | Link analysis | — (tool) | Visual pivoting: sample → C2 → IP → ASN → other malware |
| S8 | RIPEstat | Registry (RIR) | A1 | Authoritative netblock / ASN / BGP status |
| S9 | MITRE ATT&CK S1025 | Knowledge base | A2 | Technique list, data sources |

## 1.4 OPSEC rules for collection

1. **Passive only.** No browsing to C2 URLs, no `curl` to attacker hosts — only third-party data (VT, Shodan, RIPE).
2. **Never upload** samples or URLs to VirusTotal for scanning — search existing reports only (uploading can tip off the actor, and files become public).
3. **No malware samples on personal machines.** Hash look-ups only; any detonation only in an isolated lab VM.
4. **Defang everything** I write (`hxxp`, `[.]`) except in machine-readable outputs.
5. **Respect TLP.** All my sources are TLP:CLEAR, so the repo can be public.
6. **Record provenance**: every file in `data/raw/` keeps source URL, publish date, collection date (see [`data/raw/SOURCES.md`](data/raw/SOURCES.md)).

## 1.5 Collection results (counts)

| Source | Hashes | URLs | IPs | Domains | Host artefacts | Total raw |
|---|---|---|---|---|---|---|
| Talos TXT | 8 | 4 | 3 | — | — | 15 |
| Talos STIX 2.1 | 6 | 4 | 3 | — | — | 13 indicators |
| Trellix | 3 | 4 | 2 | 2 | 11 | 22 |
| Microsoft | 15 | 12 | — | — | — | 27 |
| Splunk | 4 | — | — | — | — | 4 |
| **Total** | **36** | **24** | **8** | **2** | **11** | **81** |

Duplicates, truncated values and non-Amadey (StealC) indicators are expected — they are cleaned in Week 3.
