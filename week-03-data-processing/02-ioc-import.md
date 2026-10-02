# 2. Importing the Amadey IOCs into MISP

I import **processed** data (output of [`03-filtering-normalization.md`](03-filtering-normalization.md)), not the raw lists — garbage in a TIP becomes garbage in every SIEM that consumes it.

## 2.1 What gets imported

File: [`output/misp/amadey_misp_event.json`](output/misp/amadey_misp_event.json) — built by `scripts/build_misp_event.py`.

| Property | Value |
|---|---|
| Event info | *Amadey loader/botnet (S1025) + StealC payloads – consolidated OSINT IOCs (Talos, Trellix, Microsoft, Splunk)* |
| Threat level / analysis | Medium / Completed |
| Distribution | Your organisation only (lab) |
| Event tags | `tlp:clear`, `admiralty-scale:source-reliability="a"`, `admiralty-scale:information-credibility="2"` |
| Galaxies | `mitre-malware="Amadey - S1025"`, `malpedia="Amadey"`, `malpedia="Stealc"`, 6 × `mitre-attack-pattern` (T1053.005, T1547.001, T1071.001, T1105, T1218.011, T1553.005) |
| Attributes | **81** (sha256 28, url 20, domain 15, ip-dst 7, filename 4, text 5, mutex 1, windows-scheduled-task 1) |
| `to_ids = true` | **54** — only these are exported to SIEM/IDS |
| Per-attribute | `first_seen`/`last_seen` (report dates), comment with family/role/sources/confidence and *why not IDS*, tags `amadey-th:family=…`, `amadey-th:role=…` |
| UUIDs | Deterministic (UUIDv5) → re-import **updates** the event instead of duplicating |

All attribute **type ↔ category** pairs were validated against MISP's own `describeTypes.json` (shipped with PyMISP 2.5.34) and the file loads cleanly with `pymisp.MISPEvent.load_file()`. All galaxy/taxonomy tag names were checked against the official `misp-galaxy` and `misp-taxonomies` repositories.

## 2.2 Three ways to import

### A) UI — MISP JSON (recommended for the defense)

1. *Event Actions → Import from… → **MISP JSON***
2. Upload `amadey_misp_event.json` → *Upload*
3. Open the new event → check the attribute count (81), the tags and the galaxy matrix.

### B) UI — Freetext import (shows MISP's own parsing)

1. *Event Actions → Add Event* → info `Amadey freetext test`, distribution *Your org only* → *Submit*
2. In the event: *Populate from → **Freetext Import Tool***
3. Paste [`output/misp/freetext_import.txt`](output/misp/freetext_import.txt) (52 actionable hashes/URLs/domains)
4. MISP proposes types/categories → review → *Submit*.
   *Good comparison for the defense:* MISP guesses `sha256`, `url`, `domain` correctly, but it **cannot know** that a 32-hex string from Trellix is a *mutex*, not an MD5 — that's why the pipeline uses the declared type first.

### C) API — PyMISP

```bash
pip install pymisp
set MISP_URL=https://localhost:8443
set MISP_KEY=<auth key>
python scripts/push_to_misp.py          # add (or update) the event
python scripts/push_to_misp.py --check  # list attributes that correlate with other events/feeds
```

### Bonus: STIX 2.1 import of the original Talos bundle

*Event Actions → Import from… → STIX 2.x* → upload `week-02-data-collection/data/raw/talos_2025-07_emmenhtal-amadey.stix2.json`.

Result: MISP **correlated** the Talos event with the consolidated event on exactly the **13** predicted shared values (6 hashes, 4 URLs, 3 IPs) — a live demonstration of MISP correlation (see 2.4).

## 2.3 After import — what to show

| Screen | What it proves |
|---|---|
| Event view, attribute list filtered `to_ids = 1` | Only 54 actionable indicators would go to the SIEM |
| *Correlation graph* | Consolidated event ↔ Talos STIX event (and any feed hits) |
| *ATT&CK matrix* tab (galaxy) | Techniques attached to the event |
| An expired IP attribute (e.g. `185.215.113.43`) | `to_ids` off, comment: *expired + infrastructure offline* |
| *Download as… → Suricata / Snort / CSV / STIX 2* | MISP as a distribution hub for other tools |

## 2.4 Results in my MISP instance (2026-10-03)

| Event | Imported how | Attributes | IDS | Tags / galaxies | Notes |
|---|---|---|---|---|---|
| **#1** consolidated Amadey + StealC | A) MISP JSON (`amadey_misp_event.json`) | **81** | **54** | `tlp:clear`, Admiralty **A2**; S1025, Malpedia Amadey/StealC, 6 ATT&CK techniques — all resolved to galaxy clusters | *Related events: #2 (13 correlations)*, *extended by #3* |
| **#2** raw Talos bundle | STIX 2.1 upload (`talos_2025-07_emmenhtal-amadey.stix2.json`) | 15 + 1 object | 13 | `TLP:WHITE` (**flagged invalid by MISP**), `Threat-Report`, ATT&CK tags as **bare STIX UUIDs**, deprecated **T1158** cluster | Threat level *Undefined*, analysis *Initial*, distribution *This community* — vendor defaults, not mine |
| **#3** VirusTotal pivot leads | MISP JSON built by [`scripts/build_pivot_event.py`](scripts/build_pivot_event.py) from Week 2 [`vt_pivot_new_leads_2026-10-02.csv`](../week-02-data-collection/data/enrichment/vt_pivot_new_leads_2026-10-02.csv) | 7 | 0 | `tlp:clear`, Admiralty **B3**; S1025, T1584.004 (compromised server), T1608.001 (upload malware), T1105 | `extends_uuid` = event #1 → shows as *Extends event 1*; all leads are expired or legitimate-compromised hosts → **retro-hunt only** |

**Sightings:** the two values that VirusTotal's sandbox *confirmed* (mutex `f936986d…`, scheduled task `Yfgfwb.job`) were not duplicated into event #3 — I added a **sighting** to the event #1 attributes instead (*Sightings: 2*). One observation = one sighting; no duplicate attributes.

**Feeds:** URLhaus, MalwareBazaar, ThreatFox (recent CSV) and Feodo were cached → **0 feed hits** on event #1. Expected: those feeds hold the last 2–30 days, my indicators are 3–15 months old and the 2025 infrastructure is offline. This supports the decay decision (IPs/URLs not IDS).

### What the import itself taught me (talking points)

1. **Raw vendor STIX is not ready to use.** Event #2 shows an invalid `TLP:WHITE` tag (TLP 2.0 renamed it to `tlp:clear`), ATT&CK references as unresolved UUIDs, a deprecated technique (T1158 → T1564.001) and *every* IP marked IDS — including `185.215.113.209` and `.75` from a /24 that RIPEstat shows withdrawn from BGP since 2025-05-02. My normalised event #1 fixes all four.
2. **Correlation works on exact values** — the 13 shared values link both events automatically. The two hashes that Talos' TXT list truncated to 63 characters (`4e3951e6…`, `c62e7aca…`) could never match anything, which is why the pipeline rejects them instead of importing them.
3. **MISP normalises too:** it stored `C:\Windows\Tasks\Yfgfwb.job` as `%WINDIR%\Tasks\Yfgfwb.job`. A SIEM query built from the MISP value must expand the variable again or match only the end of the path (`\Tasks\Yfgfwb.job`).
4. **Analyst output ≠ publisher data.** My own pivots live in an *extension* event with a lower Admiralty rating (B3) instead of being mixed into the publishers' A2 event.
5. **NIDS export needs publishing.** *Download as… → Suricata* returned only the header: MISP exports IDS rules only from **published** events, so publishing is the review gate before anything reaches a sensor. Events stay unpublished in my lab until the Week 4 SIEM integration.

Screenshots: [`evidence/`](evidence/) (files 03–14).
