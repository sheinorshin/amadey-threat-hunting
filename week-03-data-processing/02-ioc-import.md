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

MISP should then **correlate** the Talos event with the consolidated event (up to 13 shared values) — a live demonstration of MISP correlation.

## 2.3 After import — what to show

| Screen | What it proves |
|---|---|
| Event view, attribute list filtered `to_ids = 1` | Only 54 actionable indicators would go to the SIEM |
| *Correlation graph* | Consolidated event ↔ Talos STIX event (and any feed hits) |
| *ATT&CK matrix* tab (galaxy) | Techniques attached to the event |
| An expired IP attribute (e.g. `185.215.113.43`) | `to_ids` off, comment: *expired + infrastructure offline* |
| *Download as… → Suricata / Snort / CSV / STIX 2* | MISP as a distribution hub for other tools |
