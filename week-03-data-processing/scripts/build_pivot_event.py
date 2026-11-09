#!/usr/bin/env python3
"""
build_pivot_event.py - turn the Week 2 VirusTotal pivot leads into a MISP *extension* event.

Input : ../../week-02-data-collection/data/enrichment/vt_pivot_new_leads_2026-10-02.csv
Output: output/misp/amadey_vt_pivot_event.json   (Event Actions -> Import from... -> MISP JSON)

Why a separate event?  The consolidated event (#1) holds what *publishers* reported.  These leads are
*my own* analysis (VirusTotal relations + sandbox of the Trellix Amadey 5.70 sample d7a366fa), so they
go into an event that EXTENDS event #1 (MISP "extends_uuid") instead of silently changing it.

Rows that only CONFIRM values already in event #1 (mutex, scheduled task) are not duplicated:
they are recorded as MISP *sightings* on the event #1 attributes (source: VirusTotal sandbox).

The same decay policy as normalize_iocs.py is applied (URL/domain 180 days, IP 90 days, as-of 2026-10-02),
so every network lead is expired -> to_ids = false -> used for retro-hunting in old logs, not for blocking.
Standard library only; deterministic UUIDs (same namespace as build_misp_event.py).
"""
import csv
import json
import uuid
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
IN = ROOT / "week-02-data-collection" / "data" / "enrichment" / "vt_pivot_new_leads_2026-10-02.csv"
OUT = HERE.parent / "output" / "misp"
NS = uuid.UUID("6f1c2a3e-0d6b-4a43-9a8e-a1b2c3d4e5f6")
AS_OF = date(2026, 10, 2)
SAMPLE_FIRST_SEEN = date(2025, 11, 20)        # first VT submission of d7a366fa (contacted hosts seen from then)
TTL_DAYS = {"url": 180, "domain": 180, "ip": 90}
EXTENDS = str(uuid.uuid5(NS, "event|amadey-week3"))   # UUID of the consolidated event #1

MISP_MAP = {
    "url":       ("Network activity",  "url"),
    "domain":    ("Network activity",  "domain"),
    "ip":        ("Network activity",  "ip-dst"),
    "file_path": ("Artifacts dropped", "filename"),
}
ROLE = {
    "werdigo": "payload-host", "gitd3ti": "payload-host", "203.6.149.147": "payload-host",
    "Plugins": "plugin", "scr=1": "c2", "10000210101": "host-artefact",
}
EVENT_TAGS = [
    "tlp:clear",
    'admiralty-scale:source-reliability="b"',        # VirusTotal: usually reliable aggregator
    'admiralty-scale:information-credibility="3"',   # possibly true: one sample, one sandbox, not yet confirmed
    'misp-galaxy:mitre-malware="Amadey - S1025"',
    'misp-galaxy:mitre-attack-pattern="Server - T1584.004"',          # compromised university GitLab
    'misp-galaxy:mitre-attack-pattern="Upload Malware - T1608.001"',  # payload staged in a GitLab repo
    'misp-galaxy:mitre-attack-pattern="Ingress Tool Transfer - T1105"',
]


def role_of(value):
    for key, role in ROLE.items():
        if key in value:
            return role
    return "lead"


def main():
    rows = list(csv.DictReader(IN.open(encoding="utf-8")))
    attrs, sightings = [], []
    for r in rows:
        if r["assessment"].startswith("CONFIRMS"):
            sightings.append(r)
            continue
        category, mtype = MISP_MAP[r["type"]]
        first = date.fromisoformat(r["vt_first_scan"]) if r["vt_first_scan"] else SAMPLE_FIRST_SEEN
        reasons = []
        ttl = TTL_DAYS.get(r["type"])
        if ttl and first + timedelta(days=ttl) < AS_OF:
            reasons.append(f"expired {first + timedelta(days=ttl)} (TTL {ttl} d)")
        if r["http_status"] == "404":
            reasons.append("payload removed (HTTP 404)")
        if r["type"] in ("domain", "ip") and ("gitd3ti" in r["indicator"] or "GitLab" in r["assessment"]):
            reasons.append("legitimate compromised host - block the URL path, not the host")
        if r["type"] == "file_path":
            reasons.append("folder number varies per infection - hunt with a pattern, not the exact path")
        comment = f"VT pivot lead | found via: {r['found_via']} | VT: {r['vt_detections'] or 'n/a'}"
        comment += f" | {r['assessment']}"
        if reasons:
            comment += " | not IDS: " + "; ".join(reasons) + " -> retro-hunt only"
        attrs.append({
            "uuid": str(uuid.uuid5(NS, f"pivot|{r['type']}|{r['indicator']}")),
            "type": mtype,
            "category": category,
            "value": r["indicator"],
            "to_ids": not reasons,
            "comment": comment[:1000],
            "distribution": "5",
            "first_seen": f"{first.isoformat()}T00:00:00+00:00",
            "Tag": [{"name": 'amadey-th:family="amadey"'},
                    {"name": f'amadey-th:role="{role_of(r["indicator"])}"'},
                    {"name": 'amadey-th:lead="vt-pivot"'}],
        })

    event = {
        "Event": {
            "uuid": str(uuid.uuid5(NS, "event|amadey-vt-pivot")),
            "info": "Amadey 5.70 sample d7a366fa (Trellix) - VirusTotal pivot leads (analyst enrichment, extends consolidated event)",
            "date": AS_OF.isoformat(),
            "threat_level_id": "2",
            "analysis": "1",             # ongoing - leads still to be confirmed
            "distribution": "0",
            "published": False,
            "extends_uuid": EXTENDS,
            "Tag": [{"name": t} for t in EVENT_TAGS],
            "Attribute": attrs,
        }
    }
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / "amadey_vt_pivot_event.json"
    out.write_text(json.dumps(event, indent=2), encoding="utf-8")
    print(f"Pivot event: {len(attrs)} attributes ({sum(a['to_ids'] for a in attrs)} to_ids), extends {EXTENDS} -> {out}")
    for s in sightings:
        print(f"Sighting for event #1 attribute {s['type']} = {s['indicator']}  (source: VirusTotal sandbox of d7a366fa)")


if __name__ == "__main__":
    main()
