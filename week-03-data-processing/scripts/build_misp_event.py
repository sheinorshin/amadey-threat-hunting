#!/usr/bin/env python3
"""
build_misp_event.py — convert output/iocs_normalized.json into a MISP event (MISP JSON format).

Result: output/misp/amadey_misp_event.json
Import in MISP UI:  Event Actions -> Import from... -> "MISP JSON"   (or use push_to_misp.py)

Also writes output/misp/freetext_import.txt for the "Populate from -> Freetext Import" tool.
Standard library only.  UUIDs are deterministic, so re-importing updates instead of duplicating.
"""
import json
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
IN = HERE.parent / "output" / "iocs_normalized.json"
OUT = HERE.parent / "output" / "misp"
NS = uuid.UUID("6f1c2a3e-0d6b-4a43-9a8e-a1b2c3d4e5f6")

# our type -> (MISP category, MISP attribute type)
MISP_MAP = {
    "sha256":         ("Payload delivery",  "sha256"),
    "md5":            ("Payload delivery",  "md5"),
    "sha1":           ("Payload delivery",  "sha1"),
    "url":            ("Network activity",  "url"),
    "domain":         ("Network activity",  "domain"),
    "ip":             ("Network activity",  "ip-dst"),
    "mutex":          ("Artifacts dropped", "mutex"),
    "filename":       ("Artifacts dropped", "filename"),
    "directory":      ("Artifacts dropped", "text"),
    "scheduled_task": ("Artifacts dropped", "windows-scheduled-task"),
    "bot_id":         ("Other",             "text"),
    "crypto_key":     ("Other",             "text"),
}

EVENT_TAGS = [
    "tlp:clear",
    'admiralty-scale:source-reliability="a"',
    'admiralty-scale:information-credibility="2"',
    'misp-galaxy:mitre-malware="Amadey - S1025"',
    'misp-galaxy:malpedia="Amadey"',
    'misp-galaxy:malpedia="Stealc"',
    'misp-galaxy:mitre-attack-pattern="Scheduled Task - T1053.005"',
    'misp-galaxy:mitre-attack-pattern="Registry Run Keys / Startup Folder - T1547.001"',
    'misp-galaxy:mitre-attack-pattern="Web Protocols - T1071.001"',
    'misp-galaxy:mitre-attack-pattern="Ingress Tool Transfer - T1105"',
    'misp-galaxy:mitre-attack-pattern="Rundll32 - T1218.011"',
    'misp-galaxy:mitre-attack-pattern="Mark-of-the-Web Bypass - T1553.005"',
]


def main():
    data = json.loads(IN.read_text(encoding="utf-8"))
    attrs = []
    for ioc in data["indicators"]:
        category, mtype = MISP_MAP[ioc["type"]]
        comment = f"{ioc['family']} {ioc['role']} | src: {ioc['sources']} | conf: {ioc['confidence']} ({ioc['confidence_score']})"
        if ioc["type"] == "directory":
            comment = "directory path | " + comment
        if ioc["type"] in ("bot_id", "crypto_key"):
            comment = f"{ioc['type']} | " + comment
        if ioc["filter_reasons"]:
            comment += f" | not IDS: {ioc['filter_reasons']}"
        tags = [{"name": f"amadey-th:family=\"{ioc['family'].lower()}\""},
                {"name": f"amadey-th:role=\"{ioc['role']}\""}]
        a = {
            "uuid": ioc["uuid"],
            "type": mtype,
            "category": category,
            "value": ioc["value"],
            "to_ids": bool(ioc["to_ids"]),
            "comment": comment[:1000],
            "distribution": "5",                    # inherit event distribution
            "first_seen": f"{ioc['first_seen']}T00:00:00+00:00",
            "last_seen": f"{ioc['last_seen']}T00:00:00+00:00",
            "Tag": tags,
        }
        attrs.append(a)

    event = {
        "Event": {
            "uuid": str(uuid.uuid5(NS, "event|amadey-week3")),
            "info": "Amadey loader/botnet (S1025) + StealC payloads - consolidated OSINT IOCs (Talos, Trellix, Microsoft, Splunk)",
            "date": data["generated"],
            "threat_level_id": "2",      # medium
            "analysis": "2",             # completed
            "distribution": "0",         # your organisation only
            "published": False,
            "Tag": [{"name": t} for t in EVENT_TAGS],
            "Attribute": attrs,
        }
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "amadey_misp_event.json").write_text(json.dumps(event, indent=2), encoding="utf-8")

    # Freetext import: only actionable network/hash values, one per line
    ft = [i["value"] for i in data["indicators"] if i["to_ids"] and i["type"] in ("sha256", "url", "domain", "ip")]
    (OUT / "freetext_import.txt").write_text("\n".join(ft) + "\n", encoding="utf-8")

    n_ids = sum(a["to_ids"] for a in attrs)
    print(f"MISP event: {len(attrs)} attributes ({n_ids} to_ids) -> {OUT/'amadey_misp_event.json'}")
    print(f"Freetext list: {len(ft)} values -> {OUT/'freetext_import.txt'}")


if __name__ == "__main__":
    main()
