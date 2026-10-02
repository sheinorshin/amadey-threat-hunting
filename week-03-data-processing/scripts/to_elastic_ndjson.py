#!/usr/bin/env python3
"""
to_elastic_ndjson.py — export actionable (to_ids) indicators as ECS threat-indicator documents
for Elasticsearch, so a Kibana *Indicator Match* rule can compare lab logs against them.

Output:
  output/elastic/ti-amadey.bulk.ndjson      -> POST /_bulk
  output/elastic/ti-amadey.mapping.json     -> PUT /ti-amadey (create index first)

Load (from the CentOS VM, adjust auth):
  curl -k -u elastic -X PUT  "https://localhost:9200/ti-amadey" -H "Content-Type: application/json" --data-binary @ti-amadey.mapping.json
  curl -k -u elastic -X POST "https://localhost:9200/_bulk"    -H "Content-Type: application/x-ndjson" --data-binary @ti-amadey.bulk.ndjson

Standard library only.  (Preferred long-term path: Elastic "Threat Intelligence -> MISP" integration
pulling straight from MISP; this file is the offline alternative.)
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
IN = HERE.parent / "output" / "iocs_normalized.json"
OUT = HERE.parent / "output" / "elastic"
INDEX = "ti-amadey"

ECS_TYPE = {"sha256": "file", "url": "url", "domain": "domain-name", "ip": "ipv4-addr",
            "mutex": "mutex", "scheduled_task": "windows-scheduled-task"}

MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"kind": {"type": "keyword"}, "category": {"type": "keyword"},
                                     "type": {"type": "keyword"}, "dataset": {"type": "keyword"}}},
            "threat": {"properties": {
                "feed": {"properties": {"name": {"type": "keyword"}}},
                "software": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}},
                "indicator": {"properties": {
                    "type": {"type": "keyword"},
                    "ip": {"type": "ip"},
                    "file": {"properties": {"hash": {"properties": {"sha256": {"type": "keyword"}}}}},
                    "url": {"properties": {"full": {"type": "keyword"}, "domain": {"type": "keyword"},
                                           "path": {"type": "keyword"}}},
                    "description": {"type": "text"},
                    "provider": {"type": "keyword"},
                    "confidence": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "modified_at": {"type": "date"},
                    "marking": {"properties": {"tlp": {"type": "keyword"}}},
                }},
            }},
            "tags": {"type": "keyword"},
        }
    }
}


def doc(ioc, as_of):
    ind = {"type": ECS_TYPE.get(ioc["type"], "other"), "provider": ioc["sources"],
           "confidence": ioc["confidence"], "first_seen": ioc["first_seen"], "last_seen": ioc["last_seen"],
           "modified_at": as_of, "marking": {"tlp": "CLEAR"},
           "description": f"{ioc['family']} {ioc['role']}"}
    t, v = ioc["type"], ioc["value"]
    if t == "sha256":
        ind["file"] = {"hash": {"sha256": v}}
    elif t == "ip":
        ind["ip"] = v
    elif t == "domain":
        ind["url"] = {"domain": v}
    elif t == "url":
        host_path = v.split("://", 1)[1]
        host, _, path = host_path.partition("/")
        ind["url"] = {"full": v, "domain": host.split(":")[0], "path": "/" + path}
    else:
        ind["description"] += f" | {t}: {v}"
    fam = "Amadey" if ioc["family"].startswith("Amadey") else ioc["family"]
    return {
        "@timestamp": f"{as_of}T00:00:00Z",
        "event": {"kind": "enrichment", "category": ["threat"], "type": ["indicator"], "dataset": "ti_custom.amadey"},
        "threat": {"feed": {"name": "AITU Threat Hunting - Amadey"},
                   "software": {"name": fam, "id": "S1025" if fam == "Amadey" else ""},
                   "indicator": ind},
        "tags": ["amadey-project", ioc["family"].lower(), ioc["role"]],
    }


def main():
    data = json.loads(IN.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    lines, n = [], 0
    for ioc in data["indicators"]:
        if not ioc["to_ids"]:
            continue
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": ioc["uuid"]}}))
        lines.append(json.dumps(doc(ioc, data["generated"])))
        n += 1
    (OUT / f"{INDEX}.bulk.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / f"{INDEX}.mapping.json").write_text(json.dumps(MAPPING, indent=2), encoding="utf-8")
    print(f"{n} ECS indicator docs -> {OUT / (INDEX + '.bulk.ndjson')}")


if __name__ == "__main__":
    main()
