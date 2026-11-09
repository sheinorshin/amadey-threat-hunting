#!/usr/bin/env python3
"""
load_synthetic.py - load the Week 5 synthetic ECS dataset into the local Elasticsearch
(from docker-compose.yml) so the project's hunt / CAR queries can run.

Elasticsearch ships a built-in "logs" template that forces any index named logs-*-* to be a
data stream, which blocks a plain index. So we load each dataset into a normal index with a
non-colliding name (ith-...) mapped all-keyword, then point a logs-<dataset>-default ALIAS at it.
The queries' "FROM logs-system.security-*" then resolves to the alias - no query change needed.

Usage (where Elasticsearch runs, security disabled):
  python3 load_synthetic.py                        # uses http://localhost:9200
  python3 load_synthetic.py http://localhost:9200  # or pass the URL

Standard library only. Re-running is safe: each index is deleted and recreated.
"""
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

ES = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9200").rstrip("/")
DATA = Path(__file__).resolve().parent.parent / "week-05-threat-hunting" / "data" / "dataset.ndjson"

MAPPING = {
    "settings": {"number_of_replicas": 0},
    "mappings": {
        "dynamic_templates": [
            {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 8192}}}
        ],
        "properties": {"@timestamp": {"type": "date"}},
    },
}


def req(method, path, body=None, ctype="application/json"):
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(ES + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    if not DATA.exists():
        sys.exit(f"dataset not found: {DATA}")
    try:
        req("GET", "/")
    except Exception as e:
        sys.exit(f"cannot reach Elasticsearch at {ES} - is it up? ({e})")

    by_ds = defaultdict(list)
    for line in DATA.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        by_ds[ev.get("data_stream", {}).get("dataset", "misc")].append(ev)

    for ds, events in by_ds.items():
        index = "ith-" + ds.replace(".", "-")          # plain index name, no logs-* template conflict
        req("DELETE", "/" + index)
        code, resp = req("PUT", "/" + index, json.dumps(MAPPING))
        if code >= 300:
            print(f"! could not create {index} (HTTP {code}): {resp[:160]}")
            continue
        bulk = []
        for ev in events:
            bulk.append(json.dumps({"index": {"_index": index}}))
            bulk.append(json.dumps(ev))
        code, resp = req("POST", f"/{index}/_bulk?refresh=true", "\n".join(bulk) + "\n", "application/x-ndjson")
        ok = code < 300 and not json.loads(resp).get("errors", True)
        cnt_code, cnt_resp = req("GET", f"/{index}/_count")
        cnt = json.loads(cnt_resp).get("count", "?") if cnt_code < 300 else "?"
        print(f"{index:38} {cnt} / {len(events)} indexed  {'OK' if ok else 'HAD ERRORS'}")
        if not ok:
            print("   first 300 chars of response:", resp[:300])

    code, resp = req("GET", "/ith-*/_count")
    total = json.loads(resp).get("count", "?") if code < 300 else "?"
    print(f"\nTotal in ith-* : {total}  (expected 976)")
    print("Now run the queries with lab/query.py - it retargets logs-* to ith-* automatically.")


if __name__ == "__main__":
    main()
