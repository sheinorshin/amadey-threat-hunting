#!/usr/bin/env python3
"""
query.py - run one ES|QL query against the local Elasticsearch and print it as a table.
For the no-Kibana path: start Elasticsearch only, load the data, then run the .esql files here.

Usage:
  python3 query.py ../week-05-threat-hunting/queries/h1_script_host_powershell.esql
  echo 'FROM logs-* | STATS n = COUNT(*) BY event.code | SORT n DESC' | python3 query.py -
  python3 query.py - "FROM logs-system.security-* | WHERE event.code==\"4698\" | KEEP winlog.event_data.TaskName"

Reads the file, drops // comment lines (so the active query remains), sends it to
POST /_query?format=txt and prints the ASCII table Elasticsearch returns.
Standard library only. ES at http://localhost:9200 (override with ES_URL env var).
"""
import json
import os
import sys
import urllib.error
import urllib.request

ES = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")


def read_query():
    if len(sys.argv) > 2:
        return sys.argv[2]
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("//") and ln.strip()]
    q = "\n".join(lines).strip()
    # The data is loaded into ith-* indices (the logs-* names collide with Elasticsearch's built-in
    # data-stream template). Retarget the queries' FROM so the files stay generic.
    for pat in ("logs-windows.powershell_operational-*", "logs-system.security-*", "logs-*"):
        q = q.replace(pat, "ith-*")
    return q


def main():
    q = read_query()
    if not q:
        sys.exit("no query given")
    body = json.dumps({"query": q}).encode()
    req = urllib.request.Request(ES + "/_query?format=txt", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        print("ERROR", e.code)
        print(e.read().decode())
    except Exception as e:
        sys.exit(f"cannot reach Elasticsearch at {ES} - is it up? ({e})")


if __name__ == "__main__":
    main()
