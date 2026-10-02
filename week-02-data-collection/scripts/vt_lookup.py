#!/usr/bin/env python3
"""
vt_lookup.py — look up Amadey IOCs in VirusTotal (API v3, free/public key).

Usage:
    set VT_API_KEY=<your key>          (Windows)   |  export VT_API_KEY=<your key>  (Linux)
    python vt_lookup.py targets.txt -o ../data/enrichment/vt_results.csv

targets.txt: one indicator per line (hash / IP / domain / URL). Defanged values
(hxxp, [.], [:]) are accepted and refanged automatically. Lines starting with # are ignored.

Notes:
  * Public API quota = 4 requests/minute, 500/day -> the script sleeps 15.5 s between calls.
  * Read-only: it never uploads files or submits URLs for scanning (OPSEC: don't tip off the actor).
  * Standard library only — no pip install required.
"""
import argparse
import base64
import csv
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3"
SLEEP = 15.5

RE_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def refang(v: str) -> str:
    v = v.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def classify(v: str) -> str:
    if RE_HASH.match(v):
        return "file"
    if RE_IPV4.match(v):
        return "ip"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    return "domain"


def endpoint(kind: str, v: str) -> str:
    if kind == "file":
        return f"{API}/files/{v.lower()}"
    if kind == "ip":
        return f"{API}/ip_addresses/{v}"
    if kind == "domain":
        return f"{API}/domains/{v.lower()}"
    url_id = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
    return f"{API}/urls/{url_id}"


def ts(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d") if epoch else ""


def query(url: str, key: str) -> dict:
    req = urllib.request.Request(url, headers={"x-apikey": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_status": "not_found"}
        if e.code == 429:
            return {"_status": "quota_exceeded"}
        return {"_status": f"http_{e.code}"}


def summarise(kind: str, v: str, data: dict) -> dict:
    row = {"indicator": v, "type": kind, "status": data.get("_status", "found")}
    a = data.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    row["malicious"] = stats.get("malicious", "")
    row["suspicious"] = stats.get("suspicious", "")
    row["harmless_undetected"] = (stats.get("harmless", 0) + stats.get("undetected", 0)) if stats else ""
    row["last_analysis"] = ts(a.get("last_analysis_date"))
    if kind == "file":
        ptc = a.get("popular_threat_classification", {})
        row["label"] = ptc.get("suggested_threat_label", "")
        row["first_seen"] = ts(a.get("first_submission_date"))
        row["names"] = ";".join(a.get("names", [])[:5])
        row["file_type"] = a.get("type_description", "")
        row["tags"] = ";".join(a.get("tags", []))
    elif kind == "ip":
        row["label"] = a.get("as_owner", "")
        row["names"] = f"AS{a.get('asn', '')} {a.get('country', '')}"
    elif kind == "domain":
        row["label"] = a.get("registrar", "")
        row["first_seen"] = ts(a.get("creation_date"))
        row["tags"] = ";".join(a.get("tags", []))
    else:
        row["label"] = a.get("title", "")
        row["first_seen"] = ts(a.get("first_submission_date"))
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets")
    ap.add_argument("-o", "--out", default="vt_results.csv")
    args = ap.parse_args()

    key = os.environ.get("VT_API_KEY")
    if not key:
        sys.exit("Set VT_API_KEY first (VirusTotal -> profile -> API key).")

    items = []
    with open(args.targets, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                v = refang(line.split()[0])
                items.append((classify(v), v))

    fields = ["indicator", "type", "status", "malicious", "suspicious", "harmless_undetected",
              "label", "first_seen", "last_analysis", "file_type", "names", "tags"]
    with open(args.out, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for i, (kind, v) in enumerate(items, 1):
            data = query(endpoint(kind, v), key)
            row = summarise(kind, v, data)
            w.writerow(row)
            print(f"[{i}/{len(items)}] {kind:6} {v[:70]:70} -> {row['status']} mal={row['malicious']} {row.get('label','')}")
            if data.get("_status") == "quota_exceeded":
                print("Quota exceeded — stopping. Re-run later with the remaining lines.")
                break
            if i < len(items):
                time.sleep(SLEEP)
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
