#!/usr/bin/env python3
"""
shodan_lookup.py — check Amadey-related IPs in Shodan.

Two modes:
  --internetdb   free, no API key (https://internetdb.shodan.io) — ports, hostnames, CPEs, tags
  (default)      full host lookup with SHODAN_API_KEY — adds org, ISP, ASN, banners, HTTP titles

Usage:
    python shodan_lookup.py ips.txt --internetdb -o ../data/enrichment/internetdb.csv
    set SHODAN_API_KEY=<key> & python shodan_lookup.py ips.txt -o ../data/enrichment/shodan_hosts.csv

ips.txt: one IP per line, defanged values accepted. Standard library only.
Passive only: Shodan returns *its own* scan data; the script never touches the target host.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def refang(v):
    return v.strip().replace("[.]", ".").replace("(.)", ".")


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_status": "no_data" if e.code == 404 else f"http_{e.code}"}


def internetdb(ip):
    d = get(f"https://internetdb.shodan.io/{ip}")
    return {
        "ip": ip, "status": d.get("_status", "found"),
        "ports": ";".join(map(str, d.get("ports", []))),
        "hostnames": ";".join(d.get("hostnames", [])),
        "cpes": ";".join(d.get("cpes", [])),
        "tags": ";".join(d.get("tags", [])),
        "vulns_count": len(d.get("vulns", [])) if "vulns" in d else "",
    }


def host(ip, key):
    d = get(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    titles = sorted({(b.get("http") or {}).get("title", "") for b in d.get("data", []) if b.get("http")} - {""})
    products = sorted({b.get("product", "") for b in d.get("data", [])} - {""})
    return {
        "ip": ip, "status": d.get("_status", "found"),
        "org": d.get("org", ""), "isp": d.get("isp", ""), "asn": d.get("asn", ""),
        "country": d.get("country_name", ""), "last_update": d.get("last_update", ""),
        "ports": ";".join(map(str, d.get("ports", []))),
        "hostnames": ";".join(d.get("hostnames", [])),
        "products": ";".join(products), "http_titles": ";".join(titles),
        "tags": ";".join(d.get("tags", [])),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ips")
    ap.add_argument("--internetdb", action="store_true")
    ap.add_argument("-o", "--out", default="shodan_results.csv")
    a = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not a.internetdb and not key:
        sys.exit("Set SHODAN_API_KEY or use --internetdb.")

    ips = [refang(l.split("#", 1)[0]) for l in open(a.ips, encoding="utf-8")]
    ips = [i for i in ips if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", i)]

    rows = []
    for ip in ips:
        r = internetdb(ip) if a.internetdb else host(ip, key)
        rows.append(r)
        print(f"{ip:16} {r['status']:8} ports={r['ports']} hosts={r['hostnames']}")
        time.sleep(1.1)  # Shodan API: max 1 req/s

    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["ip"])
        w.writeheader()
        w.writerows(rows)
    print(f"Saved {a.out}")


if __name__ == "__main__":
    main()
