#!/usr/bin/env python3
"""
ripestat_enrich.py — passive WHOIS / ASN / routing enrichment of IPs via RIPEstat (no API key).

Usage:
    python ripestat_enrich.py ips.txt -o ../data/enrichment/ripestat.csv

For every IP: netblock (inetnum), netname, org, country, origin ASN, ASN holder,
and whether the prefix is still announced in BGP (offline infrastructure = decayed IOC).
"""
import argparse
import csv
import ipaddress
import json
import time
import urllib.request

BASE = "https://stat.ripe.net/data"


def get(endpoint, resource):
    url = f"{BASE}/{endpoint}/data.json?resource={resource}&sourceapp=amadey-th-student"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r).get("data", {})


def whois_fields(ip):
    d = get("whois", ip)
    out = {}
    for rec in d.get("records", []):
        for kv in rec:
            k, v = kv.get("key", "").lower(), kv.get("value", "")
            if k in ("inetnum", "netname", "org", "country", "origin", "route") and k not in out:
                out[k] = v
    for rec in d.get("irr_records", []):
        for kv in rec:
            k = kv.get("key", "").lower()
            if k in ("origin", "route") and k not in out:
                out[k] = kv.get("value", "")
    # inetnum is usually a range "a.b.c.0 - a.b.c.255" -> convert to CIDR for the routing lookup
    rng = out.get("inetnum", "")
    if " - " in rng:
        lo, hi = (ipaddress.IPv4Address(x.strip()) for x in rng.split(" - "))
        out["inetnum"] = ",".join(str(n) for n in ipaddress.summarize_address_range(lo, hi))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ips")
    ap.add_argument("-o", "--out", default="ripestat.csv")
    a = ap.parse_args()

    ips = [l.split("#", 1)[0].strip().replace("[.]", ".") for l in open(a.ips, encoding="utf-8")]
    ips = [i for i in ips if i]
    rows = []
    for ip in ips:
        w = whois_fields(ip)
        asn = w.get("origin", "").upper().replace("AS", "")
        holder = get("as-overview", f"AS{asn}").get("holder", "") if asn else ""
        prefix = w.get("route") or w.get("inetnum", "")
        rs = get("routing-status", prefix) if prefix and "/" in prefix else {}
        announced = "yes" if rs.get("origins") else "no"
        last = (rs.get("last_seen") or {}).get("time", "")
        rows.append({"ip": ip, "netblock": w.get("inetnum", ""), "netname": w.get("netname", ""),
                     "org": w.get("org", ""), "country": w.get("country", ""), "origin_asn": f"AS{asn}" if asn else "",
                     "asn_holder": holder, "prefix_announced": announced, "last_seen": last})
        print(rows[-1])
        time.sleep(1)

    with open(a.out, "w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"Saved {a.out}")


if __name__ == "__main__":
    main()
