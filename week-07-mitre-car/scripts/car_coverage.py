#!/usr/bin/env python3
"""
car_coverage.py - Week 7: which of Amadey's ATT&CK techniques does MITRE CAR cover?

1. Reads the list of CAR analytics from https://car.mitre.org/analytics/ and downloads each analytic's YAML
   from the public CAR repository (cached in ~/.cache/car/).
2. Writes a compact catalogue: data/car_analytics.json (id, title, date, types, platforms, ATT&CK coverage,
   implementation languages, data-model references, D3FEND mappings).
3. Checks every CAR technique ID against ATT&CK v19.2 (CAR was last updated in 2022, so some IDs moved).
4. Crosses CAR with the 40 Amadey techniques of Week 4 (week-04-kill-chain/data/amadey_kill_chain.json):
   data/amadey_car_coverage.json + navigator/amadey_car_coverage_layer.json
   score 3 = CAR analytic implemented in my SIEM this week, 2 = a CAR analytic covers the sub-technique,
   1 = CAR covers only the parent technique, 0 = no CAR analytic.

Usage:  python car_coverage.py [--stix PATH]
Needs:  PyYAML (pip install pyyaml); the ATT&CK v19.2 bundle (downloaded by the Week 4/6 scripts)
"""
import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
INDEX_URL = "https://car.mitre.org/analytics/"
YAML_URL = "https://raw.githubusercontent.com/mitre-attack/car/master/analytics/{}.yaml"
CACHE = Path(os.path.expanduser("~/.cache/car"))
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
IMPLEMENTED = {"CAR-2021-12-001": "primary", "CAR-2013-08-001": "baseline"}   # what this week puts in the SIEM


def fetch(url, path):
    """Download once into the cache; be polite (pause between requests, back off on HTTP 429)."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ITH course project)"})
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    path.write_bytes(r.read())
                break
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt == 5:
                    raise
                time.sleep(5 * 2 ** attempt)
        time.sleep(1)
    return path.read_text(encoding="utf-8")


def attack_status(stix_path):
    if not stix_path.exists():
        stix_path.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(STIX_URL, stix_path)
    objs = json.loads(stix_path.read_text(encoding="utf-8"))["objects"]
    ext = {}
    for o in objs:
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                ext[o["id"]] = r.get("external_id")
    status, names = {}, {}
    for o in objs:
        if o["type"] != "attack-pattern" or o["id"] not in ext:
            continue
        tid = ext[o["id"]]
        st = "revoked" if o.get("revoked") else "deprecated" if o.get("x_mitre_deprecated") else "active"
        if st == "active" or tid not in status:
            status[tid], names[tid] = st, o["name"]
    replaced = {}
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "revoked-by":
            src, dst = ext.get(o["source_ref"]), ext.get(o["target_ref"])
            if src and dst:
                replaced[src] = dst
    return status, names, replaced


def catalogue():
    ids = sorted(set(re.findall(r"CAR-\d{4}-\d{2}-\d{3}", fetch(INDEX_URL, CACHE / "index.html"))))
    out = []
    for cid in ids:
        a = yaml.safe_load(fetch(YAML_URL.format(cid), CACHE / f"{cid}.yaml"))
        cov = a.get("coverage") or []
        out.append({
            "id": cid, "title": a.get("title"), "submitted": str(a.get("submission_date")),
            "analytic_types": a.get("analytic_types", []), "platforms": a.get("platforms", []),
            "coverage": [{"technique": c.get("technique"), "subtechniques": c.get("subtechniques") or [],
                          "tactics": c.get("tactics") or [], "level": c.get("coverage")} for c in cov],
            "implementations": sorted({str(i.get("type", "?")).lower() for i in a.get("implementations") or []}),
            "data_model_references": a.get("data_model_references") or [],
            "d3fend": [m.get("id") for m in a.get("d3fend_mappings") or []],
            "unit_tests": len(a.get("unit_tests") or []),
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stix", default=os.path.expanduser("~/.cache/attack/enterprise-attack-19.2.json"))
    a = ap.parse_args()
    cars = catalogue()
    status, names, replaced = attack_status(Path(a.stix))

    # CAR technique IDs that ATT&CK v19.2 no longer has as active techniques
    stale = {}
    for c in cars:
        for cov in c["coverage"]:
            for tid in [cov["technique"]] + cov["subtechniques"]:
                if tid and status.get(tid) != "active":
                    stale.setdefault(tid, {"state": status.get(tid, "unknown"), "now": replaced.get(tid),
                                           "analytics": []})["analytics"].append(c["id"])

    # index: technique -> analytics (sub-technique level and parent level)
    sub_idx, parent_idx = {}, {}
    for c in cars:
        for cov in c["coverage"]:
            for s in cov["subtechniques"]:
                sub_idx.setdefault(replaced.get(s, s), set()).add(c["id"])
            if cov["technique"]:
                parent_idx.setdefault(replaced.get(cov["technique"], cov["technique"]), set()).add(c["id"])

    kc = json.loads((ROOT / "week-04-kill-chain" / "data" / "amadey_kill_chain.json").read_text(encoding="utf-8"))
    amadey = {}
    for ph in kc["phases"]:
        for t in ph["techniques"]:
            amadey.setdefault(t["id"], {"name": t["name"], "tactics": t["tactics"], "lab": t["status"]})
    rows = []
    for tid, info in amadey.items():
        parent = tid.split(".")[0]
        exact = sorted(sub_idx.get(tid, set()) if "." in tid else parent_idx.get(tid, set()))
        parent_only = sorted(parent_idx.get(parent, set()) - set(exact)) if "." in tid else []
        score = 3 if any(x in IMPLEMENTED for x in exact) else 2 if exact else 1 if parent_only else 0
        rows.append({"id": tid, "name": info["name"], "tactics": info["tactics"], "week4_lab_status": info["lab"],
                     "car_exact": exact, "car_parent_only": parent_only, "score": score})

    (WEEK / "data").mkdir(exist_ok=True)
    (WEEK / "data" / "car_analytics.json").write_text(json.dumps(
        {"source": INDEX_URL, "count": len(cars), "analytics": cars}, indent=1) + "\n", encoding="utf-8")
    summary = {
        "car_analytics": len(cars),
        "stale_technique_ids": stale,
        "amadey_techniques": len(rows),
        "covered_exact": sum(r["score"] >= 2 for r in rows),
        "covered_parent_only": sum(r["score"] == 1 for r in rows),
        "not_covered": sum(r["score"] == 0 for r in rows),
        "implemented_this_week": IMPLEMENTED,
        "techniques": rows,
    }
    (WEEK / "data" / "amadey_car_coverage.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")

    techniques = []
    for r in rows:
        label = {3: "CAR analytic implemented in my SIEM (Week 7)", 2: "CAR analytic exists",
                 1: "CAR covers only the parent technique", 0: "no CAR analytic"}[r["score"]]
        comment = label + (": " + ", ".join(r["car_exact"] or r["car_parent_only"]) if r["score"] else "")
        for tac in r["tactics"]:
            techniques.append({"techniqueID": r["id"], "tactic": tac, "score": r["score"], "color": "",
                               "comment": comment, "enabled": True, "showSubtechniques": False})
    layer = {
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "filters": {"platforms": ["Windows"]}, "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False, "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 7)"}],
        "name": "Amadey techniques - MITRE CAR coverage",
        "description": "The 40 Amadey techniques from Week 4, scored by MITRE CAR coverage: 3 = implemented in my SIEM "
                       "this week, 2 = a CAR analytic exists, 1 = CAR covers only the parent technique, 0 = none.",
        "gradient": {"colors": ["#d9d9d9", "#f8c471", "#5dade2", "#1baf7a"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "Implemented in my SIEM (Week 7)", "color": "#1baf7a"},
                        {"label": "CAR analytic exists", "color": "#5dade2"},
                        {"label": "CAR covers parent only", "color": "#f8c471"},
                        {"label": "No CAR analytic", "color": "#d9d9d9"}],
        "showTacticRowBackground": False, "tacticRowBackground": "#dddddd",
        "techniques": techniques,
    }
    (WEEK / "navigator").mkdir(exist_ok=True)
    (WEEK / "navigator" / "amadey_car_coverage_layer.json").write_text(json.dumps(layer, indent=2) + "\n",
                                                                     encoding="utf-8")

    print(f"CAR analytics: {len(cars)} | technique IDs no longer active in ATT&CK v19.2: {len(stale)}")
    print(f"Amadey techniques: {len(rows)} -> CAR exact {summary['covered_exact']}, parent only "
          f"{summary['covered_parent_only']}, none {summary['not_covered']}")
    for r in sorted(rows, key=lambda r: -r["score"]):
        if r["score"]:
            print(f"  {r['score']} {r['id']:10} {r['name'][:38]:38} {', '.join(r['car_exact'] or r['car_parent_only'])}")


if __name__ == "__main__":
    main()
