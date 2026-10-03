#!/usr/bin/env python3
"""
build_attack_profile.py - Week 6: study one ATT&CK technique (T1053.005) from the official data.

Reads the ATT&CK Enterprise v19.2 STIX bundle and writes:
  data/attack_profile.json                       facts for T1053.005, its parent T1053 and the syllabus
                                                 example T1059 (tactics, platforms, sub-techniques,
                                                 mitigations, detection strategy + analytic + log sources,
                                                 procedure-example counts, revocation history)
  navigator/t1053_005_lab_exercise_layer.json    ATT&CK Navigator layer: the techniques the Week 6 lab
                                                 exercise touches, scored by expected visibility in my lab

Nothing is typed by hand: names, tactics and relationships come from the bundle, and every ID must exist
and be neither revoked nor deprecated.

Usage:  python build_attack_profile.py [--stix PATH]   (downloads the bundle to ~/.cache/attack if missing)
Needs:  Python 3.9+ standard library only
"""
import argparse
import json
import os
import re
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
FOCUS = "T1053.005"
REFERENCE = "T1059"          # the syllabus example ("T1059 - Command-Line Interface")
AMADEY = "S1025"

# Techniques the Week 6 lab exercise touches -> what my lab should record (from the Week 2 data-source map).
# score: 2 = visible with current lab logging, 1 = visible only after a logging change, 0 = not visible
LAB_EXERCISE = [
    {"id": "T1053.005", "score": 2,
     "how": "Method A: schtasks.exe /Create /SC MINUTE /MO 1; Method B: Register-ScheduledTask. "
            "Task runs a harmless logging .cmd from C:\\Users\\Public, then is deleted.",
     "expected": "4688 schtasks.exe / powershell.exe; 4698 task created; 4699 task deleted; "
                 "TaskScheduler/Operational 106, 200, 201, 141; 4688 cmd.exe with parent svchost.exe"},
    {"id": "T1059.001", "score": 2,
     "how": "Method B creates the task with PowerShell cmdlets (no schtasks.exe process).",
     "expected": "4688 powershell.exe; PowerShell/Operational 4104 script block with Register-ScheduledTask"},
    {"id": "T1059.003", "score": 2,
     "how": "The task's action runs cmd.exe /c <logging .cmd> every minute.",
     "expected": "4688 cmd.exe, parent svchost.exe (Schedule service), command line with the .cmd path"},
]


def load_bundle(path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading {STIX_URL} ...")
        urllib.request.urlretrieve(STIX_URL, path)
    return json.loads(path.read_text(encoding="utf-8"))["objects"]


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")


def live(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def state(o):
    return "revoked" if o.get("revoked") else "deprecated" if o.get("x_mitre_deprecated") else "active"


def clean(text):
    """Drop ATT&CK citation markers and markdown links so the text reads as plain prose."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


class Attack:
    def __init__(self, objs):
        self.objs = objs
        self.by_ref = {o["id"]: o for o in objs}
        self.rels = [o for o in objs if o["type"] == "relationship" and live(o)]
        self.tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic"}

    def technique(self, tid):
        cands = [o for o in self.objs if o["type"] == "attack-pattern" and ext_id(o) == tid and live(o)]
        if not cands:
            raise SystemExit(f"ATT&CK validation failed: {tid} is unknown, revoked or deprecated in v19.2")
        return cands[0]

    def family(self, parent_id):
        out = []
        for o in self.objs:
            tid = ext_id(o) or ""
            if o["type"] == "attack-pattern" and (tid == parent_id or tid.startswith(parent_id + ".")):
                out.append({"id": tid, "name": o["name"], "state": state(o),
                            "platforms": o.get("x_mitre_platforms", [])})
        return sorted(out, key=lambda x: x["id"])

    def revoked_into(self, prefix):
        out = []
        for r in self.objs:
            if r["type"] == "relationship" and r["relationship_type"] == "revoked-by":
                src, dst = self.by_ref.get(r["source_ref"]), self.by_ref.get(r["target_ref"])
                if src and dst and (ext_id(dst) or "").startswith(prefix):
                    out.append({"old": ext_id(src), "old_name": src["name"],
                                "new": ext_id(dst), "new_name": dst["name"]})
        return sorted(out, key=lambda x: x["old"])

    def related(self, target, rtype):
        return [(r, self.by_ref[r["source_ref"]]) for r in self.rels
                if r["relationship_type"] == rtype and r["target_ref"] == target["id"]
                and live(self.by_ref[r["source_ref"]])]

    def profile(self, tid):
        t = self.technique(tid)
        users = self.related(t, "uses")
        by_type = Counter(src["type"] for _, src in users)
        mitigations = [{"id": ext_id(src), "name": src["name"], "how": clean(r.get("description"))}
                       for r, src in self.related(t, "mitigates")]
        detections = []
        for _, det in self.related(t, "detects"):
            analytics = []
            for ref in det.get("x_mitre_analytic_refs", []):
                an = self.by_ref[ref]
                sources = []
                for ls in an.get("x_mitre_log_source_references", []):
                    dc = self.by_ref.get(ls["x_mitre_data_component_ref"], {})
                    sources.append({"data_component": f"{ext_id(dc)} {dc.get('name', '?')}",
                                    "log_source": ls["name"], "channel": ls["channel"]})
                analytics.append({"id": ext_id(an), "platforms": an.get("x_mitre_platforms", []),
                                  "description": clean(an.get("description")),
                                  "log_sources": sources,
                                  "tunable": [m["field"] for m in an.get("x_mitre_mutable_elements", [])]})
            detections.append({"id": ext_id(det), "name": det["name"], "analytics": analytics})
        tactics = [p["phase_name"] for p in t.get("kill_chain_phases", [])]
        return {
            "id": tid, "name": t["name"], "version": t.get("x_mitre_version"),
            "created": t["created"][:10], "modified": t["modified"][:10],
            "is_subtechnique": t.get("x_mitre_is_subtechnique", False),
            "tactics": [f"{self.tactic_names[x]} ({x})" for x in tactics],
            "platforms": t.get("x_mitre_platforms", []),
            "description": clean(t.get("description")),
            "procedure_examples": {"total": len(users), "malware": by_type.get("malware", 0),
                                   "tool": by_type.get("tool", 0), "groups": by_type.get("intrusion-set", 0),
                                   "campaigns": by_type.get("campaign", 0)},
            "groups": sorted(src["name"] for _, src in users if src["type"] == "intrusion-set"),
            "amadey_listed": any(ext_id(src) == AMADEY for _, src in users),
            "mitigations": sorted(mitigations, key=lambda m: m["id"]),
            "detection_strategies": detections,
        }


def layer(attack):
    techniques = []
    for item in LAB_EXERCISE:
        t = attack.technique(item["id"])
        for phase in t.get("kill_chain_phases", []):
            techniques.append({
                "techniqueID": item["id"], "tactic": phase["phase_name"], "score": item["score"],
                "color": "", "enabled": True, "showSubtechniques": False,
                "comment": f"{item['how']} Expected telemetry: {item['expected']}",
                "metadata": [{"name": "name", "value": t["name"]}],
            })
    return {
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 6)"}],
        "name": "Week 6 lab exercise - T1053.005 Scheduled Task",
        "description": "Techniques touched by the benign Week 6 lab exercise. Score = expected visibility in my lab "
                       "(2 = logged today, 1 = needs a logging change, 0 = not visible).",
        "gradient": {"colors": ["#ffffff", "#f8c471", "#1baf7a"], "minValue": 0, "maxValue": 2},
        "legendItems": [{"label": "Logged with current lab settings", "color": "#1baf7a"},
                        {"label": "Needs a logging change", "color": "#f8c471"}],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "techniques": techniques,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stix", default=os.path.expanduser("~/.cache/attack/enterprise-attack-19.2.json"))
    a = ap.parse_args()
    attack = Attack(load_bundle(Path(a.stix)))
    version = next((o.get("x_mitre_version") for o in attack.objs if o["type"] == "x-mitre-collection"), "?")

    focus = attack.profile(FOCUS)
    out = {
        "attack_version": version,
        "focus": focus,
        "parent": {**{k: v for k, v in attack.profile("T1053").items()
                      if k in ("id", "name", "tactics", "platforms", "procedure_examples")},
                   "subtechniques": attack.family("T1053"), "revoked_into": attack.revoked_into("T1053")},
        "reference": {**{k: v for k, v in attack.profile(REFERENCE).items()
                         if k in ("id", "name", "tactics", "platforms", "procedure_examples")},
                      "subtechniques": attack.family(REFERENCE), "revoked_into": attack.revoked_into(REFERENCE)},
        "lab_exercise": LAB_EXERCISE,
    }
    (WEEK / "data").mkdir(exist_ok=True)
    (WEEK / "navigator").mkdir(exist_ok=True)
    (WEEK / "data" / "attack_profile.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n",
                                                       encoding="utf-8")
    (WEEK / "navigator" / "t1053_005_lab_exercise_layer.json").write_text(
        json.dumps(layer(attack), indent=2) + "\n", encoding="utf-8")

    pe = focus["procedure_examples"]
    print(f"ATT&CK v{version}: {FOCUS} {focus['name']} v{focus['version']} (modified {focus['modified']})")
    print(f"  tactics: {', '.join(focus['tactics'])} | platforms: {', '.join(focus['platforms'])}")
    print(f"  procedure examples: {pe['total']} = {pe['malware']} malware + {pe['tool']} tools + "
          f"{pe['groups']} groups + {pe['campaigns']} campaigns | Amadey ({AMADEY}) listed: {focus['amadey_listed']}")
    print(f"  mitigations: {', '.join(m['id'] for m in focus['mitigations'])}")
    for det in focus["detection_strategies"]:
        for an in det["analytics"]:
            srcs = "; ".join(f"{s['log_source']} {s['channel']}" for s in an["log_sources"])
            print(f"  detection: {det['id']} / {an['id']}: {srcs}")
    print(f"  {REFERENCE} sub-techniques: {len([s for s in out['reference']['subtechniques'] if s['state'] == 'active']) - 1} active")
    print(f"Wrote data/attack_profile.json and navigator/t1053_005_lab_exercise_layer.json")


if __name__ == "__main__":
    main()
