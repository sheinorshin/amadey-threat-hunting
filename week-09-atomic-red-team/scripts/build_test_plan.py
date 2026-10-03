#!/usr/bin/env python3
"""
build_test_plan.py - Week 9: the Atomic Red Team test plan for my lab, written before the run.

Writes:
  data/test_plan.json                        14 planned tests: technique, why it is in the plan, what the chosen atomic
                                             must exercise, expected telemetry, which of my detections should fire and
                                             the predicted result category (None / Telemetry / General / Tactic /
                                             Technique), plus ATT&CK facts and who uses the technique (Week 4 + 10);
                                             and the ATT&CK tactics of every technique score_atomic_run.py can report
  navigator/w9_test_plan_layer.json          Navigator layer of the plan, scored by the PREDICTED category
                                             (0 None, 1 Telemetry, 2 General/Tactic, 3 Technique)

The plan names techniques and the behaviour a test must show; the concrete atomic (number + GUID) is chosen from the
public Atomic Red Team library on the lab VM and recorded by Invoke-AtomicTest's execution log (03-siem-analysis.md).
Every technique ID is checked against ATT&CK v19.2 (must exist, not revoked, not deprecated).

Usage:  python build_test_plan.py [--stix PATH]   (downloads the bundle to ~/.cache/attack if missing)
Needs:  Python 3.9+ standard library only
"""
import argparse
import json
import os
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
CATEGORY_SCORE = {"None": 0, "Telemetry": 1, "General": 2, "Tactic": 2, "Technique": 3}

# Tier A = the "commodity core" that Amadey shares with APT29/APT41 and that my lab should see today (Week 10 §4.8)
# Tier B = the rest of Amadey's own chain (Week 4 phases 4, 5, 7)
# Tier C = the syllabus example T1003, taken from the APT side (APT29 + APT41) - optional, snapshot first
PLAN = [
    {"id": "W9-A1", "tier": "A", "technique": "T1059.001",
     "why": "Amadey KC4 (Emmenhtal PowerShell) and KC7 (Expand-Archive); used by all five actors in Week 10",
     "behaviour": "PowerShell running a script block; one variant with an encoded command; nothing fetched from the internet",
     "telemetry": ["4688 powershell.exe (+ -EncodedCommand)", "4104 script block"],
     "detections": ["W5-H1b only if the block contains a download keyword", "W5-H1a only if the parent is a script host"],
     "predicted": "Telemetry",
     "note": "Atomic tests start PowerShell from PowerShell, not from wscript/mshta, so H1's parent check should stay quiet."},
    {"id": "W9-A2", "tier": "A", "technique": "T1059.003",
     "why": "syllabus example T1059; Windows Command Shell used by APT29, APT41, TA505, Kimsuky",
     "behaviour": "a batch file or cmd.exe /c one-liner",
     "telemetry": ["4688 cmd.exe with command line"],
     "detections": [],
     "predicted": "Telemetry",
     "note": "No rule of mine looks at plain cmd.exe - the expected result is visibility only."},
    {"id": "W9-A3", "tier": "A", "technique": "T1053.005",
     "why": "Amadey KC5 (every-minute task) - the technique of Weeks 3, 5, 6 and 7; also APT29, APT41, Kimsuky",
     "behaviour": "two tests: a task created with schtasks.exe, and a task created with PowerShell cmdlets (no schtasks.exe)",
     "telemetry": ["4688 schtasks.exe /create", "4698 task created", "TaskScheduler 106 / 200 / 201", "4104 Register-ScheduledTask"],
     "detections": ["W7-CAR-PROC / W7-CAR-TASK if the action is in a user-writable path or an every-minute interpreter",
                    "W3-SCHTASKS + W5-H2b only for /SC MINUTE /MO 1", "W5-H2c only for PT1M"],
     "predicted": "Technique",
     "note": "If the atomic's task runs a System32 program at logon, my tuned rule should NOT fire - that is a finding, not a failure of the test."},
    {"id": "W9-A4", "tier": "A", "technique": "T1105",
     "why": "Amadey KC3 / KC7 (loader and StealC downloads); all five actors",
     "behaviour": "download with a built-in Windows tool (certutil, bitsadmin or PowerShell) from a web server inside the lab",
     "telemetry": ["4688 certutil.exe / bitsadmin.exe / powershell.exe with a URL", "4104 for the PowerShell variant"],
     "detections": ["W5-H1b for the PowerShell variant (download keyword in 4104)"],
     "predicted": "Telemetry",
     "note": "The VM is isolated - pick or adapt atomics so the URL points at a lab-local HTTP server, otherwise the test only fails."},
    {"id": "W9-A5", "tier": "A", "technique": "T1136.001",
     "why": "Amadey v5 hidden local admin (KC7); APT41, Kimsuky",
     "behaviour": "create a local user and add it to the local Administrators group",
     "telemetry": ["4720 user created", "4732 member added to Administrators", "4688 net.exe / 4104 New-LocalUser"],
     "detections": ["W5-H3 (account part)"],
     "predicted": "Technique",
     "note": "Run W9-A6 within 30 minutes on the same host so the H3 correlation can confirm."},
    {"id": "W9-A6", "tier": "A", "technique": "T1686",
     "why": "Amadey v5 firewall rule for RDP (KC7; was T1562.004 before ATT&CK v19); APT29, Kimsuky",
     "behaviour": "add an inbound Windows Firewall rule",
     "telemetry": ["4946 firewall rule added", "4688 netsh.exe / 4104 New-NetFirewallRule"],
     "detections": ["W5-H3 confirmation (new admin + firewall rule within 30 min)"],
     "predicted": "Technique",
     "note": "Needs the MPSSVC Rule-Level Policy Change audit (4946) - already used by Week 5 H3."},
    {"id": "W9-A7", "tier": "A", "technique": "T1218.011",
     "why": "Amadey KC7 plugins (rundll32 ..., Main); all five actors - tests Week 10's 'nominal coverage' finding",
     "behaviour": "rundll32.exe running an export of a harmless DLL from a user-writable folder (not an Amadey plugin name)",
     "telemetry": ["4688 rundll32.exe with the DLL path"],
     "detections": ["W3-RUNDLL32 should NOT fire - it only matches cred64.dll / clip64.dll"],
     "predicted": "Telemetry",
     "note": "If it is Telemetry, the Week 3 rule's T1218.011 tag is confirmed as nominal coverage."},
    {"id": "W9-A8", "tier": "A", "technique": "T1082",
     "why": "Amadey KC6 check-in data; APT41, Kimsuky - tests Week 10's 'procedure, not technique' finding",
     "behaviour": "command-line system discovery (systeminfo, hostname, ver)",
     "telemetry": ["4688 systeminfo.exe / hostname.exe / cmd.exe"],
     "detections": [],
     "predicted": "Telemetry",
     "note": "Amadey collects the same data through API calls (no process) - visible here does NOT mean visible for Amadey."},
    {"id": "W9-B1", "tier": "B", "technique": "T1059.007",
     "why": "Amadey KC4: Emmenhtal JavaScript run by Windows Script Host",
     "behaviour": "a local .js file run by wscript.exe or cscript.exe that starts PowerShell",
     "telemetry": ["4688 wscript.exe / cscript.exe", "4688 powershell.exe with parent wscript.exe / cscript.exe"],
     "detections": ["W5-H1a (script host -> PowerShell)"],
     "predicted": "Technique",
     "note": "If the chosen atomic does not start PowerShell, H1 stays quiet and the result is Telemetry."},
    {"id": "W9-B2", "tier": "B", "technique": "T1218.005",
     "why": "Amadey KC4: mshta.exe runs Emmenhtal",
     "behaviour": "mshta.exe running a local .hta or inline script that starts PowerShell",
     "telemetry": ["4688 mshta.exe", "4688 powershell.exe with parent mshta.exe"],
     "detections": ["W5-H1a (script host -> PowerShell)"],
     "predicted": "Technique",
     "note": "Same condition as W9-B1."},
    {"id": "W9-B3", "tier": "B", "technique": "T1547.001",
     "why": "Amadey KC5: Startup folder redirected / Run key",
     "behaviour": "add a value under a Run key (reg.exe or PowerShell)",
     "telemetry": ["4688 reg.exe add ...\\Run", "4104 Set-ItemProperty / New-ItemProperty"],
     "detections": ["W3-STARTUP-REG needs Sysmon 13 - not installed"],
     "predicted": "Telemetry",
     "note": "Without Sysmon the registry change itself is not logged; only the process that made it."},
    {"id": "W9-B4", "tier": "B", "technique": "T1112",
     "why": "Amadey v5 enables RDP (fDenyTSConnections = 0) before adding the admin and the firewall rule",
     "behaviour": "set fDenyTSConnections to 0 with reg.exe or PowerShell, then restore it",
     "telemetry": ["4688 reg.exe with Terminal Server\\fDenyTSConnections", "4104 Set-ItemProperty"],
     "detections": ["W3-RDP-REG needs Sysmon 13 - not installed"],
     "predicted": "Telemetry",
     "note": "Enables RDP on the VM for the duration of the test - restore it in the cleanup step."},
    {"id": "W9-C1", "tier": "C", "technique": "T1003.002",
     "why": "syllabus example T1003; APT29 and APT41 both save the SAM hive with reg save (Week 10); not an Amadey technique",
     "behaviour": "registry hive export of SAM / SYSTEM to a file, then delete the files",
     "telemetry": ["4688 reg.exe save HKLM\\SAM / HKLM\\SYSTEM"],
     "detections": [],
     "predicted": "Telemetry",
     "note": "Optional, snapshot first. Gap expected - a reg.exe save rule is cheap with data I already collect."},
    {"id": "W9-C2", "tier": "C", "technique": "T1003.001",
     "why": "syllabus example T1003; APT41, Kimsuky, APT1 (LSASS memory)",
     "behaviour": "an LSASS memory access test that uses only built-in Windows components",
     "telemetry": ["4688 of the process that accesses LSASS", "Defender 1116/1117 if it blocks"],
     "detections": ["needs Sysmon 10 (process access) - not installed"],
     "predicted": "Telemetry",
     "note": "Optional, snapshot first, Defender stays ON: a Defender block is a valid result (Prevented)."},
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stix", default=os.path.expanduser("~/.cache/attack/enterprise-attack-19.2.json"))
    a = ap.parse_args()
    objs = load_bundle(Path(a.stix))
    tech = {ext_id(o): o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked")
            and not o.get("x_mitre_deprecated")}
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic"}

    kc = json.loads((ROOT / "week-04-kill-chain" / "data" / "amadey_kill_chain.json").read_text(encoding="utf-8"))
    week4 = {}
    for ph in kc["phases"]:
        for t in ph["techniques"]:
            week4.setdefault(t["id"], {"phase": f"KC{ph['phase']} {ph['name']}", "status": t["status"]})
    users = {}
    cmp_path = ROOT / "week-10-apt-techniques" / "data" / "comparison.json"
    if cmp_path.exists():
        for p in json.loads(cmp_path.read_text(encoding="utf-8"))["priorities"]:
            users[p["id"]] = p["who"]
    w10_csv = ROOT / "week-10-apt-techniques" / "data" / "apt_techniques.csv"
    if w10_csv.exists():
        import csv
        with open(w10_csv, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                users.setdefault(r["technique_id"], [u for u in r["used_by"].split(";") if u and u != "APT1"])

    tests = []
    for item in PLAN:
        tid = item["technique"]
        if tid not in tech:
            raise SystemExit(f"ATT&CK validation failed: {tid} is unknown, revoked or deprecated in v19.2")
        if item["predicted"] not in CATEGORY_SCORE:
            raise SystemExit(f"{item['id']}: unknown category {item['predicted']}")
        t = tech[tid]
        tactics = [p["phase_name"] for p in t.get("kill_chain_phases", [])]
        tests.append({**item, "name": t["name"], "tactics": tactics,
                      "tactic_names": [tactic_names[x] for x in tactics],
                      "amadey_week4": week4.get(tid), "used_by": users.get(tid, [])})

    # ATT&CK tactics of every technique the scorer can report, so score_atomic_run.py needs no bundle and no
    # hand-typed tactic list (used for the "Tactic" result category and the observed layer)
    from score_atomic_run import EMITTED
    tactics = {}
    for tid in sorted(set(EMITTED) | {t["technique"] for t in tests}):
        if tid not in tech:
            raise SystemExit(f"ATT&CK validation failed: scorer technique {tid} is not active in v19.2")
        tactics[tid] = [p["phase_name"] for p in tech[tid].get("kill_chain_phases", [])]

    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")
    (WEEK / "data").mkdir(exist_ok=True)
    (WEEK / "data" / "test_plan.json").write_text(json.dumps(
        {"attack_version": version, "categories": CATEGORY_SCORE, "tactics": tactics, "tests": tests},
        indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    colors = {0: "#d03b3b", 1: "#fab219", 2: "#5dade2", 3: "#0ca30c"}
    techniques = []
    for t in tests:
        score = CATEGORY_SCORE[t["predicted"]]
        for tac in t["tactics"]:
            techniques.append({"techniqueID": t["technique"], "tactic": tac, "score": score, "color": colors[score],
                               "comment": f"{t['id']} (tier {t['tier']}) predicted {t['predicted']}. {t['why']}. "
                                          f"Expected: {'; '.join(t['telemetry'])}.",
                               "enabled": True, "showSubtechniques": False})
    layer = {
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "filters": {"platforms": ["Windows"]}, "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False, "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 9)"}],
        "name": "Week 9 Atomic Red Team plan - predicted results",
        "description": "Techniques in the Week 9 test plan, scored by the result predicted BEFORE the run: "
                       "3 = Technique-level detection, 2 = General/Tactic, 1 = Telemetry only, 0 = None.",
        "gradient": {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "Technique detection", "color": colors[3]},
                        {"label": "General / Tactic", "color": colors[2]},
                        {"label": "Telemetry only", "color": colors[1]},
                        {"label": "None", "color": colors[0]}],
        "showTacticRowBackground": False, "tacticRowBackground": "#dddddd",
        "techniques": techniques,
    }
    (WEEK / "navigator").mkdir(exist_ok=True)
    (WEEK / "navigator" / "w9_test_plan_layer.json").write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")

    print(f"ATT&CK v{version}: {len(tests)} planned tests, {len({t['technique'] for t in tests})} techniques - all IDs valid "
          f"(+ tactics for {len(tactics)} techniques the scorer can report)")
    for tier in "ABC":
        row = [t for t in tests if t["tier"] == tier]
        print(f"  tier {tier}: " + ", ".join(f"{t['technique']}->{t['predicted']}" for t in row))
    pred = {}
    for t in tests:
        pred[t["predicted"]] = pred.get(t["predicted"], 0) + 1
    print("  predicted: " + ", ".join(f"{k} {v}" for k, v in sorted(pred.items(), key=lambda kv: -CATEGORY_SCORE[kv[0]])))
    print("Wrote data/test_plan.json and navigator/w9_test_plan_layer.json")


if __name__ == "__main__":
    main()
