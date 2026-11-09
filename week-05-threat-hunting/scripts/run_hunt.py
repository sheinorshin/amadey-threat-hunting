#!/usr/bin/env python3
"""
run_hunt.py - execute the three hypothesis hunts against data/dataset.ndjson and prove they work.

This is a LOCAL verifier, not a replacement for Kibana. It applies exactly the detection logic
of the ES|QL / EQL / KQL queries in ../queries/ to the synthetic ECS dataset, so I can show that
each hypothesis (a) finds the planted Amadey -> StealC intrusion and (b) survives triage against
near-misses - producing the funnel numbers and triage tables used in 03-hunt-execution.md.

In the real lab the same queries run in Kibana (Discover / Security / Timeline) over logs-*.
Output: prints a report, writes ../data/hunt_results.json, and exits non-zero if a self-check fails.
Standard library only.
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "dataset.ndjson"
OUT = Path(__file__).resolve().parent.parent / "data" / "hunt_results.json"
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "wmic.exe", "regsvr32.exe"}
CRADLE = re.compile(r"(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|"
                    r"frombase64string|\biex\b|reflection\.assembly\]::load|-enc(odedcommand)?\b)")
HEXDIR = re.compile(r"(?i)\\[a-f0-9]{10}\\[^\\]+\.exe$")
EVERY_MIN = re.compile(r"(?i)(PT1M|/sc\s+minute.*?/mo\s+1|/mo\s+1\b)")


def ts(e):
    return datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00"))


def load():
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    rows.sort(key=ts)
    return rows


def g(e, *path, default=None):
    cur = e
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def hunt_h1(rows):
    """H1: a script host (wscript/cscript/mshta/...) spawned PowerShell that pulled/ran remote content."""
    ps = [e for e in rows if e["event"]["code"] == "4688" and g(e, "process", "name") == "powershell.exe"]
    cradle_only = [e for e in rows if e["event"]["code"] == "4104" and CRADLE.search(g(e, "powershell", "file", "script_block_text", default=""))]
    cradle_only += [e for e in ps if CRADLE.search(g(e, "process", "command_line", default=""))]
    # candidates = PowerShell whose PARENT is a script host  (the specific hunt)
    candidates = [e for e in ps if g(e, "process", "parent", "name") in SCRIPT_HOSTS]
    # confirm: that PowerShell (or its pid's 4104) shows a remote download / encoded exec
    script_by_pid = defaultdict(list)
    for e in rows:
        if e["event"]["code"] == "4104":
            script_by_pid[g(e, "process", "pid")].append(g(e, "powershell", "file", "script_block_text", default=""))
    confirmed = []
    for e in candidates:
        cmd = g(e, "process", "command_line", default="")
        blocks = " ".join(script_by_pid.get(g(e, "process", "pid"), []))
        if CRADLE.search(cmd) or CRADLE.search(blocks):
            confirmed.append(e)
    return {"name": "H1 script host -> PowerShell -> remote content", "attack": ["T1059.001", "T1059.007", "T1218.005", "T1105"],
            "scope": len(ps), "cradle_only_naive": len(cradle_only), "candidates": candidates, "confirmed": confirmed}


def hunt_h2(rows):
    """H2: an EXE from a hex-named user folder gets a scheduled task running every minute."""
    hexexe = [e for e in rows if e["event"]["code"] == "4688" and HEXDIR.search(g(e, "process", "executable", default=""))]
    schtasks = [e for e in rows if e["event"]["code"] == "4688" and g(e, "process", "name") == "schtasks.exe"
                and EVERY_MIN.search(g(e, "process", "command_line", default=""))]
    task4698 = [e for e in rows if e["event"]["code"] == "4698" and EVERY_MIN.search(g(e, "winlog", "event_data", "TaskContent", default=""))]
    # confirm per host: a hex-folder exe AND an every-minute task that points at a user-writable path
    def userwritable(s):
        return bool(re.search(r"(?i)\\(users|appdata|temp|programdata)\\", s or ""))
    confirmed_hosts = set()
    for a in hexexe:
        h = a["host"]["name"]
        same = [b for b in schtasks + task4698 if b["host"]["name"] == h and
                (userwritable(g(b, "process", "command_line", default="")) or userwritable(g(b, "winlog", "event_data", "TaskContent", default="")))]
        if same:
            confirmed_hosts.add(h)
    return {"name": "H2 hex-folder EXE + 1-minute scheduled task", "attack": ["T1053.005", "T1204.002"],
            "scope": sum(1 for e in rows if e["event"]["code"] in ("4688", "4698")),
            "candidates": hexexe + schtasks + task4698, "confirmed_hosts": sorted(confirmed_hosts),
            "task4698": task4698, "schtasks": schtasks, "hexexe": hexexe}


def hunt_h3(rows):
    """H3: a new local admin (or hidden '$' account) and a firewall rule on the same host within 30 min."""
    acct = [e for e in rows if (e["event"]["code"] == "4732" and g(e, "winlog", "event_data", "TargetUserName") == "Administrators")
            or (e["event"]["code"] == "4720" and str(g(e, "winlog", "event_data", "TargetUserName", default="")).endswith("$"))]
    fw = [e for e in rows if e["event"]["code"] == "4946"]
    confirmed = []
    for a in acct:
        for f in fw:
            if a["host"]["name"] == f["host"]["name"] and abs((ts(f) - ts(a)).total_seconds()) <= 1800:
                confirmed.append({"host": a["host"]["name"], "account_event": a["event"]["code"],
                                  "account": g(a, "winlog", "event_data", "MemberName") or g(a, "winlog", "event_data", "TargetUserName"),
                                  "rule": g(f, "winlog", "event_data", "RuleName"),
                                  "t_account": a["@timestamp"], "t_rule": f["@timestamp"]})
    return {"name": "H3 new admin + firewall rule within 30 min", "attack": ["T1136.001", "T1021.001", "T1686"],
            "scope": sum(1 for e in rows if e["event"]["code"] in ("4720", "4732", "4946")),
            "candidate_accounts": acct, "candidate_fw": fw, "confirmed": confirmed}


def short(e):
    return {"t": e["@timestamp"], "host": e["host"]["name"], "user": g(e, "user", "name"),
            "code": e["event"]["code"], "proc": g(e, "process", "name"),
            "parent": g(e, "process", "parent", "name"), "cmd": g(e, "process", "command_line")}


def main():
    rows = load()
    h1, h2, h3 = hunt_h1(rows), hunt_h2(rows), hunt_h3(rows)
    print(f"dataset: {len(rows)} events, {len({e['host']['name'] for e in rows})} hosts, "
          f"{rows[0]['@timestamp']} -> {rows[-1]['@timestamp']}\n")

    print("== H1  script host -> PowerShell -> remote content")
    print(f"   scope (all PowerShell 4688): {h1['scope']}")
    print(f"   naive 4104/cmd download-cradle search alone: {h1['cradle_only_naive']} hits (includes benign internal + explorer-launched)")
    print(f"   candidates (PS whose parent is a script host): {len(h1['candidates'])}")
    for e in h1["candidates"]:
        print(f"     - {e['@timestamp']} {e['host']['name']} parent={g(e,'process','parent','name')} :: {g(e,'process','command_line')[:70]}")
    print(f"   CONFIRMED true positives: {len(h1['confirmed'])} -> {sorted({e['host']['name'] for e in h1['confirmed']})}\n")

    print("== H2  hex-folder EXE + 1-minute scheduled task")
    print(f"   hex-folder EXE (4688): {len(h2['hexexe'])}  | schtasks /mo 1 (4688): {len(h2['schtasks'])}  | every-minute task (4698): {len(h2['task4698'])}")
    print(f"   CONFIRMED hosts: {h2['confirmed_hosts']}\n")

    print("== H3  new admin + firewall rule within 30 min")
    print(f"   candidate admin/'$' account events: {len(h3['candidate_accounts'])}  | firewall-rule events: {len(h3['candidate_fw'])}")
    for c in h3["confirmed"]:
        print(f"   CONFIRMED {c['host']}: account '{c['account']}' ({c['t_account']}) + rule '{c['rule']}' ({c['t_rule']})")
    print()

    # -------- self-checks: planted intrusion found, near-misses excluded
    checks = {
        "H1 finds WIN-FIN-07": "WIN-FIN-07" in {e["host"]["name"] for e in h1["confirmed"]},
        "H1 confirmed count == 1": len(h1["confirmed"]) == 1,
        "H2 confirms WIN-FIN-07 only": h2["confirmed_hosts"] == ["WIN-FIN-07"],
        "H3 confirms WIN-FIN-07": any(c["host"] == "WIN-FIN-07" for c in h3["confirmed"]),
        "H3 excludes RDP-Users near-miss": all(c["host"] != "WIN-DEV-11" for c in h3["confirmed"]),
        "H3 excludes lone firewall rule": all(c["host"] != "WIN-SALES-05" for c in h3["confirmed"]),
    }
    print("\n== self-checks")
    ok = True
    for k, v in checks.items():
        print(f"   [{'PASS' if v else 'FAIL'}] {k}")
        ok = ok and v

    results = {
        "dataset_events": len(rows), "hosts": sorted({e["host"]["name"] for e in rows}),
        "H1": {"scope": h1["scope"], "cradle_only_naive": h1["cradle_only_naive"],
               "candidates": len(h1["candidates"]), "confirmed": [short(e) for e in h1["confirmed"]]},
        "H2": {"scope": h2["scope"], "hexexe": len(h2["hexexe"]), "schtasks_mo1": len(h2["schtasks"]),
               "task4698_every_min": len(h2["task4698"]), "confirmed_hosts": h2["confirmed_hosts"],
               "hexexe_rows": [short(e) for e in h2["hexexe"]]},
        "H3": {"scope": h3["scope"], "candidate_accounts": len(h3["candidate_accounts"]),
               "candidate_fw": len(h3["candidate_fw"]), "confirmed": h3["confirmed"]},
        "self_checks_pass": ok,
    }
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {OUT}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
