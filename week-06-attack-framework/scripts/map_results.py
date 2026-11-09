#!/usr/bin/env python3
"""
map_results.py - Week 6: map the telemetry of the lab exercise to ATT&CK and test my detections on it.

Inputs (both produced in the lab, see 03-lab-exercise.md):
  --events  CSV downloaded from Kibana with queries/w6_exercise_events.esql
  --runlog  ground-truth CSV written by lab/ith-w6-task-exercise.ps1 (what was done, when)

Outputs:
  results/w6_results.md                        observations per method, ATT&CK mapping, detection results
  results/w6_results.json                      the same, machine-readable
  navigator/t1053_005_observed_layer.json      Navigator layer: 2 = seen + a detection fired,
                                               1 = seen, no detection fired, 0 = expected but not seen

Detections tested (re-implemented here with the same logic as the originals):
  W3-SIGMA  week-03 Sigma rule proc_creation_win_amadey_schtasks_every_minute (schtasks command line)
  W5-H2b    week-05 H2 query (2): schtasks.exe with /SC MINUTE /MO 1
  W5-H2c    week-05 H2 query (3): event 4698 whose TaskContent contains PT1M

  python map_results.py --events export.csv --runlog w6_run_log_HOST_TIME.csv
  python map_results.py --selftest        # checks the mapping logic on built-in sample events, writes nothing

Standard library only.
"""
import argparse
import csv
import json
import re
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
EXPECTED_LAYER = WEEK / "navigator" / "t1053_005_lab_exercise_layer.json"
TS_PARENTS = {"svchost.exe", "taskeng.exe", "taskhostw.exe"}
USER_PATHS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\")

DETECTIONS = OrderedDict([
    ("W3-SIGMA", "Week 3 Sigma: schtasks every minute from a user folder (command line)"),
    ("W5-H2b", "Week 5 H2 (2): schtasks.exe /SC MINUTE /MO 1"),
    ("W5-H2c", "Week 5 H2 (3): 4698 task with PT1M repetition"),
])


def field(ev, name):
    return (ev.get(name) or "").strip()


def classify(ev):
    """One event -> (observation, [ATT&CK technique IDs]) or None if it is not part of the exercise."""
    code = field(ev, "event.code")
    cl = field(ev, "process.command_line").lower()
    proc = (field(ev, "process.name") or cl.split(" ")[0].split("\\")[-1]).lower()
    parent = field(ev, "process.parent.name").lower()
    if code == "4688":
        if proc == "schtasks.exe" and "/create" in cl:
            return "4688 schtasks.exe /Create", ["T1053.005"]
        if proc == "schtasks.exe" and "/delete" in cl:
            return "4688 schtasks.exe /Delete (cleanup)", []
        if proc == "cmd.exe" and "ith-w6-heartbeat" in cl:
            if parent in TS_PARENTS:
                return "4688 cmd.exe started by Task Scheduler", ["T1053.005", "T1059.003"]
            return "4688 cmd.exe heartbeat (parent not Task Scheduler)", ["T1059.003"]
        if proc in ("powershell.exe", "pwsh.exe"):
            return "4688 powershell.exe running the exercise", ["T1059.001"]
        return f"4688 {proc}", []
    if code == "4104":
        sb = field(ev, "powershell.file.script_block_text").lower()
        if "register-scheduledtask" in sb:
            return "4104 script block with Register-ScheduledTask", ["T1059.001", "T1053.005"]
        return "4104 script block", ["T1059.001"]
    named = {
        "4698": ("4698 scheduled task created", ["T1053.005"]),
        "4699": ("4699 scheduled task deleted (cleanup)", []),
        "4702": ("4702 scheduled task updated", ["T1053.005"]),
        "100": ("TaskScheduler 100 task started", ["T1053.005"]),
        "102": ("TaskScheduler 102 task completed", ["T1053.005"]),
        "106": ("TaskScheduler 106 task registered", ["T1053.005"]),
        "129": ("TaskScheduler 129 task process created", ["T1053.005"]),
        "140": ("TaskScheduler 140 task updated", ["T1053.005"]),
        "141": ("TaskScheduler 141 task deleted (cleanup)", []),
        "200": ("TaskScheduler 200 action started", ["T1053.005"]),
        "201": ("TaskScheduler 201 action completed", ["T1053.005"]),
    }
    return named.get(code, (f"event {code}", []))


def detections_fired(ev):
    code = field(ev, "event.code")
    cl = field(ev, "process.command_line").lower()
    proc = (field(ev, "process.name") or cl.split(" ")[0].split("\\")[-1]).lower()
    fired = []
    if code == "4688" and proc == "schtasks.exe":
        if all(k in cl for k in ("/create", "/sc minute", "/mo 1", "/tr")) and any(p in cl for p in USER_PATHS):
            fired.append("W3-SIGMA")
        if re.search(r"/sc\s+minute", cl) and re.search(r"/mo\s+1\b", cl):
            fired.append("W5-H2b")
    if code == "4698" and "pt1m" in field(ev, "winlog.event_data.TaskContent").lower():
        fired.append("W5-H2c")
    return fired


def parse_ts(s):
    s = s.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(s[:26] + s[-6:] if "." in s and len(s) > 32 else s)


def method_windows(runlog):
    """Method -> (start, end) from the ground-truth rows whose step starts with 'A:' or 'B:'."""
    win = {}
    for row in runlog:
        m = row["step"][:1]
        if row["step"][1:2] == ":" and m in "AB":
            s, e = parse_ts(row["utc_start"]), parse_ts(row["utc_end"]) + timedelta(seconds=30)
            lo, hi = win.get(m, (s, e))
            win[m] = (min(lo, s), max(hi, e))
    if "A" in win and "B" in win and win["A"][1] > win["B"][0]:   # keep the windows from overlapping
        win["A"] = (win["A"][0], win["B"][0])
    return win


def which_method(ev, windows):
    text = (field(ev, "winlog.event_data.TaskName") + " " + field(ev, "process.command_line") + " "
            + field(ev, "powershell.file.script_block_text")).lower()
    hits = [m for m in "AB" if f"ith-w6-exercise-{m.lower()}" in text]
    if len(hits) == 1:
        return hits[0]
    ts = parse_ts(field(ev, "@timestamp"))
    for m, (lo, hi) in windows.items():
        if lo <= ts <= hi:
            return m
    return "setup/other"


def analyse(events, runlog):
    windows = method_windows(runlog)
    per = defaultdict(lambda: {"observations": OrderedDict(), "techniques": set(), "detections": set()})
    for ev in sorted(events, key=lambda e: field(e, "@timestamp")):
        obs, techs = classify(ev)
        m = which_method(ev, windows)
        o = per[m]["observations"].setdefault(obs, {"count": 0, "first": field(ev, "@timestamp")})
        o["count"] += 1
        per[m]["techniques"].update(techs)
        per[m]["detections"].update(detections_fired(ev))
    result = OrderedDict()
    for m in sorted(per):
        result[m] = {"observations": per[m]["observations"],
                     "techniques": sorted(per[m]["techniques"]),
                     "detections": [d for d in DETECTIONS if d in per[m]["detections"]]}
    return result


def build_layer(result):
    layer = json.loads(EXPECTED_LAYER.read_text(encoding="utf-8"))
    seen = {t for r in result.values() for t in r["techniques"]}
    detected_methods = {m for m, r in result.items() if r["detections"]}
    for t in layer["techniques"]:
        tid = t["techniqueID"]
        methods = [m for m, r in result.items() if tid in r["techniques"]]
        if tid not in seen:
            t["score"], t["comment"] = 0, "Expected but NOT seen in the exported telemetry."
        else:
            hit = any(m in detected_methods for m in methods) and tid == "T1053.005"
            t["score"] = 2 if hit else 1
            fired = sorted({d for m in methods for d in result[m]["detections"]})
            t["comment"] = (f"Seen in method(s) {', '.join(methods)}. "
                            + (f"Detections fired: {', '.join(fired)}." if fired else "No detection fired."))
    layer["name"] = "Week 6 lab exercise - observed results"
    layer["description"] = ("Observed in my lab. Score 2 = seen and a detection fired, 1 = seen but no detection "
                            "fired, 0 = expected but not seen.")
    layer["gradient"] = {"colors": ["#d73027", "#f8c471", "#1baf7a"], "minValue": 0, "maxValue": 2}
    layer["legendItems"] = [{"label": "Seen + detected", "color": "#1baf7a"},
                            {"label": "Seen, no detection", "color": "#f8c471"},
                            {"label": "Expected, not seen", "color": "#d73027"}]
    return layer


def report(result, runlog):
    lines = ["# Week 6 lab exercise - results", "",
             "Generated by `scripts/map_results.py` from the Kibana export and the ground-truth run log - do not edit by hand.",
             "", "## Ground truth (what the script did)", "",
             "| UTC start | Step | ATT&CK |", "|---|---|---|"]
    lines += [f"| {r['utc_start']} | {r['step']} | {r['technique']} |" for r in runlog]
    for m, r in result.items():
        title = {"A": "Method A - schtasks.exe", "B": "Method B - Register-ScheduledTask",
                 "setup/other": "Setup / whole-script events (not tied to one method)"}.get(m, m)
        lines += ["", f"## {title}", "", "| Observation | Events | First seen (UTC) |", "|---|---|---|"]
        lines += [f"| {o} | {v['count']} | {v['first']} |" for o, v in r["observations"].items()]
        lines += ["", f"**ATT&CK techniques observed:** {', '.join(r['techniques']) or 'none'}  "]
        lines += [f"**Detections fired:** {', '.join(r['detections']) or 'none'}"]
    lines += ["", "## Detection matrix", "", "| Detection | " + " | ".join(m for m in result) + " |",
              "|---|" + "---|" * len(result)]
    for d, label in DETECTIONS.items():
        lines.append(f"| {d} - {label} | " + " | ".join("✅" if d in r["detections"] else "—" for r in result.values()) + " |")
    return "\n".join(lines) + "\n"


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def selftest():
    """Built-in sample events shaped like the expected lab telemetry - tests the logic, not the lab."""
    runlog = [
        {"step": "A: created ITH-W6-Exercise-A with schtasks.exe (every 1 min)", "technique": "T1053.005",
         "utc_start": "2026-01-01T10:00:00Z", "utc_end": "2026-01-01T10:00:01Z"},
        {"step": "A: deleted ITH-W6-Exercise-A with schtasks.exe", "technique": "cleanup",
         "utc_start": "2026-01-01T10:02:31Z", "utc_end": "2026-01-01T10:02:32Z"},
        {"step": "B: created ITH-W6-Exercise-B with Register-ScheduledTask (every 1 min)", "technique": "T1053.005;T1059.001",
         "utc_start": "2026-01-01T10:03:00Z", "utc_end": "2026-01-01T10:03:02Z"},
        {"step": "B: deleted ITH-W6-Exercise-B with Unregister-ScheduledTask", "technique": "cleanup",
         "utc_start": "2026-01-01T10:05:32Z", "utc_end": "2026-01-01T10:05:33Z"},
    ]
    hb = r"cmd.exe /c C:\Users\Public\ITH-W6\ith-w6-heartbeat.cmd"
    pt1m = "<Triggers><TimeTrigger><Repetition><Interval>PT1M</Interval></Repetition></TimeTrigger></Triggers>"
    ev = lambda ts, code, **kw: {"@timestamp": ts, "event.code": code, **kw}
    events = [
        ev("2026-01-01T10:00:00Z", "4688", **{"process.name": "schtasks.exe", "process.parent.name": "powershell.exe",
           "process.command_line": f'schtasks.exe /Create /SC MINUTE /MO 1 /TN ITH-W6-Exercise-A /TR "{hb}" /F'}),
        ev("2026-01-01T10:00:01Z", "4698", **{"winlog.event_data.TaskName": "\\ITH-W6-Exercise-A", "winlog.event_data.TaskContent": pt1m}),
        ev("2026-01-01T10:01:00Z", "4688", **{"process.name": "cmd.exe", "process.parent.name": "svchost.exe", "process.command_line": hb}),
        # PowerShell logs the whole .ps1 once, before method A starts -> not tied to one method
        ev("2026-01-01T09:59:58Z", "4104", **{"powershell.file.script_block_text":
           "$TaskA = 'ITH-W6-Exercise-A'; $TaskB = 'ITH-W6-Exercise-B'; Register-ScheduledTask -TaskName $TaskB"}),
        ev("2026-01-01T10:03:01Z", "4698", **{"winlog.event_data.TaskName": "\\ITH-W6-Exercise-B", "winlog.event_data.TaskContent": pt1m}),
        ev("2026-01-01T10:03:31Z", "4688", **{"process.name": "cmd.exe", "process.parent.name": "svchost.exe", "process.command_line": hb}),
    ]
    r = analyse(events, runlog)
    checks = [
        ("A: Week 3 Sigma fires on the schtasks command line", "W3-SIGMA" in r["A"]["detections"]),
        ("B: Week 3 Sigma does NOT fire (no schtasks.exe)", "W3-SIGMA" not in r["B"]["detections"]),
        ("A and B: 4698 PT1M hunt (W5-H2c) fires", all("W5-H2c" in r[m]["detections"] for m in "AB")),
        ("A and B: techniques = T1053.005 + T1059.003", all(r[m]["techniques"] == ["T1053.005", "T1059.003"] for m in "AB")),
        ("whole-script 4104 -> T1059.001, not tied to a method", r["setup/other"]["techniques"] == ["T1053.005", "T1059.001"]),
        ("cmd.exe heartbeat attributed by time window", r["B"]["observations"]["4688 cmd.exe started by Task Scheduler"]["count"] == 1),
    ]
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return all(ok for _, ok in checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", type=Path)
    ap.add_argument("--runlog", type=Path)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(0 if selftest() else 1)
    if not a.events or not a.runlog:
        ap.error("--events and --runlog are required (or use --selftest)")
    runlog = read_csv(a.runlog)
    result = analyse(read_csv(a.events), runlog)
    out = WEEK / "results"
    out.mkdir(exist_ok=True)
    (out / "w6_results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (out / "w6_results.md").write_text(report(result, runlog), encoding="utf-8")
    (WEEK / "navigator" / "t1053_005_observed_layer.json").write_text(
        json.dumps(build_layer(result), indent=2) + "\n", encoding="utf-8")
    for m, r in result.items():
        print(f"{m:12} techniques={','.join(r['techniques']) or '-':32} detections={','.join(r['detections']) or '-'}")
    print("Wrote results/w6_results.md, results/w6_results.json, navigator/t1053_005_observed_layer.json")


if __name__ == "__main__":
    main()
