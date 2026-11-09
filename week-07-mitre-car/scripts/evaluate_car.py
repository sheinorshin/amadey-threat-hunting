#!/usr/bin/env python3
"""
evaluate_car.py - Week 7: run the selected CAR analytics (and my tuned version) against data and test cases.

Variants (same logic as queries/ and sigma/):
  CAR-2013-08-001         Execution with schtasks - pseudocode: any process whose exe is schtasks.exe
  CAR-2021-12-001         Suspicious scheduled task - pseudocode semantics (case-insensitive, like Splunk):
                          (A) 4688/Sysmon 1: command line has SCHTASKS + /CREATE|/CHANGE + a suspicious term
                          (B) 4698/4702: TaskContent has a suspicious term (extension, LOLBin or writable path)
  CAR-2021-12-001-elastic the Elastic query published in CAR, evaluated with Elastic's semantics for
                          keyword/wildcard fields: wildcard matching is CASE-SENSITIVE
  TUNED                   my implementation, case-insensitive: (A) schtasks /create|/change and (B) 4698/4702 when
                          the action is in a USER-WRITABLE PATH (one known-benign path excluded: Windows Defender
                          platform under ProgramData) OR the task runs a script interpreter / LOLBin EVERY MINUTE;
                          severity high when the task repeats every minute (PT1M), else medium

Inputs:
  week-05-threat-hunting/data/dataset.ndjson (976 synthetic ECS events, 1 planted Amadey task) - always
  built-in TEST_CASES (labelled, one event each)                                              - always
  --week6-events <csv>  the Week 6 Kibana export (queries/w6_exercise_events.esql)            - optional

Output: data/evaluation.json + the tables printed as Markdown.   Standard library only.
"""
import argparse
import csv
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
DATASET = ROOT / "week-05-threat-hunting" / "data" / "dataset.ndjson"

# --- CAR-2021-12-001 term lists, copied from the analytic (pseudocode / Splunk / Elastic implementations) ---
EXTENSIONS = [".cmd", ".ps1", ".vbs", ".py", ".js", ".exe", ".bat"]
BINARIES = ["javascript", "powershell", "wmic", "rundll32", "cmd", "cscript", "wscript", "regsvr32", "mshta",
            "bitsadmin", "certutil", "msiexec", "javaw"]
CAR_PATHS = ["%APPDATA%", "\\AppData\\Roaming", "%PUBLIC%", "C:\\Users\\Public", "%ProgramData%", "C:\\ProgramData",
             "%TEMP%", "\\AppData\\Local\\Temp", "\\Windows\\PLA\\System", "\\tasks", "\\Registration\\CRMLog",
             "\\FxsTmp", "\\spool\\drivers\\color", "\\tracing"]
CAR_TERMS = EXTENSIONS + BINARIES + CAR_PATHS

# --- my tuned version: writable-path terms only (CAR's path list + the generic user-profile locations) ---
TUNED_PATHS = ["\\AppData\\", "\\Users\\Public\\", "\\ProgramData\\", "\\Temp\\", "%APPDATA%", "%LOCALAPPDATA%",
               "%TEMP%", "%PUBLIC%", "%ProgramData%", "\\Windows\\Tasks\\", "\\Windows\\PLA\\System",
               "\\Registration\\CRMLog", "\\FxsTmp", "\\spool\\drivers\\color", "\\tracing\\"]
TUNED_EXCLUDE = ["\\ProgramData\\Microsoft\\Windows Defender\\"]
# Amadey v5 on Windows 10/11 installs to C:\Users\<user>\<10 hex>\ (Microsoft) - a user profile folder that
# none of the generic terms names; catch "directly under the profile" with a regex on the task command
PROFILE_ROOT_EXE = re.compile(r".*c:\\users\\[^\\]+\\[^\\]+\\[^\\]+\.exe.*", re.I | re.S)   # same as the Sigma rule

VARIANTS = ["CAR-2013-08-001", "CAR-2021-12-001", "CAR-2021-12-001-elastic", "TUNED"]


def g(ev, dotted):
    cur = ev
    for k in dotted.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return ""
        cur = cur[k]
    return cur if isinstance(cur, str) else ""


def norm(ev):
    """Flat view of an event: works for nested ECS (Week 5 NDJSON) and flat CSV exports (Week 6)."""
    if "event.code" in ev:
        get = lambda k: ev.get(k) or ""
    else:
        get = lambda k: g(ev, k)
    cl = get("process.command_line")
    return {"code": str(get("event.code")), "cl": cl,
            "proc": (get("process.name") or cl.split(" ")[0].split("\\")[-1]).lower(),
            "task": get("winlog.event_data.TaskContent"), "host": get("host.name"), "ts": get("@timestamp")}


def has(text, terms, case_sensitive=False):
    if case_sensitive:
        return any(t in text for t in terms)
    low = text.lower()
    return any(t.lower() in low for t in terms)


def fire(variant, e):
    code, cl, task = e["code"], e["cl"], e["task"]
    is_proc = code in ("4688", "1")
    is_task = code in ("4698", "4702")
    if variant == "CAR-2013-08-001":
        return is_proc and e["proc"] == "schtasks.exe"
    if variant == "CAR-2021-12-001":
        a = is_proc and has(cl, ["schtasks"]) and has(cl, ["/create", "/change"]) and has(cl, CAR_TERMS)
        b = is_task and has(task, CAR_TERMS)
        return a or b
    if variant == "CAR-2021-12-001-elastic":
        # process.command_line:*SCHTASKS* AND (*\/CREATE* OR *\/CHANGE*) ... - wildcard on keyword = case-sensitive
        a = is_proc and "SCHTASKS" in cl and has(cl, ["/CREATE", "/CHANGE"], True) and has(cl, CAR_TERMS, True)
        b = is_task and has(task, CAR_TERMS, True)
        return a or b
    if variant == "TUNED":
        def suspicious(text):
            writable = has(text, TUNED_PATHS) and not has(text, TUNED_EXCLUDE)
            return writable or bool(PROFILE_ROOT_EXE.fullmatch(text)) or (every_minute(text) and has(text, BINARIES))
        a = is_proc and e["proc"] == "schtasks.exe" and has(cl, ["/create", "/change"]) and suspicious(cl)
        b = is_task and suspicious(task)
        return bool(a or b)
    raise ValueError(variant)


def every_minute(text):
    text = text.lower()
    return "pt1m" in text or bool(re.fullmatch(r".*/sc[ ]+minute.*/mo[ ]+1([^0-9].*)?", text, re.S))   # as in Sigma


def severity(e):
    return "high" if every_minute(e["task"] + " " + e["cl"]) else "medium"


def tc(cmd, interval=None):
    rep = f"<Repetition><Interval>{interval}</Interval></Repetition>" if interval else ""
    return f"<Triggers><TimeTrigger>{rep}</TimeTrigger></Triggers><Actions><Exec><Command>{cmd}</Command></Exec></Actions>"


# One event per case. True = should alert in a SOC watching for Amadey-style persistence, False = benign,
# None = not scored (CAR's own demo command: a System32 program, only there to show the analytic fires).
TEST_CASES = [
    ("CAR unit test 1 (calc.exe from System32, every minute)", None, {"event.code": "4688", "process.name": "schtasks.exe",
     "process.command_line": 'SCHTASKS /CREATE /SC MINUTE /MO 1 /TN "CALC_TASK" /TR "C:\\Windows\\System32\\calc.exe"'}),
    ("CAR unit test 2 (cmd ping every minute)", True, {"event.code": "4688", "process.name": "schtasks.exe",
     "process.command_line": 'SCHTASKS /CREATE /SC MINUTE /MO 1 /TN "PING_TASK" /TR "cmd /c ping 8.8.8.8"'}),
    ("Amadey v3/v4 - schtasks, %TEMP%\\<hex>", True, {"event.code": "4688", "process.name": "schtasks.exe",
     "process.command_line": 'schtasks.exe /Create /SC MINUTE /MO 1 /TN bguuwe.exe /TR "C:\\Users\\u1\\AppData\\Local\\Temp\\9487d68b99\\bguuwe.exe" /F'}),
    ("Amadey v3/v4 - its 4698 event", True, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("C:\\Users\\u1\\AppData\\Local\\Temp\\9487d68b99\\bguuwe.exe", "PT1M")}),
    ("Amadey v5 - COM API, 4698 only (Win10/11 path)", True, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("C:\\Users\\u1\\e079729711\\nudwee.exe", "PT1M")}),
    ("Week 6 Method A - schtasks.exe", True, {"event.code": "4688", "process.name": "schtasks.exe",
     "process.command_line": 'schtasks.exe /Create /SC MINUTE /MO 1 /TN ITH-W6-Exercise-A /TR "cmd.exe /c C:\\Users\\Public\\ITH-W6\\ith-w6-heartbeat.cmd" /F'}),
    ("Week 6 Method B - cmdlet, 4698 only", True, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("cmd.exe</Command><Arguments>/c C:\\Users\\Public\\ITH-W6\\ith-w6-heartbeat.cmd</Arguments><Command>", "PT1M")}),
    ("Benign - admin queries tasks (schtasks /Query)", False, {"event.code": "4688", "process.name": "schtasks.exe",
     "process.command_line": "schtasks.exe /Query /FO LIST /V"}),
    ("Benign - Google Update task", False, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe")}),
    ("Benign - Office ClickToRun task (hourly)", False, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe", "PT1H")}),
    ("Benign - Windows Defender task (ProgramData)", False, {"event.code": "4698",
     "winlog.event_data.TaskContent": tc("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25010.11-0\\MpCmdRun.exe")}),
]


def evaluate(events, truth):
    out = {}
    for v in VARIANTS:
        hits = [e for e in events if fire(v, e)]
        tp = sum(truth(e) for e in hits)
        out[v] = {"alerts": len(hits), "true_positive": tp, "false_positive": len(hits) - tp,
                  "incident_detected": tp > 0}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--week6-events", type=Path)
    a = ap.parse_args()

    ds = [norm(json.loads(l)) for l in DATASET.read_text(encoding="utf-8").splitlines() if l.strip()]
    def truth(e):                         # the planted Amadey task (Week 5): its schtasks call and its 4698
        return "yfgfwb" in (e["cl"] + e["task"]).lower() and (e["code"] in ("4698", "4702") or e["proc"] == "schtasks.exe")
    task_related = [e for e in ds if e["code"] in ("4698", "4702") or e["proc"] == "schtasks.exe"]
    week5 = evaluate(ds, truth)

    cases = []
    for name, malicious, ev in TEST_CASES:
        e = norm(ev)
        cases.append({"case": name, "malicious": malicious, "severity": severity(e) if malicious else "",
                      **{v: fire(v, e) for v in VARIANTS}})
    case_score = {v: {"caught": sum(c[v] for c in cases if c["malicious"] is True),
                      "malicious": sum(c["malicious"] is True for c in cases),
                      "false_alarms": sum(c[v] for c in cases if c["malicious"] is False),
                      "benign": sum(c["malicious"] is False for c in cases)} for v in VARIANTS}

    result = {"week5_dataset": {"events": len(ds), "task_related_events": len(task_related),
                                "amadey_task_events": sum(truth(e) for e in ds), "by_variant": week5},
              "test_cases": cases, "test_case_score": case_score}
    if a.week6_events:
        with open(a.week6_events, newline="", encoding="utf-8-sig") as f:
            w6 = [norm(r) for r in csv.DictReader(f)]
        result["week6_lab"] = evaluate(w6, lambda e: "ith-w6" in (e["cl"] + e["task"]).lower())

    (WEEK / "data").mkdir(exist_ok=True)
    (WEEK / "data" / "evaluation.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")

    print(f"Week 5 dataset: {len(ds)} events, {len(task_related)} task-related, "
          f"{result['week5_dataset']['amadey_task_events']} belong to the planted Amadey task\n")
    print("| Variant | Alerts | On the Amadey task | False positives | Amadey task detected |\n|---|---|---|---|---|")
    for v, r in week5.items():
        print(f"| {v} | {r['alerts']} | {r['true_positive']} | {r['false_positive']} | {'yes' if r['incident_detected'] else 'no'} |")
    print("\n| Test case | Should alert | " + " | ".join(VARIANTS) + " |\n|---|---|" + "---|" * len(VARIANTS))
    for c in cases:
        expect = {True: f"yes ({c['severity']})", False: "no", None: "n/a (demo)"}[c["malicious"]]
        print(f"| {c['case']} | {expect} | "
              + " | ".join("✅" if c[v] else "—" for v in VARIANTS) + " |")
    print("| **Score** | | " + " | ".join(f"{s['caught']}/{s['malicious']} caught, {s['false_alarms']}/{s['benign']} false alarms"
                                         for s in case_score.values()) + " |")
    if "week6_lab" in result:
        print("\nWeek 6 lab export:", json.dumps(result["week6_lab"]))


if __name__ == "__main__":
    main()
