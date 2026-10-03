#!/usr/bin/env python3
"""
score_atomic_run.py - Week 9: map an Atomic Red Team run to ATT&CK and score my detections on it.

Inputs (all produced in the lab, see 03-siem-analysis.md):
  --runlog  what was run and when: the Invoke-AtomicTest execution log (CSV written by the default execution
            logger) or my manual run sheet (templates/w9_run_sheet.csv) - the ground truth
  --events  CSV exported from Kibana with queries/w9_run_events.esql, time picker covering the whole run
  --alerts  optional: CSV exported with queries/w9_alerts.esql - shows whether the rules deployed in Kibana fired
  --window  minutes after a test's start that still belong to that test (default 3; never past the next test)

Outputs:
  results/w9_results.md     per test: events, ATT&CK techniques observed, detections fired, result category,
                            time to detect, prediction check; per-technique summary; detection matrix
  results/w9_results.json   the same, machine-readable
  navigator/w9_observed_layer.json   3 = Technique, 2 = General/Tactic, 1 = Telemetry, 0 = None

How events are tied to a test (the purple-team join of "what was done" with "what was logged"):
  1. time window: [start - 5 s, min(start + window, next test start)) on the same host
  2. process tree: if the log has the test's ProcessId, only processes descending from it (and their 4104 script
     blocks, Sysmon events) count; service-side events (4698, 4720, 4946, ...) are joined by window only;
     Task Scheduler run events only for task names created inside the same test
  3. framework noise (Invoke-AtomicTest's own script blocks) and known agents are never counted

Result categories (adapted from MITRE ATT&CK Evaluations): None - nothing that shows the test reached the SIEM;
Telemetry - events, no detection; General - a detection fired that names no technique or another technique and
tactic (a Defender alert counts here: it is a detection in the SIEM, but not one of my rules);
Tactic - fired, mapped to the same tactic; Technique - fired, mapped to the tested technique (or its parent/child).
Flags: AV (Defender 1116/1117 in the window), FAILED (exit code not 0).

Detections re-implemented with the same logic as the originals (Week 7's tuned CAR logic is imported, not copied):
  W3-SCHTASKS, W3-HEXEXE, W3-RUNDLL32, W5-H1a, W5-H1b, W5-H2b, W5-H2c, W5-H3, W5-H3-confirmed, W7-CAR-PROC, W7-CAR-TASK
  + AV-DEFENDER (Defender 1116/1117 reaching the SIEM through the Custom Windows Event Log integration)

  python score_atomic_run.py --runlog Invoke-AtomicTest-ExecutionLog.csv --events export.csv [--alerts alerts.csv]
  python score_atomic_run.py --selftest       # checks the logic on built-in sample events, writes nothing

Standard library only.
"""
import argparse
import csv
import importlib.util
import json
import re
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
PLAN = WEEK / "data" / "test_plan.json"
CAR_MODULE = ROOT / "week-07-mitre-car" / "scripts" / "evaluate_car.py"

CATEGORY_SCORE = OrderedDict([("None", 0), ("Telemetry", 1), ("General", 2), ("Tactic", 2), ("Technique", 3)])
RANK = {"None": 0, "Telemetry": 1, "General": 2, "Tactic": 3, "Technique": 4}

PROC_CODES = {"4688"}                     # + Sysmon 1 (checked with the dataset)
SERVICE_CODES = {"4698", "4699", "4702", "106", "140", "141", "4720", "4722", "4724", "4726", "4732", "4733",
                 "4946", "4947", "4948", "1102", "4719", "7045", "1116", "1117"}
TASK_RUN_CODES = {"100", "102", "129", "200", "201"}
TS_PARENTS = {"svchost.exe", "taskeng.exe", "taskhostw.exe"}
NOISE_PROCS = {"elastic-agent.exe", "elastic-endpoint.exe", "filebeat.exe", "metricbeat.exe", "osqueryd.exe",
               "winlogbeat.exe", "fleet-server.exe"}
FRAMEWORK_MARKERS = ("invoke-atomictest", "invoke-executecommand", "write-executionlog", "invoke-atomicredteam")
USER_PATHS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\")
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "wmic.exe", "regsvr32.exe"}
H1B = re.compile(r".*(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr |net\.webclient|"
                 r"frombase64string|iex |reflection\.assembly\]::load).*", re.S)       # Week 5 H1 query (2)
HEX_TEMP = re.compile(r".*\\appdata\\local\\temp\\[0-9a-f]{10}\\[a-z]{4,10}\.exe", re.I)   # Week 3 Sigma
HEX_PROFILE = re.compile(r"[a-z]:\\users\\[^\\]+\\[0-9a-f]{10}\\[a-z]{4,10}\.exe", re.I)

DETECTIONS = OrderedDict([
    ("W3-SCHTASKS", {"techniques": ["T1053.005"], "label": "Week 3 Sigma: schtasks every minute from a user folder"}),
    ("W3-HEXEXE", {"techniques": ["T1204.002"], "label": "Week 3 Sigma: EXE from a 10-hex-character folder"}),
    ("W3-RUNDLL32", {"techniques": ["T1218.011", "T1555.003", "T1115"],
                     "label": "Week 3 Sigma: rundll32 loading Amadey cred/clip plugin"}),
    ("W5-H1a", {"techniques": ["T1059.001", "T1059.007", "T1218.005"], "label": "Week 5 H1 (1): script host -> PowerShell"}),
    ("W5-H1b", {"techniques": ["T1059.001", "T1105"], "label": "Week 5 H1 (2): 4104 download cradle / encoded exec"}),
    ("W5-H2b", {"techniques": ["T1053.005"], "label": "Week 5 H2 (2): schtasks /SC MINUTE /MO 1"}),
    ("W5-H2c", {"techniques": ["T1053.005"], "label": "Week 5 H2 (3): 4698 task with PT1M"}),
    ("W5-H3", {"techniques": ["T1136.001"], "label": "Week 5 H3: new account / member added to Administrators"}),
    ("W5-H3-confirmed", {"techniques": ["T1136.001", "T1686", "T1021.001"],
                         "label": "Week 5 H3: new admin + firewall rule on one host within 30 min"}),
    ("W7-CAR-PROC", {"techniques": ["T1053.005"], "label": "Week 7 CAR-2021-12-001 tuned, process branch"}),
    ("W7-CAR-TASK", {"techniques": ["T1053.005"], "label": "Week 7 CAR-2021-12-001 tuned, Task Scheduler branch"}),
    ("AV-DEFENDER", {"techniques": [], "label": "Microsoft Defender 1116/1117 (antivirus, not one of my rules)"}),
])
# Kibana rule names -> my detection IDs (Week 7 NDJSON names; Week 3 Sigma titles if those were imported too)
KIBANA_RULES = {
    "schtasks creates or changes a task with a user-writable or every-minute interpreter action": "W7-CAR-PROC",
    "scheduled task created or changed with a user-writable or every-minute interpreter action": "W7-CAR-TASK",
    "amadey-style scheduled task running every minute from user folder": "W3-SCHTASKS",
    "executable started from 10-hex-character folder in temp or user profile": "W3-HEXEXE",
    "rundll32 loading amadey credential/clipper plugin": "W3-RUNDLL32",
}
# every technique classify() can emit - build_test_plan.py stores their ATT&CK v19.2 tactics in data/test_plan.json
EMITTED = ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1053.005",
           "T1003.001", "T1003.002", "T1547.001", "T1112", "T1021.001", "T1136.001", "T1098", "T1098.007",
           "T1087.001", "T1087.002", "T1069.001", "T1069.002", "T1686", "T1105", "T1197", "T1082", "T1016", "T1033",
           "T1057", "T1685.005", "T1685.001", "T1543.003", "T1204.002", "T1555.003", "T1115"]


# ------------------------------------------------------------------------------------------------ parsing
TIME_FORMATS = ["%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"]


def parse_ts(s):
    """ISO 8601 (Kibana, my run sheet) or the common Windows formats of the execution log; naive = UTC."""
    s = (s or "").strip()
    if not s:
        return None
    iso = s.replace("Z", "+00:00")
    if re.match(r"\d{4}-\d{2}-\d{2}T", iso):
        m = re.match(r"(.*?\.\d{1,6})\d*(.*)", iso)                 # Python < 3.11 accepts at most 6 decimals
        iso = m.group(1) + m.group(2) if m else iso
        dt = datetime.fromisoformat(iso)
    else:
        for fmt in TIME_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unknown time format: {s!r} - use ISO 8601 (2026-10-05T10:00:00Z) in the run sheet")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def col(row, *names):
    low = {k.strip().lower(): v for k, v in row.items() if k}
    for n in names:
        if n in low and low[n] not in (None, ""):
            return str(low[n]).strip()
    return ""


def norm_pid(v):
    v = (v or "").strip().replace(",", "")
    if not v:
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(float(v))
    except ValueError:
        return None


def read_runlog(rows, window_min):
    tests = []
    for r in rows:
        phase = col(r, "phase").lower()
        name = col(r, "test name", "test_name")
        if phase == "cleanup" or name.lower().startswith("cleanup"):
            continue
        start = parse_ts(col(r, "execution time (utc)", "utc_start", "start_utc", "start"))
        if not start:
            continue
        tests.append({
            "technique": col(r, "technique", "technique_id").upper(),
            "test_number": col(r, "test number", "test_number"),
            "test_name": name, "guid": col(r, "guid", "test_guid", "auto_generated_guid"),
            "host": col(r, "hostname", "host").lower(),
            "pid": norm_pid(col(r, "processid", "process id", "pid")),
            "exit_code": col(r, "exitcode", "exit code", "exit_code"),
            "start": start, "end_given": parse_ts(col(r, "utc_end", "end_utc", "end")),
            "plan_id": col(r, "plan_id"),
        })
    tests.sort(key=lambda t: t["start"])
    for i, t in enumerate(tests):
        end = t["end_given"] + timedelta(seconds=30) if t["end_given"] else t["start"] + timedelta(minutes=window_min)
        if i + 1 < len(tests):
            end = min(end, tests[i + 1]["start"] - timedelta(seconds=5))
        t["window"] = (t["start"] - timedelta(seconds=5), end)
        t["key"] = f"{i + 1:02d} {t['technique']}" + (f"-{t['test_number']}" if t["test_number"] else "")
    return tests


def norm_event(r, idx):
    get = lambda *k: col(r, *[x.lower() for x in k])
    cl = get("process.command_line")
    exe = get("process.executable")
    proc = (get("process.name") or exe.split("\\")[-1] or cl.split(" ")[0].strip('"').split("\\")[-1]).lower()
    code = get("event.code")
    dataset = get("data_stream.dataset", "event.dataset").lower()
    is_sysmon = "sysmon" in dataset
    return {
        "idx": idx, "ts": parse_ts(get("@timestamp")), "raw_ts": get("@timestamp"), "host": get("host.name").lower(),
        "code": code, "sysmon": is_sysmon, "dataset": dataset,
        "is_proc": code in PROC_CODES or (code == "1" and is_sysmon),
        # 4104: PowerShell's own PID may only be in winlog.process.pid (never use that field for Security events:
        # there it is the PID of the process that wrote the log)
        "pid": norm_pid(get("process.pid") or (get("winlog.process.pid") if code == "4104" else "")),
        "ppid": norm_pid(get("process.parent.pid")),
        "proc": proc, "parent": (get("process.parent.name") or get("process.parent.executable").split("\\")[-1]).lower(),
        "exe": exe, "cl": cl, "task": get("winlog.event_data.TaskName"),
        "task_content": get("winlog.event_data.TaskContent"),
        "target_user": get("winlog.event_data.TargetUserName", "user.target.name"),
        "member": get("winlog.event_data.MemberName", "winlog.event_data.MemberSid"),
        "rule": get("winlog.event_data.RuleName"),
        "sb": get("powershell.file.script_block_text"),
        "reg": get("registry.path"), "target_image": get("winlog.event_data.TargetImage"),
        "raw": r,
    }


# --------------------------------------------------------------------------------------------- ATT&CK map
def classify(e):
    """One event -> (observation, [ATT&CK technique IDs]). Same idea as Week 6, extended to the plan's techniques."""
    code, proc, cl, parent = e["code"], e["proc"], e["cl"].lower(), e["parent"]
    if e["is_proc"]:
        t = []
        if proc in ("powershell.exe", "pwsh.exe"):
            t.append("T1059.001")
            if re.search(r"invoke-webrequest|\biwr\b|downloadstring|downloadfile|start-bitstransfer|net\.webclient", cl):
                t.append("T1105")
        elif proc == "cmd.exe":
            t.append("T1059.003")
        elif proc in ("wscript.exe", "cscript.exe"):
            if re.search(r"\.jse?\b|jscript|javascript", cl):
                t.append("T1059.007")
            elif re.search(r"\.vbe?s?\b|vbscript", cl):
                t.append("T1059.005")
        elif proc == "mshta.exe":
            t.append("T1218.005")
        elif proc == "rundll32.exe":
            t.append("T1218.011")
        elif proc == "regsvr32.exe":
            t.append("T1218.010")
        elif proc == "schtasks.exe":
            if "/create" in cl or "/change" in cl:
                t.append("T1053.005")
            elif "/delete" in cl:
                return "4688 schtasks.exe /Delete (cleanup)", []
        elif proc == "reg.exe":
            if " save " in f" {cl} " and re.search(r"hklm\\(sam|system|security)\b", cl):
                t.append("T1003.002")
            elif re.search(r"\\currentversion\\run|user shell folders", cl):
                t.append("T1547.001")
            elif "fdenytsconnections" in cl:
                t += ["T1112", "T1021.001"]
            elif " add " in f" {cl} ":
                t.append("T1112")
        elif proc in ("net.exe", "net1.exe"):
            if " user " in f" {cl} " and "/add" in cl:
                t.append("T1136.001")
            elif "localgroup" in cl and "/add" in cl:
                t.append("T1098.007")
            elif " user" in cl:
                t.append("T1087.002" if "/domain" in cl else "T1087.001")
            elif "group" in cl:
                t.append("T1069.002" if "/domain" in cl else "T1069.001")
        elif proc == "netsh.exe":
            if "firewall" in cl and re.search(r"\b(add|set)\b", cl):
                t.append("T1686")
            elif "interface" in cl:
                t.append("T1016")
        elif proc == "certutil.exe" and ("urlcache" in cl or "http" in cl):
            t.append("T1105")
        elif proc == "bitsadmin.exe":
            t += ["T1197", "T1105"] if "http" in cl else ["T1197"]
        elif proc == "curl.exe" and "http" in cl:
            t.append("T1105")
        elif proc in ("systeminfo.exe", "hostname.exe"):
            t.append("T1082")
        elif proc in ("ipconfig.exe", "route.exe", "arp.exe"):
            t.append("T1016")
        elif proc in ("whoami.exe", "quser.exe"):
            t.append("T1033")
        elif proc == "tasklist.exe":
            t.append("T1057")
        if "lsass" in cl and re.search(r"minidump|comsvcs|procdump|\.dmp", cl):
            t.append("T1003.001")
        if parent in TS_PARENTS and proc in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                                             "rundll32.exe", "mshta.exe"):
            t.append("T1053.005")
        return f"{'Sysmon 1' if e['sysmon'] else '4688'} {proc}", sorted(set(t))
    if code == "4104":
        sb = e["sb"].lower()
        t = ["T1059.001"]
        for pat, tid in [(r"register-scheduledtask|new-scheduledtask", "T1053.005"), (r"new-localuser", "T1136.001"),
                         (r"add-localgroupmember", "T1098.007"), (r"new-netfirewallrule|set-netfirewallrule", "T1686"),
                         (r"invoke-webrequest|\biwr\b|downloadstring|downloadfile|start-bitstransfer|net\.webclient", "T1105"),
                         (r"currentversion\\run", "T1547.001"), (r"fdenytsconnections", "T1112"),
                         (r"get-computerinfo|systeminfo", "T1082")]:
            if re.search(pat, sb):
                t.append(tid)
        if "fdenytsconnections" in sb:
            t.append("T1021.001")
        return "4104 script block", sorted(set(t))
    if e["sysmon"]:
        if code == "13":
            p = e["reg"].lower()
            if "\\currentversion\\run" in p or "user shell folders" in p:
                return "Sysmon 13 registry value set (autostart)", ["T1547.001"]
            if "fdenytsconnections" in p:
                return "Sysmon 13 registry value set (RDP enabled)", ["T1021.001", "T1112"]
            return "Sysmon 13 registry value set", ["T1112"]
        if code == "10" and "lsass" in e["target_image"].lower():
            return "Sysmon 10 process access to lsass.exe", ["T1003.001"]
        return f"Sysmon {code}", []
    named = {
        "4698": ("4698 scheduled task created", ["T1053.005"]),
        "4702": ("4702 scheduled task updated", ["T1053.005"]),
        "4699": ("4699 scheduled task deleted (cleanup)", []),
        "106": ("TaskScheduler 106 task registered", ["T1053.005"]),
        "140": ("TaskScheduler 140 task updated", ["T1053.005"]),
        "141": ("TaskScheduler 141 task deleted (cleanup)", []),
        "100": ("TaskScheduler 100 task started", ["T1053.005"]),
        "102": ("TaskScheduler 102 task completed", ["T1053.005"]),
        "129": ("TaskScheduler 129 task process created", ["T1053.005"]),
        "200": ("TaskScheduler 200 action started", ["T1053.005"]),
        "201": ("TaskScheduler 201 action completed", ["T1053.005"]),
        "4720": ("4720 user account created", ["T1136.001"]),
        "4722": ("4722 user account enabled", []),
        "4724": ("4724 password reset", ["T1098"]),
        "4726": ("4726 user account deleted (cleanup)", []),
        "4732": ("4732 member added to a local group", ["T1098.007"]),
        "4733": ("4733 member removed from a local group (cleanup)", []),
        "4946": ("4946 firewall rule added", ["T1686"]),
        "4947": ("4947 firewall rule modified", ["T1686"]),
        "4948": ("4948 firewall rule deleted (cleanup)", []),
        "1102": ("1102 audit log cleared", ["T1685.005"]),
        "4719": ("4719 audit policy changed", ["T1685.001"]),
        "7045": ("7045 service installed", ["T1543.003"]),
        "1116": ("Defender 1116 malware detected", []),
        "1117": ("Defender 1117 action taken", []),
    }
    return named.get(code, (f"event {code}", []))


# ------------------------------------------------------------------------------------------- detections
def load_car():
    if not CAR_MODULE.exists():
        return None
    spec = importlib.util.spec_from_file_location("evaluate_car", CAR_MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fired_on_event(e, car):
    """Single-event detections (everything except the H3 correlation)."""
    out = []
    cl, proc = e["cl"].lower(), e["proc"]
    if e["is_proc"]:
        if proc == "schtasks.exe":
            if all(k in cl for k in ("/create", "/sc minute", "/mo 1", "/tr")) and any(p in cl for p in USER_PATHS):
                out.append("W3-SCHTASKS")
            if re.search(r"/sc\s+minute", cl) and re.search(r"/mo\s+1\b", cl):
                out.append("W5-H2b")
        if HEX_TEMP.fullmatch(e["exe"]) or HEX_PROFILE.fullmatch(e["exe"]):
            out.append("W3-HEXEXE")
        if proc == "rundll32.exe" and any(x in cl for x in ("\\cred.dll", "\\cred64.dll", "\\clip.dll", "\\clip64.dll")):
            out.append("W3-RUNDLL32")
        if proc == "powershell.exe" and e["parent"] in SCRIPT_HOSTS:
            out.append("W5-H1a")
    if e["code"] == "4104" and H1B.fullmatch(e["sb"].lower()):
        out.append("W5-H1b")
    if e["code"] == "4698" and "pt1m" in e["task_content"].lower():
        out.append("W5-H2c")
    if e["code"] == "4720" or (e["code"] == "4732" and e["target_user"].lower() == "administrators"):
        out.append("W5-H3")
    if e["code"] in ("1116", "1117"):
        out.append("AV-DEFENDER")
    if car is not None:
        flat = {"event.code": "4688" if e["is_proc"] else e["code"], "process.name": e["proc"],
                "process.command_line": e["cl"], "winlog.event_data.TaskContent": e["task_content"]}
        if car.fire("TUNED", car.norm(flat)):
            out.append("W7-CAR-PROC" if e["is_proc"] else "W7-CAR-TASK")
    return out


def h3_confirmations(events):
    """Week 5 H3 EQL: account event (4720 / 4732 Administrators) and firewall rule (4946) on one host within 30 min.
    The detection 'fires' on the later event of the pair."""
    acct = [e for e in events if "W5-H3" in e["fired"]]
    fw = [e for e in events if e["code"] == "4946"]
    for f in fw:
        for a in acct:
            if a["host"] == f["host"] and abs((f["ts"] - a["ts"]).total_seconds()) <= 1800:
                later = f if f["ts"] >= a["ts"] else a
                if "W5-H3-confirmed" not in later["fired"]:
                    later["fired"].append("W5-H3-confirmed")


# ----------------------------------------------------------------------------------------------- scoring
def family(a, b):
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


def attribute(tests, events):
    """Assign each event to at most one test (or to 'background')."""
    for t in tests:
        lo, hi = t["window"]
        inwin = [e for e in events if e["ts"] and lo <= e["ts"] < hi and (not t["host"] or not e["host"]
                                                                          or e["host"].split(".")[0] == t["host"].split(".")[0])]
        tree = {t["pid"]} if t["pid"] is not None else set()
        if tree:
            for e in sorted(inwin, key=lambda x: x["ts"]):
                if e["is_proc"] and e["ppid"] in tree and e["pid"] is not None:
                    tree.add(e["pid"])
        tasks = set()
        for e in inwin:
            if e.get("owner"):
                continue
            if e["code"] == "4104" and any(m in e["sb"].lower() for m in FRAMEWORK_MARKERS):
                e["owner"] = "framework"
                continue
            if e["proc"] in NOISE_PROCS:
                continue
            if e["code"] in SERVICE_CODES:
                e["owner"] = t["key"]
            elif tree:
                if e["pid"] in tree or (e["is_proc"] and e["ppid"] in tree):
                    e["owner"] = t["key"]
            elif e["code"] not in TASK_RUN_CODES:
                e["owner"] = t["key"]                          # no ProcessId in the log: window only
            if e.get("owner") == t["key"] and e["code"] in ("4698", "106", "4702", "140"):
                tasks.add(e["task"].lower().strip("\\"))
            if e.get("owner") == t["key"] and e["is_proc"] and e["proc"] == "schtasks.exe":
                m = re.search(r'/tn\s+"?([^"/]+?)"?\s+/', e["cl"], re.I)
                if m:
                    tasks.add(m.group(1).lower().strip().strip("\\"))
        for e in inwin:
            if not e.get("owner") and e["code"] in TASK_RUN_CODES and e["task"].lower().strip("\\") in tasks:
                e["owner"] = t["key"]
        t["tree"] = sorted(p for p in tree if p is not None)


def score(tests, events, alerts, plan):
    tactics = plan.get("tactics", {})
    predicted = {}
    for p in plan.get("tests", []):
        predicted.setdefault(p["technique"], p["predicted"])
    by_owner = defaultdict(list)
    for e in events:
        if e.get("owner") and e["owner"] != "framework":
            by_owner[e["owner"]].append(e)
    results = OrderedDict()
    for t in tests:
        evs = sorted(by_owner[t["key"]], key=lambda e: e["ts"])
        tid = t["technique"]
        obs, techs, fired, evidence = OrderedDict(), set(), OrderedDict(), 0
        av = False
        for e in evs:
            label, tt = classify(e)
            if e["is_proc"] and t["pid"] is not None and e["pid"] == t["pid"]:
                # the executor Invoke-AtomicTest started (powershell.exe / cmd.exe): its command line carries the
                # test's commands, so it is evidence only when it shows the tested technique itself
                label, tt = f"executor: {label}", [x for x in tt if family(tid, x)]
                evidence += bool(tt)
            else:
                evidence += 1
            o = obs.setdefault(label, {"count": 0, "first": e["raw_ts"]})
            o["count"] += 1
            techs.update(tt)
            av |= e["code"] in ("1116", "1117")
            for d in e["fired"]:
                fired.setdefault(d, (e["ts"] - t["start"]).total_seconds())
        kib = OrderedDict()
        for a in alerts:
            if a.get("owner") == t["key"]:
                kib.setdefault(a["rule"], a["delay"])
        dets = set(fired) | {KIBANA_RULES.get(r.lower(), f"KIBANA:{r}") for r in kib}
        det_techs = {x for d in dets for x in DETECTIONS.get(d, {"techniques": []})["techniques"]}
        if not evidence and not dets:
            cat = "None"
        elif any(family(tid, x) for x in det_techs):
            cat = "Technique"
        elif set(tactics.get(tid, [])) & {tac for x in det_techs for tac in tactics.get(x, [])}:
            cat = "Tactic"
        elif dets:
            cat = "General"
        else:
            cat = "Telemetry"
        first_det = min(fired.values()) if fired else None
        results[t["key"]] = {
            "technique": tid, "test_number": t["test_number"], "test_name": t["test_name"], "guid": t["guid"],
            "start_utc": t["start"].isoformat(), "window_end_utc": t["window"][1].isoformat(),
            "attribution": "process tree" if t["pid"] is not None else "time window only",
            "exit_code": t["exit_code"], "events": len(evs), "observations": obs,
            "techniques_observed": sorted(techs), "tested_technique_observed": any(family(tid, x) for x in techs),
            "detections_fired": list(fired), "kibana_alerts": kib, "category": cat,
            "seconds_to_first_detection": first_det,
            "flags": [f for f, on in (("AV", av), ("FAILED", t["exit_code"] not in ("", "0"))) if on],
            "predicted": predicted.get(tid),
        }
    return results


def per_technique(results):
    out = OrderedDict()
    for r in results.values():
        tid = r["technique"]
        cur = out.setdefault(tid, {"tests": 0, "best": "None", "categories": [], "predicted": r["predicted"]})
        cur["tests"] += 1
        cur["categories"].append(r["category"])
        if RANK[r["category"]] > RANK[cur["best"]]:
            cur["best"] = r["category"]
    for v in out.values():
        if v["predicted"]:
            d = RANK[v["best"]] - RANK[v["predicted"]]
            v["vs_prediction"] = "as predicted" if d == 0 else "better than predicted" if d > 0 else "worse than predicted"
        else:
            v["vs_prediction"] = "not in the plan"
    return out


def attach_alerts(alert_rows, tests):
    alerts = []
    for r in alert_rows:
        created = parse_ts(col(r, "@timestamp"))
        orig = parse_ts(col(r, "kibana.alert.original_time")) or created
        a = {"rule": col(r, "kibana.alert.rule.name"), "host": col(r, "host.name").lower(), "created": created,
             "orig": orig, "owner": None, "delay": None}
        for t in tests:
            lo, hi = t["window"]
            if orig and lo <= orig < hi and (not t["host"] or not a["host"]
                                             or a["host"].split(".")[0] == t["host"].split(".")[0]):
                a["owner"], a["delay"] = t["key"], (created - t["start"]).total_seconds()
        alerts.append(a)
    return alerts


def analyse(runlog_rows, event_rows, alert_rows=(), window_min=3, plan=None):
    plan = plan if plan is not None else (json.loads(PLAN.read_text(encoding="utf-8")) if PLAN.exists() else {})
    tests = read_runlog(runlog_rows, window_min)
    events = [norm_event(r, i) for i, r in enumerate(event_rows)]
    events = [e for e in events if e["ts"]]
    car = load_car()
    for e in events:
        e["fired"] = fired_on_event(e, car)
    h3_confirmations(events)
    attribute(tests, events)
    alerts = attach_alerts(alert_rows, tests)
    results = score(tests, events, alerts, plan)
    techniques = per_technique(results)
    n = len(results) or 1
    cats = [r["category"] for r in results.values()]
    timed = [r["seconds_to_first_detection"] for r in results.values() if r["seconds_to_first_detection"] is not None]
    kib_delays = [d for r in results.values() for d in r["kibana_alerts"].values() if d is not None]
    metrics = {
        "tests": len(results),
        "techniques": len(techniques),
        "visibility_rate": round(sum(c != "None" for c in cats) / n, 2),
        "technique_detection_rate": round(sum(c == "Technique" for c in cats) / n, 2),
        "any_detection_rate": round(sum(c in ("General", "Tactic", "Technique") for c in cats) / n, 2),
        "tested_technique_observed": sum(r["tested_technique_observed"] for r in results.values()),
        "by_category": {c: cats.count(c) for c in RANK},
        "median_seconds_to_detection": sorted(timed)[len(timed) // 2] if timed else None,
        "median_seconds_to_kibana_alert": sorted(kib_delays)[len(kib_delays) // 2] if kib_delays else None,
        "failed_tests": sum("FAILED" in r["flags"] for r in results.values()),
        "av_flagged_tests": sum("AV" in r["flags"] for r in results.values()),
        "background_events": sum(1 for e in events if not e.get("owner")),
        "alerts_outside_tests": sum(1 for a in alerts if not a["owner"]),
        "as_predicted": sum(v["vs_prediction"] == "as predicted" for v in techniques.values()),
        "better_than_predicted": sum(v["vs_prediction"] == "better than predicted" for v in techniques.values()),
        "worse_than_predicted": sum(v["vs_prediction"] == "worse than predicted" for v in techniques.values()),
    }
    return {"tests": results, "techniques": techniques, "metrics": metrics}


# ---------------------------------------------------------------------------------------------- outputs
def report(res):
    m = res["metrics"]
    L = ["# Week 9 Atomic Red Team run - results", "",
         "Generated by `scripts/score_atomic_run.py` from the execution log and the Kibana export - do not edit by hand.",
         "", "## Summary", "", "| Metric | Value |", "|---|---|",
         f"| Tests / techniques | {m['tests']} / {m['techniques']} |",
         f"| Visibility (any telemetry) | {m['visibility_rate']:.0%} |",
         f"| Technique-level detection | {m['technique_detection_rate']:.0%} |",
         f"| Any detection (General / Tactic / Technique) | {m['any_detection_rate']:.0%} |",
         f"| Tested technique seen in the mapped telemetry | {m['tested_technique_observed']} of {m['tests']} |",
         f"| Categories | " + ", ".join(f"{k} {v}" for k, v in m["by_category"].items()) + " |",
         f"| Median time to detection (event) / to Kibana alert | {m['median_seconds_to_detection']} s / "
         f"{m['median_seconds_to_kibana_alert']} s |",
         f"| Failed tests / Defender-flagged tests | {m['failed_tests']} / {m['av_flagged_tests']} |",
         f"| Background events in the windows / alerts outside any test | {m['background_events']} / {m['alerts_outside_tests']} |",
         f"| Predictions: as / better / worse | {m['as_predicted']} / {m['better_than_predicted']} / {m['worse_than_predicted']} |",
         "", "## Per test", "",
         "| # | Test | Events | Techniques observed | Detections fired | Kibana alerts | Result | Flags | Predicted |",
         "|---|---|---|---|---|---|---|---|---|"]
    for k, r in res["tests"].items():
        L.append(f"| {k} | {r['test_name'] or '—'} | {r['events']} | {', '.join(r['techniques_observed']) or '—'} | "
                 f"{', '.join(r['detections_fired']) or '—'} | {', '.join(r['kibana_alerts']) or '—'} | "
                 f"**{r['category']}** | {', '.join(r['flags']) or '—'} | {r['predicted'] or '—'} |")
    L += ["", "## Per technique (best result over its tests)", "",
          "| Technique | Tests | Best | Predicted | vs prediction |", "|---|---|---|---|---|"]
    for tid, v in res["techniques"].items():
        L.append(f"| {tid} | {v['tests']} | {v['best']} | {v['predicted'] or '—'} | {v['vs_prediction']} |")
    L += ["", "## Detection matrix", "", "| Detection | " + " | ".join(res["tests"]) + " |",
          "|---|" + "---|" * len(res["tests"])]
    for d, meta in DETECTIONS.items():
        L.append(f"| {d} - {meta['label']} | " + " | ".join(
            "✅" if d in r["detections_fired"] else "—" for r in res["tests"].values()) + " |")
    L += ["", "## Observations per test", ""]
    for k, r in res["tests"].items():
        L += [f"### {k} — {r['test_name'] or r['technique']}", "",
              f"Window {r['start_utc']} → {r['window_end_utc']} · attribution: {r['attribution']} · "
              f"exit code {r['exit_code'] or '?'} · GUID {r['guid'] or '?'}", "",
              "| Observation | Events | First seen |", "|---|---|---|"]
        L += [f"| {o} | {v['count']} | {v['first']} |" for o, v in r["observations"].items()] or ["| — | 0 | — |"]
        L.append("")
    return "\n".join(L) + "\n"


def layer(res):
    colors = {0: "#d03b3b", 1: "#fab219", 2: "#5dade2", 3: "#0ca30c"}
    plan = json.loads(PLAN.read_text(encoding="utf-8")) if PLAN.exists() else {}
    tactics = plan.get("tactics", {})
    techniques = []
    for tid, v in res["techniques"].items():
        s = CATEGORY_SCORE[v["best"]]
        for tac in tactics.get(tid, []) or [None]:
            item = {"techniqueID": tid, "score": s, "color": colors[s], "enabled": True, "showSubtechniques": False,
                    "comment": f"Observed in my lab: {v['best']} (tests: {', '.join(v['categories'])}); "
                               f"predicted {v['predicted'] or '-'} -> {v['vs_prediction']}."}
            if tac:
                item["tactic"] = tac
            techniques.append(item)
    return {
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "filters": {"platforms": ["Windows"]}, "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False, "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 9)"}],
        "name": "Week 9 Atomic Red Team run - observed results",
        "description": "Best observed result per technique: 3 = Technique-level detection, 2 = General/Tactic, "
                       "1 = Telemetry only, 0 = None.",
        "gradient": {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "Technique detection", "color": colors[3]},
                        {"label": "General / Tactic", "color": colors[2]},
                        {"label": "Telemetry only", "color": colors[1]}, {"label": "None", "color": colors[0]}],
        "showTacticRowBackground": False, "tacticRowBackground": "#dddddd", "techniques": techniques,
    }


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


# --------------------------------------------------------------------------------------------- selftest
def selftest():
    """Sample events shaped like the expected lab telemetry - tests the logic, not the lab."""
    runlog = [  # Invoke-AtomicTest execution-log columns; the first row uses a US-style time to test the parser
        {"Execution Time (UTC)": "1/1/2026 10:00:00 AM", "Technique": "T1053.005", "Test Number": "1",
         "Test Name": "sample: task every minute", "Hostname": "LAB-WIN", "GUID": "g1", "ProcessId": "4000", "ExitCode": "0"},
        {"Execution Time (UTC)": "2026-01-01T10:05:00Z", "Technique": "T1136.001", "Test Number": "1",
         "Test Name": "sample: local admin", "Hostname": "LAB-WIN", "GUID": "g2", "ProcessId": "5000", "ExitCode": "0"},
        {"Execution Time (UTC)": "2026-01-01T10:08:00Z", "Technique": "T1686", "Test Number": "1",
         "Test Name": "sample: firewall rule", "Hostname": "LAB-WIN", "GUID": "g3", "ProcessId": "6000", "ExitCode": "0"},
        {"Execution Time (UTC)": "2026-01-01T10:10:00Z", "Technique": "T1218.011", "Test Number": "1",
         "Test Name": "sample: rundll32 harmless dll", "Hostname": "LAB-WIN", "GUID": "g4", "ProcessId": "7000", "ExitCode": "0"},
        {"Execution Time (UTC)": "2026-01-01T10:12:00Z", "Technique": "T1003.001", "Test Number": "1",
         "Test Name": "sample: blocked by Defender", "Hostname": "LAB-WIN", "GUID": "g5", "ProcessId": "8000", "ExitCode": "1"},
        {"Execution Time (UTC)": "2026-01-01T10:14:00Z", "Technique": "T1547.001", "Test Number": "1",
         "Test Name": "sample: nothing logged", "Hostname": "LAB-WIN", "GUID": "g6", "ProcessId": "9000", "ExitCode": "0"},
        {"Execution Time (UTC)": "2026-01-01T10:16:00Z", "Technique": "T1059.001", "Test Number": "1",
         "Test Name": "sample: powershell executor only", "Hostname": "LAB-WIN", "GUID": "g7", "ProcessId": "9500", "ExitCode": "0"},
    ]
    pt1m = "<Triggers><TimeTrigger><Repetition><Interval>PT1M</Interval></Repetition></TimeTrigger></Triggers>" \
           "<Actions><Exec><Command>cmd.exe</Command><Arguments>/c C:\\Users\\Public\\ith-w9\\beat.cmd</Arguments></Exec></Actions>"
    ev = lambda ts, code, **kw: {"@timestamp": ts, "host.name": "lab-win", "event.code": code,
                                 "data_stream.dataset": kw.pop("ds", "system.security"), **kw}
    p = lambda ts, pid, ppid, name, cl, parent="powershell.exe": ev(ts, "4688", **{
        "process.pid": str(pid), "process.parent.pid": str(ppid), "process.name": name,
        "process.parent.name": parent, "process.command_line": cl})
    events = [
        p("2026-01-01T10:00:00.5Z", 4000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        p("2026-01-01T10:00:01Z", 4100, 4000, "schtasks.exe",
          'schtasks.exe /Create /SC MINUTE /MO 1 /TN ITH-W9-Task /TR "cmd.exe /c C:\\Users\\Public\\ith-w9\\beat.cmd" /F'),
        ev("2026-01-01T10:00:02Z", "4698", **{"winlog.event_data.TaskName": "\\ITH-W9-Task",
                                             "winlog.event_data.TaskContent": pt1m}),
        ev("2026-01-01T10:01:00Z", "200", ds="winlog.winlog", **{"winlog.event_data.TaskName": "\\ITH-W9-Task"}),
        ev("2026-01-01T10:01:30Z", "200", ds="winlog.winlog", **{"winlog.event_data.TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"}),
        p("2026-01-01T10:01:40Z", 9100, 600, "wuauclt.exe", "wuauclt.exe /RunHandlerComServer", parent="svchost.exe"),
        ev("2026-01-01T10:00:00.2Z", "4104", ds="windows.powershell_operational",
           **{"process.pid": "3000", "powershell.file.script_block_text": "function Invoke-AtomicTest { ... }"}),
        p("2026-01-01T10:05:00.5Z", 5000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        p("2026-01-01T10:05:01Z", 5100, 5000, "net.exe", "net user ith-w9-user <redacted> /add"),
        ev("2026-01-01T10:05:01.2Z", "4720", **{"winlog.event_data.TargetUserName": "ith-w9-user"}),
        p("2026-01-01T10:05:02Z", 5200, 5000, "net.exe", "net localgroup administrators ith-w9-user /add"),
        ev("2026-01-01T10:05:02.2Z", "4732", **{"winlog.event_data.TargetUserName": "Administrators"}),
        p("2026-01-01T10:08:00.5Z", 6000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        p("2026-01-01T10:08:01Z", 6100, 6000, "netsh.exe",
          "netsh advfirewall firewall add rule name=ITH-W9 dir=in action=allow protocol=TCP localport=3390"),
        ev("2026-01-01T10:08:01.3Z", "4946", **{"winlog.event_data.RuleName": "ITH-W9"}),
        p("2026-01-01T10:10:00.5Z", 7000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        p("2026-01-01T10:10:01Z", 7100, 7000, "rundll32.exe", "rundll32.exe C:\\Users\\Public\\ith-w9\\sample.dll,EntryPoint"),
        p("2026-01-01T10:12:00.5Z", 8000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        ev("2026-01-01T10:12:02Z", "1116", ds="winlog.winlog"),
        p("2026-01-01T10:14:00.5Z", 9000, 3000, "powershell.exe", "powershell.exe -Command <atomic>"),
        p("2026-01-01T10:16:00.5Z", 9500, 3000, "powershell.exe", "powershell.exe -EncodedCommand <base64>"),
    ]
    alerts = [{"@timestamp": "2026-01-01T10:04:30Z", "kibana.alert.original_time": "2026-01-01T10:00:02Z",
               "kibana.alert.rule.name": "Scheduled Task Created or Changed With a User-Writable or Every-Minute "
                                         "Interpreter Action (CAR-2021-12-001, tuned)", "host.name": "lab-win"},
              {"@timestamp": "2026-01-01T11:30:00Z", "kibana.alert.original_time": "2026-01-01T11:29:00Z",
               "kibana.alert.rule.name": "Some other rule", "host.name": "lab-win"}]
    plan = {"tactics": {"T1053.005": ["execution", "persistence", "privilege-escalation"],
                        "T1136.001": ["persistence"], "T1686": ["defense-impairment"], "T1218.011": ["stealth"],
                        "T1003.001": ["credential-access"], "T1547.001": ["persistence", "privilege-escalation"],
                        "T1059.001": ["execution"]},
            "tests": [{"technique": "T1053.005", "predicted": "Technique"}, {"technique": "T1218.011", "predicted": "Telemetry"}]}
    res = analyse(runlog, events, alerts, 3, plan)
    r = list(res["tests"].values())
    checks = [
        ("execution-log columns + US time format parsed (7 tests, first at 10:00 UTC)",
         len(r) == 7 and r[0]["start_utc"].startswith("2026-01-01T10:00:00")),
        ("T1053.005: Technique - W3-SCHTASKS, W5-H2c and both Week 7 CAR branches fire",
         r[0]["category"] == "Technique" and {"W3-SCHTASKS", "W5-H2c", "W7-CAR-PROC", "W7-CAR-TASK"} <= set(r[0]["detections_fired"])
         if load_car() else r[0]["category"] == "Technique"),
        ("process tree: unrelated svchost child and unrelated Defrag task run are NOT attributed",
         r[0]["observations"].get("TaskScheduler 200 action started", {}).get("count") == 1
         and "4688 wuauclt.exe" not in r[0]["observations"]),
        ("framework 4104 (Invoke-AtomicTest itself) is ignored", "4104 script block" not in r[0]["observations"]),
        ("T1136.001: Technique via Week 5 H3", r[1]["category"] == "Technique" and "W5-H3" in r[1]["detections_fired"]),
        ("T1686: Technique via the H3 correlation (admin + firewall rule within 30 min)",
         r[2]["category"] == "Technique" and "W5-H3-confirmed" in r[2]["detections_fired"]),
        ("T1218.011: Telemetry only - Amadey-specific W3-RUNDLL32 stays quiet (nominal coverage)",
         r[3]["category"] == "Telemetry" and not r[3]["detections_fired"]),
        ("T1003.001 blocked: General via Defender, AV + FAILED flags, technique itself not seen",
         r[4]["category"] == "General" and set(r[4]["flags"]) == {"AV", "FAILED"}
         and not r[4]["tested_technique_observed"]),
        ("T1547.001 with only the executor's own process start: None",
         r[5]["category"] == "None" and not r[5]["detections_fired"]),
        ("executor counts only for its own technique: T1059.001 test -> Telemetry; T1053.005 test shows no T1059.001",
         r[6]["category"] == "Telemetry" and r[0]["techniques_observed"] == ["T1053.005"]),
        ("Kibana alert joined to test 1 by original time, 270 s after the test started",
         r[0]["kibana_alerts"].get(alerts[0]["kibana.alert.rule.name"]) == 270.0
         and res["metrics"]["alerts_outside_tests"] == 1),
        ("prediction check: T1053.005 as predicted, T1218.011 as predicted",
         res["techniques"]["T1053.005"]["vs_prediction"] == "as predicted"
         and res["techniques"]["T1218.011"]["vs_prediction"] == "as predicted"),
    ]
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return all(ok for _, ok in checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runlog", type=Path)
    ap.add_argument("--events", type=Path)
    ap.add_argument("--alerts", type=Path)
    ap.add_argument("--window", type=float, default=3.0)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(0 if selftest() else 1)
    if not a.runlog or not a.events:
        ap.error("--runlog and --events are required (or use --selftest)")
    res = analyse(read_csv(a.runlog), read_csv(a.events), read_csv(a.alerts) if a.alerts else [], a.window)
    out = WEEK / "results"
    out.mkdir(exist_ok=True)
    (out / "w9_results.json").write_text(json.dumps(res, indent=1, default=str) + "\n", encoding="utf-8")
    (out / "w9_results.md").write_text(report(res), encoding="utf-8")
    (WEEK / "navigator").mkdir(exist_ok=True)
    (WEEK / "navigator" / "w9_observed_layer.json").write_text(json.dumps(layer(res), indent=2) + "\n", encoding="utf-8")
    for k, r in res["tests"].items():
        print(f"{k:22} {r['category']:10} events={r['events']:<4} detections={','.join(r['detections_fired']) or '-'}"
              + (f"  [{','.join(r['flags'])}]" if r["flags"] else ""))
    m = res["metrics"]
    print(f"visibility {m['visibility_rate']:.0%} | technique-level detection {m['technique_detection_rate']:.0%} | "
          f"predictions as/better/worse {m['as_predicted']}/{m['better_than_predicted']}/{m['worse_than_predicted']}")
    print("Wrote results/w9_results.md, results/w9_results.json, navigator/w9_observed_layer.json")


if __name__ == "__main__":
    main()
