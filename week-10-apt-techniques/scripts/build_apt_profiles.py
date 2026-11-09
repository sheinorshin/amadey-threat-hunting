#!/usr/bin/env python3
"""
build_apt_profiles.py - Week 10: APT29 and APT41 TTPs from ATT&CK v19.2, mapped and compared with Amadey.

Reads the ATT&CK Enterprise v19.2 STIX bundle and my own project data, and writes:
  data/apt_profiles.json        APT29 (G0016) and APT41 (G0096): identity, aliases, campaigns, software, every
                                technique with tactics, platforms, procedure text and where it came from
                                (the group itself or a campaign attributed to it)
  data/apt_techniques.csv       one row per actor x technique, with my lab status - for filtering in Excel
  data/comparison.json          overlap (Jaccard) between APT29, APT41, TA505, Kimsuky, APT1 and Amadey (Week 4),
                                techniques per tactic, shared core, my lab coverage, detection priorities,
                                check of the automatic lab-visibility rule against my manual Week 4 statuses
  data/ttp_tables.md            full technique tables by tactic for APT29 and APT41 (generated, do not edit)
  navigator/*.json              4 Navigator layers: APT29, APT41, APT29 vs APT41, APT29+APT41 vs my lab coverage
  figures/*.png                 tactic profile heatmap, overlap matrix, lab coverage bars

Method (see 04-comparison-and-priorities.md):
  - A group's techniques = what ATT&CK links to the group directly + to the campaigns ATT&CK attributes to it.
    Software capabilities are counted separately and NOT merged (a tool's list covers all of its users).
  - Lab visibility of a technique = the log sources of its ATT&CK v18+ analytics (detection strategy -> analytic ->
    log source) compared with what my Windows lab collects. Rules and hunts from Weeks 3, 5 and 7 are laid on top;
    a rule that only matches Amadey's own artefacts counts as "nominal" coverage, not real coverage.

Usage:  python build_apt_profiles.py [--stix PATH]   (downloads the bundle to ~/.cache/attack if missing)
Needs:  Python 3.9+, matplotlib (figures only; skipped with a warning if missing)
"""
import argparse
import csv
import json
import os
import re
import urllib.request
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"

FOCUS = OrderedDict([("G0016", "APT29"), ("G0096", "APT41")])            # the syllabus groups
COMPARE = OrderedDict([("G0092", "TA505"), ("G0094", "Kimsuky"),          # ATT&CK: "used by" Amadey (S1025)
                       ("G0006", "APT1")])                                # the Week 10 reading (Mandiant 2013)
AMADEY = "S1025"
CURRENT = ["APT29", "APT41", "TA505", "Kimsuky", "Amadey"]                # APT1 is a 2013 reference point only

# ---- what my lab collects (Week 2 data-source map + the Week 5/6 audit changes) --------------------------------
# Windows Server VM -> Elastic Agent (System, Windows, Custom Windows Event Log integrations). No Sysmon yet.
LAB_SECURITY_EVENTS = {
    1102,                                   # audit log cleared (always logged)
    4624, 4625, 4634, 4648, 4672,           # logon / logoff / explicit credentials / special logon (defaults)
    4688,                                   # process creation + command line (enabled, Week 2)
    4698, 4699, 4702,                       # scheduled task created / deleted / updated (Week 6)
    4720, 4722, 4724, 4726, 4732, 4738, 4740,   # account + group management (defaults)
    4946, 4947, 4948,                       # firewall rule added / changed / deleted (Week 5 H3)
}
LAB_CHANNELS = {"WinEventLog:PowerShell", "WinEventLog:TaskScheduler", "WinEventLog:System",
                "WinEventLog:Application", "WinEventLog:Microsoft-Windows-Windows Defender/Operational"}

STATUS = OrderedDict([   # same colours and score scale as the Week 4 detection-coverage layer
    ("RULE",   {"score": 3, "label": "Rule + data now (generic logic)", "color": "#0ca30c"}),
    ("HUNT",   {"score": 2, "label": "Hunt query + data now", "color": "#7cc96b"}),
    ("DATA",   {"score": 2, "label": "Data now, no rule", "color": "#fab219"}),
    ("SYSMON", {"score": 1, "label": "Needs Sysmon", "color": "#ec835a"}),
    ("BLIND",  {"score": 0, "label": "Blind on Windows (network/EDR/other sensor)", "color": "#d03b3b"}),
    ("OUT",    {"score": 0, "label": "Not a Windows technique (cloud, identity, network device, Linux)",
                "color": "#6c7fa8"}),
    ("CTI",    {"score": 0, "label": "Outside network: CTI only (PRE)", "color": "#a3a29c"}),
])

# ---- my detection content from Weeks 3, 5 and 7 ---------------------------------------------------------------
# scope "generic" = the logic would also fire on another actor using the technique in a similar way;
# scope "amadey"  = it keys on Amadey's own artefacts (plugin names, hex install folder) -> nominal coverage only.
MY_DETECTIONS = [
    {"id": "W3-HEXEXE", "kind": "rule", "scope": "amadey", "needs": None, "techniques": ["T1204.002"],
     "file": "week-03-data-processing/sigma/proc_creation_win_amadey_hex_folder_exe.yml",
     "logic": "EXE started from a 10-hex-character folder (Amadey install path)"},
    {"id": "W3-RUNDLL32", "kind": "rule", "scope": "amadey", "needs": None,
     "techniques": ["T1218.011", "T1555.003", "T1115"],
     "file": "week-03-data-processing/sigma/proc_creation_win_amadey_rundll32_plugin.yml",
     "logic": "rundll32 loading cred64.dll / clip64.dll (Amadey plugin names)"},
    {"id": "W3-SCHTASKS", "kind": "rule", "scope": "amadey", "needs": None, "techniques": ["T1053.005"],
     "file": "week-03-data-processing/sigma/proc_creation_win_amadey_schtasks_every_minute.yml",
     "logic": "schtasks.exe /Create every minute from a user folder"},
    {"id": "W3-C2-POST", "kind": "rule", "scope": "amadey", "needs": "proxy logs", "techniques": ["T1071.001"],
     "file": "week-03-data-processing/sigma/proxy_amadey_c2_index_php_post.yml",
     "logic": "POST to /<random>/index.php"},
    {"id": "W3-RDP-REG", "kind": "rule", "scope": "generic", "needs": "Sysmon 13",
     "techniques": ["T1021.001", "T1112"],
     "file": "week-03-data-processing/sigma/registry_set_amadey_rdp_enabled_from_user_path.yml",
     "logic": "fDenyTSConnections=0 set by a process in a user-writable path"},
    {"id": "W3-STARTUP-REG", "kind": "rule", "scope": "generic", "needs": "Sysmon 13",
     "techniques": ["T1547.001", "T1112"],
     "file": "week-03-data-processing/sigma/registry_set_amadey_startup_folder_redirect.yml",
     "logic": "User Shell Folders\\Startup redirected away from the Start Menu"},
    {"id": "W5-H1", "kind": "hunt", "scope": "generic", "needs": None,
     "techniques": ["T1059.001", "T1059.007", "T1218.005", "T1105"],
     "file": "week-05-threat-hunting/queries/h1_script_host_powershell.esql",
     "logic": "script host (wscript/cscript/mshta/wmic/regsvr32) -> PowerShell, 4104 download cradles"},
    {"id": "W5-H2", "kind": "hunt", "scope": "amadey", "needs": None, "techniques": ["T1053.005", "T1204.002"],
     "file": "week-05-threat-hunting/queries/h2_hexfolder_minute_task.esql",
     "logic": "hex-folder EXE + every-minute task on the same host"},
    {"id": "W5-H3", "kind": "hunt", "scope": "generic", "needs": None,
     "techniques": ["T1136.001", "T1021.001", "T1686"],
     "file": "week-05-threat-hunting/queries/h3_new_admin_firewall.esql",
     "logic": "new local admin + new firewall rule on the same host"},
    {"id": "W7-CAR-TASK", "kind": "rule", "scope": "generic", "needs": None, "techniques": ["T1053.005"],
     "file": "week-07-mitre-car/sigma/win_security_task_created_user_writable_car_2021_12_001.yml",
     "logic": "4698/4702 task whose action is in a user-writable path or an every-minute interpreter"},
    {"id": "W7-CAR-PROC", "kind": "rule", "scope": "generic", "needs": None, "techniques": ["T1053.005"],
     "file": "week-07-mitre-car/sigma/proc_creation_win_schtasks_create_suspicious_car_2021_12_001.yml",
     "logic": "schtasks /create|/change with a user-writable or every-minute interpreter action"},
]


# ---------------------------------------------------------------------------------------------------- ATT&CK
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
        self.idx = {ext_id(o): o for o in objs if ext_id(o) and live(o)
                    and o["type"] in ("intrusion-set", "malware", "tool", "campaign", "attack-pattern")}
        matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
        self.tactics = OrderedDict((self.by_ref[r]["x_mitre_shortname"], self.by_ref[r]["name"])
                                   for r in matrix["tactic_refs"])
        self.version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")
        self.uses = {}
        for r in self.rels:
            if r["relationship_type"] == "uses":
                self.uses.setdefault(r["source_ref"], []).append(r)
        self.detects = {}
        for r in self.rels:
            if r["relationship_type"] == "detects":
                self.detects.setdefault(r["target_ref"], []).append(self.by_ref[r["source_ref"]])
        self.replaced = {}
        for r in objs:
            if r["type"] == "relationship" and r["relationship_type"] == "revoked-by":
                src, dst = self.by_ref.get(r["source_ref"]), self.by_ref.get(r["target_ref"])
                if src and dst and ext_id(src) and ext_id(dst):
                    self.replaced[ext_id(src)] = ext_id(dst)

    def get(self, xid):
        if xid not in self.idx:
            raise SystemExit(f"ATT&CK validation failed: {xid} is unknown, revoked or deprecated in v{self.version}")
        return self.idx[xid]

    def techniques_of(self, obj):
        """attack-pattern ext id -> list of procedure texts, for everything `obj` 'uses'."""
        out = {}
        for r in self.uses.get(obj["id"], []):
            t = self.by_ref[r["target_ref"]]
            if t["type"] == "attack-pattern" and live(t):
                out.setdefault(ext_id(t), []).append(clean(r.get("description")))
        return out

    def group(self, gid):
        g = self.get(gid)
        techs = OrderedDict()
        for tid, procs in self.techniques_of(g).items():
            techs.setdefault(tid, {"via": [], "procedures": []})
            techs[tid]["via"].append(gid)
            techs[tid]["procedures"] += [{"via": gid, "text": p} for p in procs]
        campaigns = []
        for r in self.rels:
            if r["relationship_type"] == "attributed-to" and r["target_ref"] == g["id"]:
                c = self.by_ref[r["source_ref"]]
                if not live(c):
                    continue
                ct = self.techniques_of(c)
                campaigns.append({"id": ext_id(c), "name": c["name"],
                                  "first_seen": (c.get("first_seen") or "")[:10],
                                  "last_seen": (c.get("last_seen") or "")[:10],
                                  "description": clean(c.get("description")),
                                  "techniques": len(ct), "new_vs_group": len(set(ct) - set(self.techniques_of(g)))})
                for tid, procs in ct.items():
                    techs.setdefault(tid, {"via": [], "procedures": []})
                    techs[tid]["via"].append(ext_id(c))
                    techs[tid]["procedures"] += [{"via": ext_id(c), "text": p} for p in procs]
        software, sw_caps = [], set()
        for r in self.uses.get(g["id"], []):
            s = self.by_ref[r["target_ref"]]
            if s["type"] in ("malware", "tool") and live(s):
                caps = self.techniques_of(s)
                sw_caps |= set(caps)
                software.append({"id": ext_id(s), "name": s["name"], "type": s["type"], "techniques": len(caps)})
        return {
            "id": gid, "name": g["name"], "aliases": g.get("aliases", []),
            "description": clean(g.get("description")),
            "created": g["created"][:10], "modified": g["modified"][:10],
            "url": f"https://attack.mitre.org/groups/{gid}/",
            "campaigns": sorted(campaigns, key=lambda c: c["first_seen"]),
            "software": sorted(software, key=lambda s: s["id"]),
            "software_capability_techniques": len(sw_caps),
            "software_only_techniques": len(sw_caps - set(techs)),
            "techniques": techs,
        }

    def technique_info(self, tid):
        t = self.get(tid)
        return {"id": tid, "name": t["name"],
                "parent_name": self.get(tid.split(".")[0])["name"] if "." in tid else None,
                "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                "platforms": t.get("x_mitre_platforms", [])}

    def analytics(self, tid):
        """The technique's Windows analytics (ATT&CK v18+ detection model): [(analytic ID, [(log source, channel)])]."""
        t = self.get(tid)
        out = []
        for det in self.detects.get(t["id"], []):
            for ref in det.get("x_mitre_analytic_refs", []):
                an = self.by_ref.get(ref, {})
                if "Windows" not in an.get("x_mitre_platforms", []):
                    continue
                out.append((ext_id(an), [(ls["name"], ls["channel"])
                                         for ls in an.get("x_mitre_log_source_references", [])]))
        return out


# ------------------------------------------------------------------------------------------------ lab status
def event_codes(channel):
    m = re.match(r"\s*EventCode\s*=\s*([\d,\s]+)", channel or "")
    return {int(x) for x in re.findall(r"\d+", m.group(1))} if m else set()


def collected_now(name, channel):
    if name == "WinEventLog:Security":
        return bool(event_codes(channel) & LAB_SECURITY_EVENTS)
    if name == "WinEventLog:Sysmon":            # Sysmon 1 alone -> my 4688 with command line stands in for it
        return event_codes(channel) == {1}
    return name in LAB_CHANNELS


VISIBLE_SHARE = 0.5   # an analytic is usable if at least half of the log sources it names are collected


def lab_visibility(attack, tid):
    """(DATA / SYSMON / BLIND / OUT / CTI, evidence, bounds) for one technique.

    An ATT&CK analytic names the log sources it correlates (often several: process + file + registry ...).
    DATA   = at least one Windows analytic has >= 50 % of its log sources in my lab today
    SYSMON = that bar is reached only once Sysmon is added
    BLIND  = not even with Sysmon (needs a network sensor, EDR, SACLs or another source)
    bounds = the same decision with the two extreme rules, to show how much the estimate depends on the bar:
             lenient = any one log source collected, strict = all log sources of one analytic collected."""
    info = attack.technique_info(tid)
    if "Windows" not in info["platforms"]:
        return ("CTI" if "PRE" in info["platforms"] else "OUT"), [], {"lenient": False, "strict": False}
    best_now, best_sys, evidence = 0.0, 0.0, []
    lenient = strict = False
    for aid, srcs in attack.analytics(tid):
        if not srcs:
            continue
        now = sum(collected_now(n, c) for n, c in srcs)
        sysm = sum(collected_now(n, c) or n == "WinEventLog:Sysmon" for n, c in srcs)
        lenient |= now > 0
        strict |= now == len(srcs)
        evidence.append(f"{aid}: {now}/{len(srcs)} log sources now, {sysm}/{len(srcs)} with Sysmon")
        best_now, best_sys = max(best_now, now / len(srcs)), max(best_sys, sysm / len(srcs))
    status = "DATA" if best_now >= VISIBLE_SHARE else "SYSMON" if best_sys >= VISIBLE_SHARE else "BLIND"
    return status, evidence, {"lenient": lenient, "strict": strict}


def my_coverage(tid):
    """(effective status from my content or None, [detections mapped to this ID], nominal-only?)."""
    mapped = [d for d in MY_DETECTIONS if tid in d["techniques"]]
    working = [d for d in mapped if d["needs"] is None]
    generic_rules = [d for d in working if d["kind"] == "rule" and d["scope"] == "generic"]
    generic_hunts = [d for d in working if d["kind"] == "hunt" and d["scope"] == "generic"]
    eff = "RULE" if generic_rules else "HUNT" if generic_hunts else None
    return eff, [d["id"] for d in mapped], bool(mapped) and eff is None


def status_of(attack, tid):
    vis, evidence, bounds = lab_visibility(attack, tid)
    eff, mapped, nominal_only = my_coverage(tid)
    if eff and vis in ("DATA", "SYSMON", "BLIND"):     # a working rule/hunt implies its data is collected
        return eff, vis, evidence, bounds, mapped, nominal_only
    return vis, vis, evidence, bounds, mapped, nominal_only


# ------------------------------------------------------------------------------------------------------ CAR
def car_index(attack):
    path = ROOT / "week-07-mitre-car" / "data" / "car_analytics.json"
    if not path.exists():
        return {}, {}
    sub_idx, parent_idx = {}, {}
    for c in json.loads(path.read_text(encoding="utf-8"))["analytics"]:
        for cov in c["coverage"]:
            for s in cov["subtechniques"]:
                sub_idx.setdefault(attack.replaced.get(s, s), set()).add(c["id"])
            if cov["technique"]:
                parent_idx.setdefault(attack.replaced.get(cov["technique"], cov["technique"]), set()).add(c["id"])
    return sub_idx, parent_idx


def car_for(tid, sub_idx, parent_idx):
    exact = sorted(sub_idx.get(tid, set()) if "." in tid else parent_idx.get(tid, set()))
    parent = sorted(parent_idx.get(tid.split(".")[0], set()) - set(exact)) if "." in tid else []
    return exact, parent


# ---------------------------------------------------------------------------------------------------- layers
def base_layer(name, description, platforms, legend, gradient):
    return {
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "filters": {"platforms": platforms}, "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False, "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 10)"},
                     {"name": "source", "value": "MITRE ATT&CK Enterprise v19.2 (groups + attributed campaigns)"}],
        "name": name, "description": description, "gradient": gradient, "legendItems": legend,
        "showTacticRowBackground": False, "tacticRowBackground": "#dddddd", "techniques": [],
    }


def add(layer, info, score, color, comment, extra=None):
    for tac in info["tactics"]:
        layer["techniques"].append({"techniqueID": info["id"], "tactic": tac, "score": score, "color": color,
                                    "comment": comment, "enabled": True, "showSubtechniques": False,
                                    "metadata": extra or []})


def short(text, n=260):
    return text if len(text) <= n else text[:n - 1].rsplit(" ", 1)[0] + " …"


# ---------------------------------------------------------------------------------------------------- figures
def figures(cmp_, actors, tactics):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - figures skipped (pip install matplotlib)")
        return []
    INK, INK2, MUTED, SURF = "#0b0b0b", "#52514e", "#8a8984", "#fcfcfb"
    plt.rcParams.update({"font.family": "DejaVu Sans"})
    out = WEEK / "figures"
    out.mkdir(exist_ok=True)
    names = list(actors)

    # 1. techniques per tactic, as a share of each actor's profile
    fig, ax = plt.subplots(figsize=(11.5, 7.4), dpi=120)
    fig.patch.set_facecolor(SURF); ax.set_facecolor(SURF)
    tac_keys = list(tactics)
    counts = [[cmp_["tactic_counts"][a].get(t, 0) for a in names] for t in tac_keys]
    shares = [[c / max(1, cmp_["sizes"][a]) for c, a in zip(row, names)] for row in counts]
    ax.imshow(shares, cmap="Blues", aspect="auto", vmin=0, vmax=0.45)
    for i, row in enumerate(counts):
        for j, c in enumerate(row):
            ax.text(j, i, str(c) if c else "·", ha="center", va="center", fontsize=10,
                    color="#ffffff" if shares[i][j] > 0.28 else INK)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels([f"{a}\n({cmp_['sizes'][a]} techn.)" for a in names], fontsize=9.5)
    ax.set_yticks(range(len(tac_keys)))
    ax.set_yticklabels([tactics[t] for t in tac_keys], fontsize=9.5)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Techniques per ATT&CK tactic (number; colour = share of the actor's profile)",
                 fontsize=12.5, weight="bold", color=INK, loc="left", pad=12)
    fig.text(0.01, 0.01, "ATT&CK v19.2: group + attributed campaigns. Amadey = my Week 4 analysis (40 techniques). "
             "A technique counts once per tactic it serves.", fontsize=8.5, color=INK2)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(out / "tactic_profile.png", facecolor=SURF)
    plt.close(fig)

    # 2. overlap matrix: sub-technique level (lower-left) and parent level (upper-right)
    fig, ax = plt.subplots(figsize=(8.6, 7.2), dpi=120)
    fig.patch.set_facecolor(SURF); ax.set_facecolor(SURF)
    n = len(names)
    grid = [[0.0] * n for _ in range(n)]
    for i, a in enumerate(names):
        for j, b in enumerate(names):
            if i == j:
                grid[i][j] = float("nan")
            elif i > j:
                grid[i][j] = cmp_["jaccard"]["subtechnique"][a][b]
            else:
                grid[i][j] = cmp_["jaccard"]["parent"][a][b]
    ax.imshow(grid, cmap="Oranges", vmin=0, vmax=0.5)
    for i in range(n):
        for j in range(n):
            if i == j:
                ax.text(j, i, names[i], ha="center", va="center", fontsize=9, weight="bold", color=MUTED)
            else:
                v = grid[i][j]
                ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=10,
                        color="#ffffff" if v > 0.3 else INK)
    ax.set_xticks(range(n)); ax.set_xticklabels(names, fontsize=9.5)
    ax.set_yticks(range(n)); ax.set_yticklabels(names, fontsize=9.5)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Technique overlap (Jaccard index)", fontsize=12.5, weight="bold", color=INK, loc="left", pad=10)
    fig.text(0.01, 0.015, "Below the diagonal: exact sub-techniques.  Above: rolled up to parent techniques.",
             fontsize=8.8, color=INK2)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out / "overlap_matrix.png", facecolor=SURF)
    plt.close(fig)

    # 3. lab coverage: share of each actor's techniques by my lab status
    fig, ax = plt.subplots(figsize=(11.5, 4.8), dpi=120)
    fig.patch.set_facecolor(SURF); ax.set_facecolor(SURF)
    for i, a in enumerate(names):
        left = 0
        total = cmp_["sizes"][a]
        for st, meta in STATUS.items():
            c = cmp_["lab_coverage"][a].get(st, 0)
            if not c:
                continue
            w = c / total
            ax.barh(i, w, left=left, color=meta["color"], edgecolor=SURF, height=0.66)
            if w > 0.045:
                ax.text(left + w / 2, i, str(c), ha="center", va="center", fontsize=9,
                        color="#ffffff" if st in ("RULE", "BLIND", "OUT") else INK)
            left += w
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels([f"{a} ({cmp_['sizes'][a]})" for a in names], fontsize=10)
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.tick_params(length=0, labelsize=9)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("What my Windows SIEM lab can see of each actor's techniques (estimate from ATT&CK analytics)",
                 fontsize=12, weight="bold", color=INK, loc="left", pad=10)
    handles = [plt.Rectangle((0, 0), 1, 1, color=m["color"]) for m in STATUS.values()]
    ax.legend(handles, [m["label"] for m in STATUS.values()], ncol=3, fontsize=8, frameon=False,
              loc="upper center", bbox_to_anchor=(0.5, -0.1))
    fig.tight_layout()
    fig.savefig(out / "lab_coverage.png", facecolor=SURF)
    plt.close(fig)
    return ["figures/tactic_profile.png", "figures/overlap_matrix.png", "figures/lab_coverage.png"]


# ------------------------------------------------------------------------------------------------------- main
def jaccard(a, b):
    return round(len(a & b) / len(a | b), 3) if a | b else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stix", default=os.path.expanduser("~/.cache/attack/enterprise-attack-19.2.json"))
    a = ap.parse_args()
    attack = Attack(load_bundle(Path(a.stix)))
    sub_idx, parent_idx = car_index(attack)

    # --- actors -------------------------------------------------------------------------------------------
    groups = OrderedDict((name, attack.group(gid)) for gid, name in list(FOCUS.items()) + list(COMPARE.items()))
    kc = json.loads((ROOT / "week-04-kill-chain" / "data" / "amadey_kill_chain.json").read_text(encoding="utf-8"))
    amadey_w4 = OrderedDict()
    for ph in kc["phases"]:
        for t in ph["techniques"]:
            amadey_w4.setdefault(t["id"], {"status": t["status"], "how": t["how"], "phase": ph["phase"]})
    amadey_attack = set(attack.techniques_of(attack.get(AMADEY)))
    for tid in amadey_w4:                                            # Week 4 IDs must still be valid in v19.2
        attack.get(tid)

    actors = OrderedDict()
    for name in ["APT29", "APT41", "TA505", "Kimsuky", "Amadey", "APT1"]:
        actors[name] = set(amadey_w4) if name == "Amadey" else set(groups[name]["techniques"])

    # --- technique facts + lab status for everything any actor uses ----------------------------------------
    facts = {}
    for tid in sorted(set().union(*actors.values())):
        info = attack.technique_info(tid)
        st, vis, evidence, bounds, mapped, nominal_only = status_of(attack, tid)
        exact, parent = car_for(tid, sub_idx, parent_idx)
        facts[tid] = {**info, "status": st, "visibility": vis, "evidence": evidence, "bounds": bounds,
                      "my_detections": mapped,
                      "nominal_only": nominal_only, "car_exact": exact, "car_parent_only": parent,
                      "used_by": [n for n in actors if tid in actors[n]]}

    # --- comparison ---------------------------------------------------------------------------------------
    names = list(actors)
    parents = {n: {t.split(".")[0] for t in s} for n, s in actors.items()}
    cmp_ = {
        "attack_version": attack.version,
        "sizes": {n: len(s) for n, s in actors.items()},
        "jaccard": {
            "subtechnique": {x: {y: jaccard(actors[x], actors[y]) for y in names} for x in names},
            "parent": {x: {y: jaccard(parents[x], parents[y]) for y in names} for x in names},
        },
        "tactic_counts": {n: {tac: sum(tac in facts[t]["tactics"] for t in s) for tac in attack.tactics}
                          for n, s in actors.items()},
        "lab_coverage": {n: {st: sum(facts[t]["status"] == st for t in s) for st in STATUS}
                         for n, s in actors.items()},
        "visibility_bounds": {n: {"windows_techniques": sum(facts[t]["visibility"] not in ("OUT", "CTI") for t in s),
                                  "lenient_any_source": sum(facts[t]["bounds"]["lenient"] for t in s),
                                  "chosen_half_of_sources": sum(facts[t]["visibility"] == "DATA" for t in s),
                                  "strict_all_sources": sum(facts[t]["bounds"]["strict"] for t in s)}
                              for n, s in actors.items()},
        "nominal_only": {n: sorted(t for t in s if facts[t]["nominal_only"]) for n, s in actors.items()},
        "car_coverage": {n: {"exact": sum(bool(facts[t]["car_exact"]) for t in s),
                             "parent_only": sum(bool(facts[t]["car_parent_only"]) and not facts[t]["car_exact"]
                                                for t in s)} for n, s in actors.items()},
    }
    a29, a41 = actors["APT29"], actors["APT41"]
    cmp_["apt29_and_apt41"] = sorted(a29 & a41)
    cmp_["apt29_only"], cmp_["apt41_only"] = len(a29 - a41), len(a41 - a29)
    cmp_["both_apts_and_amadey"] = sorted(a29 & a41 & actors["Amadey"])
    cmp_["amadey_with_apt29"] = sorted(a29 & actors["Amadey"])
    cmp_["amadey_with_apt41"] = sorted(a41 & actors["Amadey"])
    cmp_["amadey_attack_s1025"] = {"techniques": len(amadey_attack),
                                   "in_week4": len(amadey_attack & set(amadey_w4)),
                                   "week4_only": len(set(amadey_w4) - amadey_attack)}
    cmp_["apt1_still_used_by_both_apts"] = sorted(actors["APT1"] & a29 & a41)

    # core tradecraft: used by >= 3 of the 5 current actors
    core = []
    for tid, f in facts.items():
        k = sum(tid in actors[n] for n in CURRENT)
        if k >= 3:
            core.append({"id": tid, "name": f["name"], "actors": k,
                         "who": [n for n in CURRENT if tid in actors[n]], "status": f["status"],
                         "my_detections": f["my_detections"], "car": f["car_exact"]})
    status_rank = {s: i for i, s in enumerate(STATUS)}
    cmp_["core_tradecraft"] = sorted(core, key=lambda c: (-c["actors"], status_rank[c["status"]], c["id"]))

    # priorities for my lab: APT29 + APT41 techniques ranked by prevalence, then by how cheap the next step is
    action = {"RULE": "validate the rule with an atomic test (Week 9)",
              "HUNT": "turn the hunt into a scheduled rule, then validate",
              "DATA": "quick win: data is already collected - write a rule",
              "SYSMON": "install Sysmon (Week 4 priority #2), then write a rule",
              "BLIND": "needs a new sensor (network/EDR) - document as an accepted gap",
              "OUT": "outside the Windows lab - cloud/identity/network-device logs",
              "CTI": "CTI only - watch reporting, nothing to log inside the network"}
    prio = []
    for tid in a29 | a41:
        f = facts[tid]
        k = sum(tid in actors[n] for n in CURRENT)
        prio.append({"id": tid, "name": f["name"], "actors": k,
                     "who": [n for n in CURRENT if tid in actors[n]], "status": f["status"],
                     "next_step": action[f["status"]], "nominal_only": f["nominal_only"]})
    order = {"DATA": 0, "HUNT": 1, "RULE": 2, "SYSMON": 3, "BLIND": 4, "OUT": 5, "CTI": 6}
    cmp_["priorities"] = sorted(prio, key=lambda p: (-p["actors"], order[p["status"]], p["id"]))

    # sanity check: automatic visibility rule vs my manual Week 4 statuses for Amadey (in-network techniques)
    agree, rows = 0, []
    manual_map = {"RULE": "DATA", "DATA": "DATA", "SYSMON": "SYSMON", "BLIND": "BLIND", "CTI": "CTI"}
    for tid, w4 in amadey_w4.items():
        auto = facts[tid]["visibility"]
        manual = manual_map[w4["status"]]
        same = auto == manual or (manual == "CTI" and auto in ("CTI", "OUT"))
        agree += same
        if not same:
            rows.append({"id": tid, "name": facts[tid]["name"], "week4": w4["status"], "auto": auto,
                         "auto_evidence": facts[tid]["evidence"][:3]})
    cmp_["visibility_check_vs_week4"] = {"agree": agree, "total": len(amadey_w4), "disagreements": rows}

    # --- write data ---------------------------------------------------------------------------------------
    for d in ("data", "navigator"):
        (WEEK / d).mkdir(exist_ok=True)
    profiles = OrderedDict()
    for name, g in groups.items():
        techs = []
        for tid, v in g["techniques"].items():
            f = facts[tid]
            techs.append({**{k: f[k] for k in ("id", "name", "tactics", "platforms", "status", "visibility",
                                                "my_detections", "nominal_only", "car_exact", "car_parent_only")},
                          "via": v["via"], "also_used_by": [n for n in f["used_by"] if n != name],
                          "procedures": v["procedures"] if name in FOCUS.values() else len(v["procedures"])})
        entry = {k: g[k] for k in ("id", "name", "aliases", "description", "created", "modified", "url",
                                   "campaigns", "software_capability_techniques", "software_only_techniques")}
        entry["software"] = g["software"] if name in FOCUS.values() else len(g["software"])
        entry["technique_count"] = {"total": len(techs),
                                    "direct": sum(g["id"] in t["via"] for t in techs),
                                    "campaign_only": sum(g["id"] not in t["via"] for t in techs)}
        entry["techniques"] = sorted(techs, key=lambda t: t["id"])
        profiles[name] = entry
    (WEEK / "data" / "apt_profiles.json").write_text(json.dumps(
        {"attack_version": attack.version, "source": STIX_URL, "groups": profiles}, indent=1, ensure_ascii=False)
        + "\n", encoding="utf-8")
    (WEEK / "data" / "comparison.json").write_text(json.dumps(
        {**cmp_, "status_legend": {k: v["label"] for k, v in STATUS.items()},
         "lab_security_events": sorted(LAB_SECURITY_EVENTS), "lab_channels": sorted(LAB_CHANNELS),
         "my_detections": MY_DETECTIONS}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    with open(WEEK / "data" / "apt_techniques.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["actor", "technique_id", "technique", "tactics", "via", "lab_status", "lab_visibility",
                    "my_detections", "nominal_only", "car_exact", "used_by", "procedure_example"])
        for name in names:
            for tid in sorted(actors[name]):
                f = facts[tid]
                if name == "Amadey":
                    via, proc = f"Week 4 KC{amadey_w4[tid]['phase']}", amadey_w4[tid]["how"]
                else:
                    g = groups[name]["techniques"][tid]
                    via, proc = ";".join(g["via"]), short(next((p["text"] for p in g["procedures"] if p["text"]), ""), 300)
                w.writerow([name, tid, f["name"], ";".join(f["tactics"]), via, f["status"], f["visibility"],
                            ";".join(f["my_detections"]), f["nominal_only"], ";".join(f["car_exact"]),
                            ";".join(f["used_by"]), proc])

    # --- generated technique tables -----------------------------------------------------------------------
    md = ["# APT29 and APT41 — full technique tables (ATT&CK v19.2)", "",
          "Generated by `scripts/build_apt_profiles.py` — do not edit by hand. *Via* = where ATT&CK records the "
          "procedure: the group itself (G…) or a campaign attributed to it (C…). *Lab* = what my Windows SIEM lab can "
          "do with the technique today (legend at the end). *Also* = other actors in this comparison that use it.", ""]
    for name in FOCUS.values():
        g = groups[name]
        md += [f"## {name} ({g['id']}) — {len(g['techniques'])} techniques", ""]
        for tac, tac_name in attack.tactics.items():
            rows = [t for t in sorted(g["techniques"]) if tac in facts[t]["tactics"]]
            if not rows:
                continue
            md += [f"### {tac_name} ({len(rows)})", "", "| ID | Technique | Via | Lab | Also | Procedure (ATT&CK) |",
                   "|---|---|---|---|---|---|"]
            for tid in rows:
                f = facts[tid]
                nm = f"{f['parent_name']}: {f['name']}" if f["parent_name"] else f["name"]
                proc = next((p["text"] for p in g["techniques"][tid]["procedures"] if p["text"]), "")
                also = ", ".join(n for n in f["used_by"] if n != name) or "—"
                md.append(f"| {tid} | {nm} | {', '.join(g['techniques'][tid]['via'])} | {f['status']} | {also} | "
                          f"{short(proc, 220).replace('|', '/')} |")
            md.append("")
    md += ["## Legend", "", "| Lab | Meaning |", "|---|---|"]
    md += [f"| {k} | {v['label']} |" for k, v in STATUS.items()]
    (WEEK / "data" / "ttp_tables.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # --- Navigator layers ---------------------------------------------------------------------------------
    plats = sorted({p for t in a29 | a41 for p in facts[t]["platforms"]})
    group_colors = {"APT29": "#2a78d6", "APT41": "#eb6834"}
    for name in FOCUS.values():
        g = groups[name]
        lay = base_layer(f"{name} ({g['id']}) - techniques in ATT&CK v19.2",
                         f"{name}: {len(g['techniques'])} techniques (group + attributed campaigns). "
                         "Comment = first ATT&CK procedure example + where it is recorded.",
                         plats, [{"label": name, "color": group_colors[name]}],
                         {"colors": ["#ffffff", group_colors[name]], "minValue": 0, "maxValue": 1})
        for tid, v in g["techniques"].items():
            proc = next((p for p in v["procedures"] if p["text"]), {"via": "", "text": ""})
            add(lay, facts[tid], 1, group_colors[name], f"[{proc['via']}] {short(proc['text'], 300)}",
                [{"name": "via", "value": ", ".join(v["via"])}, {"name": "my lab", "value": facts[tid]["status"]}])
        (WEEK / "navigator" / f"{name.lower()}_layer.json").write_text(json.dumps(lay, indent=2) + "\n",
                                                                      encoding="utf-8")
    cmp_layer = base_layer("APT29 vs APT41 (ATT&CK v19.2)",
                           "1 = APT29 only, 2 = APT41 only, 3 = both. Comment says if Amadey (Week 4) uses it too.",
                           plats, [{"label": "APT29 only", "color": "#2a78d6"}, {"label": "APT41 only", "color": "#eb6834"},
                                   {"label": "Both", "color": "#4a3aa7"}],
                           {"colors": ["#2a78d6", "#eb6834", "#4a3aa7"], "minValue": 1, "maxValue": 3})
    for tid in sorted(a29 | a41):
        sc = 3 if tid in a29 and tid in a41 else 1 if tid in a29 else 2
        col = {1: "#2a78d6", 2: "#eb6834", 3: "#4a3aa7"}[sc]
        others = [n for n in ("TA505", "Kimsuky", "Amadey") if tid in actors[n]]
        add(cmp_layer, facts[tid], sc, col, "Also used by: " + (", ".join(others) if others else "none of TA505/Kimsuky/Amadey"))
    (WEEK / "navigator" / "apt29_vs_apt41_layer.json").write_text(json.dumps(cmp_layer, indent=2) + "\n",
                                                                 encoding="utf-8")
    cov_layer = base_layer("APT29 + APT41 vs my SIEM lab",
                           "3 = generic rule + data now, 2 = hunt or data now, 1 = needs Sysmon, 0 = blind / not "
                           "Windows / CTI only. Same scale as the Week 4 Amadey coverage layer.",
                           plats, [{"label": v["label"], "color": v["color"]} for v in STATUS.values()],
                           {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3})
    for tid in sorted(a29 | a41):
        f = facts[tid]
        st = STATUS[f["status"]]
        who = ", ".join(n for n in ("APT29", "APT41") if tid in actors[n])
        note = f" | mapped detections: {', '.join(f['my_detections'])}" if f["my_detections"] else ""
        if f["nominal_only"]:
            note += " (Amadey-specific or not deployable: nominal coverage only)"
        add(cov_layer, f, st["score"], st["color"], f"{st['label']} | {who}{note}")
    (WEEK / "navigator" / "apt_lab_coverage_layer.json").write_text(json.dumps(cov_layer, indent=2) + "\n",
                                                                    encoding="utf-8")

    figs = figures(cmp_, actors, attack.tactics)

    # --- summary ------------------------------------------------------------------------------------------
    print(f"ATT&CK v{attack.version}")
    for name, g in groups.items():
        tc = profiles[name]["technique_count"]
        print(f"  {name:8} {g['id']}: {tc['total']:3} techniques ({tc['direct']} direct + {tc['campaign_only']} "
              f"campaign-only) | campaigns {len(g['campaigns'])} | software {len(g['software'])} "
              f"(+{g['software_only_techniques']} software-only techniques, not merged)")
    print(f"  Amadey  Week 4: {len(amadey_w4)} techniques (ATT&CK S1025 lists {len(amadey_attack)})")
    print(f"APT29 & APT41 shared: {len(cmp_['apt29_and_apt41'])} | + Amadey: {len(cmp_['both_apts_and_amadey'])} "
          f"| Jaccard APT29-APT41 {cmp_['jaccard']['subtechnique']['APT29']['APT41']} "
          f"(parent level {cmp_['jaccard']['parent']['APT29']['APT41']})")
    for n in names:
        cov = cmp_["lab_coverage"][n]
        print(f"  lab {n:8} " + " ".join(f"{k}={v}" for k, v in cov.items() if v))
    vc = cmp_["visibility_check_vs_week4"]
    print(f"visibility rule vs Week 4 manual statuses: {vc['agree']}/{vc['total']} agree")
    print(f"core tradecraft (>=3 of {len(CURRENT)} current actors): {len(cmp_['core_tradecraft'])}")
    print("Wrote data/apt_profiles.json, data/comparison.json, data/apt_techniques.csv, data/ttp_tables.md, "
          "4 Navigator layers" + (f", {len(figs)} figures" if figs else ""))


if __name__ == "__main__":
    main()
