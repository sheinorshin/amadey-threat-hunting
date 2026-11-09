#!/usr/bin/env python3
"""
build_kill_chain.py - Week 4 (Assignment 2): Amadey intrusion -> Lockheed Martin Cyber Kill Chain -> MITRE ATT&CK v19.

One source of truth (KILL_CHAIN below) -> everything else is generated:
  data/amadey_kill_chain.json                  machine-readable mapping (names/tactics resolved from ATT&CK v19.2)
  navigator/amadey_kill_chain_layer.json        ATT&CK Navigator layer, colour = kill-chain phase
  navigator/amadey_detection_coverage_layer.json ATT&CK Navigator layer, score = detection coverage in my lab
  figures/amadey_kill_chain.png                 7-phase diagram with techniques coloured by coverage
  figures/attack_matrix_coverage.png            ATT&CK v19 matrix view of the same techniques

Validation: every technique ID is checked against the official ATT&CK STIX bundle (enterprise-attack-19.2.json):
it must exist, must not be revoked or deprecated, and its tactics are taken from the bundle, not typed by hand.
IOC counts per phase come from week-03-data-processing/output/iocs_normalized.csv (Week 3 pipeline).

Usage:  python build_kill_chain.py [--stix PATH]     (downloads the STIX bundle to ~/.cache/attack if missing)
Needs:  matplotlib (figures only)
"""
import argparse
import csv
import json
import os
import sys
import urllib.request
from collections import Counter, OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
ROOT = WEEK.parent
IOC_CSV = ROOT / "week-03-data-processing" / "output" / "iocs_normalized.csv"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
ATTACK_VERSION = "19"

# ---------------------------------------------------------------- sources (key -> citation)
SOURCES = {
    "talos2025":   "Cisco Talos, 'MaaS operation using Emmenhtal and Amadey linked to threats against Ukrainian entities', 17 Jul 2025 (A2)",
    "trellix2025": "Trellix ARC, 'Amadey Exploiting Self-Hosted GitLab to Distribute StealC', 18 Dec 2025 (A2)",
    "ms2026":      "Microsoft Threat Intelligence, 'StealC and Amadey: Breaking down infostealers ...', 24 Jun 2026 (A2)",
    "binan":       "binaryanalys.is, 'Unmasking Amadey 5' (v5 commands, RC4 protocol) (B2)",
    "asec2022":    "AhnLab ASEC, Amadey distributing LockBit 3.0, Nov 2022 (A2)",
    "s1025":       "MITRE ATT&CK S1025 Amadey v1.1 (A1)",
    "vt":          "My VirusTotal relations + sandbox review of d7a366fa, Week 2",
    "maltego":     "My Maltego pivots (NS, reverse DNS, ASN), Week 2",
    "misp":        "My MISP events #1-#3, Week 3",
}

# coverage status in MY lab (Windows Server VM + Elastic Agent: 4688 w/ command line, 4104, 4698, 4720/4732, 4946, Defender)
STATUS = OrderedDict([
    ("RULE",   {"score": 3, "label": "Rule + data now",      "color": "#0ca30c"}),
    ("DATA",   {"score": 2, "label": "Data now, no rule",    "color": "#fab219"}),
    ("SYSMON", {"score": 1, "label": "Needs Sysmon",         "color": "#ec835a"}),
    ("BLIND",  {"score": 0, "label": "Blind (proxy/mail/EDR)", "color": "#d03b3b"}),
    ("CTI",    {"score": 0, "label": "Outside network: CTI only", "color": "#a3a29c"}),
])

# ---------------------------------------------------------------- the analysis
KILL_CHAIN = [
    {
        "phase": 1, "name": "Reconnaissance",
        "lm_definition": "Research, identification and selection of targets.",
        "summary": "Opportunistic MaaS targeting; Talos linked the operation to a phishing campaign against Ukrainian entities.",
        "fig_actions": ["Linked campaign targeted Ukrainian entities (Talos)", "No victim-specific research documented"],
        "actions": [
            "Affiliate picks a target set and lure theme (the linked Talos phishing campaign targeted Ukrainian entities)",
            "No victim-specific research documented - commodity loader, volume over precision",
        ],
        "sources": ["talos2025"],
        "techniques": [
            {"id": "T1591", "how": "Target choice; the linked phishing campaign hit Ukrainian entities (inferred, low confidence)", "status": "CTI", "confidence": "low"},
        ],
    },
    {
        "phase": 2, "name": "Weaponization",
        "lm_definition": "Coupling a remote access trojan with an exploit into a deliverable payload.",
        "summary": "Amadey bought as a service, configured, packed; payloads staged on GitHub and a hijacked GitLab.",
        "fig_actions": ["MaaS build bought; bot ID 0702f, encrypted strings", "Payloads staged on GitHub + hijacked GitLab", "C2 domains, e.g. microsoft-telemetry.at"],
        "actions": [
            "Operator develops/sells the Amadey builder + panel (MaaS); affiliate obtains a build",
            "Build config: bot ID 0702f, string-decryption key, encrypted strings; Emmenhtal JS is multi-layer obfuscated",
            "Payloads uploaded to GitHub repos (Legendary99999) and to a compromised self-hosted GitLab",
            "C2 domains registered, incl. brand-impersonating microsoft-telemetry.at",
        ],
        "sources": ["talos2025", "trellix2025", "ms2026", "maltego"],
        "techniques": [
            {"id": "T1587.001", "how": "Amadey developed and sold as MaaS since 2018 (operator side)", "status": "CTI", "confidence": "high"},
            {"id": "T1588.001", "how": "Affiliates buy Amadey builds (customer side)", "status": "CTI", "confidence": "high"},
            {"id": "T1027", "how": "Encrypted strings in the build, obfuscated Emmenhtal JavaScript", "status": "BLIND", "confidence": "high"},
            {"id": "T1608.001", "how": "Payloads staged in GitHub repos and in gitlab.bzctoons.net/suau/fds", "status": "CTI", "confidence": "high"},
            {"id": "T1584.004", "how": "Self-hosted GitLab servers hijacked (bzctoons.net; gitd3ti.vokasi.uns.ac.id from my VT pivot)", "status": "CTI", "confidence": "high"},
            {"id": "T1583.001", "how": "C2 domains such as microsoft-telemetry.at, goodpanelforgoodjob.com", "status": "CTI", "confidence": "medium"},
        ],
    },
    {
        "phase": 3, "name": "Delivery",
        "lm_definition": "Transmission of the weapon to the targeted environment.",
        "summary": "Likely a phishing archive with JavaScript -> Emmenhtal stage fetched as fake .mp4 -> Amadey EXE downloaded.",
        "fig_actions": ["Phishing mail, archive with JavaScript (likely, Talos)", "Emmenhtal stage fetched as fake fb.mp4", "Amadey EXE from 185.215.113.16/test/amnew.exe"],
        "actions": [
            "Phishing e-mail with an archive containing a JavaScript file (seen in the linked SmokeLoader campaign; Talos assesses the Amadey Emmenhtal scripts were likely meant for the same delivery)",
            "Next stage pulled from pivqmane[.]com/doc/fb.mp4 (Emmenhtal disguised as video)",
            "Amadey binary downloaded from 185.215.113.16/test/amnew.exe",
        ],
        "sources": ["talos2025", "misp"],
        "techniques": [
            {"id": "T1566.001", "how": "Archive attachment with JavaScript in phishing mail (Talos: seen with SmokeLoader, likely for Amadey)", "status": "BLIND", "confidence": "medium"},
            {"id": "T1105", "how": "Emmenhtal stage and Amadey EXE downloaded over HTTP", "status": "SYSMON", "confidence": "high"},
        ],
    },
    {
        "phase": 4, "name": "Exploitation",
        "lm_definition": "Triggering the intruder's code - a vulnerability, or the user/OS auto-executing it.",
        "summary": "No software exploit: the user runs the script; Windows script hosts and LOLBins do the rest.",
        "fig_actions": ["User opens the JS (human = the exploit)", "JS -> WScript.Shell -> PowerShell -> Amadey", "fake .mp4 variants: mshta (low confidence)"],
        "actions": [
            "Victim opens the JavaScript from the archive (user execution - the 'exploited' component is the human)",
            "JS -> WScript.Shell runs encoded PowerShell -> AES-decrypted PowerShell downloads and starts Amadey",
            "Emmenhtal variants disguised as .mp4 (pivqmane[.]com) are typically run by mshta.exe - not shown in Talos' JS samples",
        ],
        "sources": ["talos2025"],
        "techniques": [
            {"id": "T1204.002", "how": "User double-clicks the JS file from the archive", "status": "DATA", "confidence": "high"},
            {"id": "T1059.007", "how": "JavaScript executed by Windows Script Host (WScript.Shell launches PowerShell)", "status": "DATA", "confidence": "high"},
            {"id": "T1218.005", "how": "mshta.exe runs Emmenhtal disguised as .mp4 (Orange Cyberdefense pattern; not in Talos' JS samples)", "status": "DATA", "confidence": "low"},
            {"id": "T1059.001", "how": "Emmenhtal PowerShell layer downloads/starts the loader", "status": "DATA", "confidence": "high"},
        ],
    },
    {
        "phase": 5, "name": "Installation",
        "lm_definition": "Installing a backdoor / persistence on the victim system.",
        "summary": "Amadey copies itself to a hex-named folder and survives reboots with a 1-minute scheduled task.",
        "fig_actions": ["Copies to %TEMP%\\067640a009\\ + mutex", "Task Yfgfwb runs every 1 minute", "Startup folder redirect, MotW zeroed"],
        "actions": [
            "Copies itself to %TEMP%\\067640a009\\Yfgfwb.exe and starts it (CreateProcess)",
            "Mutex f936986d553273aef6eeaeef713ad28f prevents double infection",
            "Scheduled task Yfgfwb (C:\\Windows\\Tasks\\Yfgfwb.job) runs it every minute",
            "Startup folder redirected in the registry; Zone.Identifier (MotW) zeroed; strings decrypted at runtime",
        ],
        "sources": ["trellix2025", "vt", "s1025", "talos2025"],
        "techniques": [
            {"id": "T1106", "how": "CreateProcessA starts the copied loader", "status": "BLIND", "confidence": "high"},
            {"id": "T1053.005", "how": "Task named after the EXE, trigger every 1 minute (confirmed in VT sandbox)", "status": "RULE", "confidence": "high"},
            {"id": "T1547.001", "how": "User Shell Folders\\Startup redirected to the install folder", "status": "SYSMON", "confidence": "high"},
            {"id": "T1112", "how": "Registry values overwritten for persistence", "status": "SYSMON", "confidence": "high"},
            {"id": "T1553.005", "how": "Zone.Identifier ADS zeroed so SmartScreen/MotW checks do not fire", "status": "SYSMON", "confidence": "high"},
            {"id": "T1140", "how": "Encrypted strings (AV names, C2, file names) decoded at runtime", "status": "BLIND", "confidence": "high"},
            {"id": "T1564.001", "how": "Hidden files/directories (Talos STIX listed revoked T1158)", "status": "BLIND", "confidence": "medium"},
        ],
    },
    {
        "phase": 6, "name": "Command & Control",
        "lm_definition": "Compromised host beacons outbound to an Internet controller.",
        "summary": "HTTP POST check-in with an RC4-encrypted host profile; infrastructure shared with StealC.",
        "fig_actions": ["POST /0gjSy4hf3/index.php -> 91.92.243.129", "RC4 host profile: user, OS, AV, locale", "C2 domain now sinkholed (Maltego)"],
        "actions": [
            "POST /0gjSy4hf3/index.php to 91.92.243.129 (AS202412) - v5: st=s, then r=<hex(RC4(profile))>",
            "Profile = computer, user, domain, OS, admin rights, AV product, locale check (skips Russia)",
            "Fast-flux DNS for C2 domains; one C2 domain now sinkholed by Microsoft (my Maltego pivot)",
        ],
        "sources": ["trellix2025", "binan", "s1025", "maltego"],
        "techniques": [
            {"id": "T1071.001", "how": "HTTP POST to /<random>/index.php (Sigma rule ready, needs proxy logs)", "status": "BLIND", "confidence": "high"},
            {"id": "T1573.001", "how": "v5 encrypts the host profile with RC4 before sending", "status": "BLIND", "confidence": "medium"},
            {"id": "T1568.001", "how": "Fast-flux DNS hides C2 hosts (S1025)", "status": "SYSMON", "confidence": "medium"},
            {"id": "T1082", "how": "OS version, computer name in the check-in", "status": "BLIND", "confidence": "high"},
            {"id": "T1016", "how": "Victim IP / network configuration", "status": "BLIND", "confidence": "high"},
            {"id": "T1033", "how": "User name (GetUserNameA)", "status": "BLIND", "confidence": "high"},
            {"id": "T1083", "how": "Looks for AV program folders", "status": "BLIND", "confidence": "high"},
            {"id": "T1518.001", "how": "AV product code in the av= field", "status": "BLIND", "confidence": "high"},
            {"id": "T1614", "how": "Locale / keyboard check, exits on Russian systems", "status": "BLIND", "confidence": "high"},
            {"id": "T1005", "how": "Host data collected for the panel", "status": "BLIND", "confidence": "high"},
            {"id": "T1041", "how": "Host profile sent over the C2 channel", "status": "SYSMON", "confidence": "high"},
        ],
    },
    {
        "phase": 7, "name": "Actions on Objectives",
        "lm_definition": "The intruder achieves the original goal (theft, destruction, further access).",
        "summary": "Plugins steal credentials and swap wallets; the real goal is delivering StealC (next kill chain).",
        "fig_actions": ["rundll32 clip64.dll / cred64.dll plugins", "StealC from hijacked GitLab -> exfil", "v5 RAT: RDP, hidden admin, proxy"],
        "actions": [
            "Downloads /0gjSy4hf3/Plugins/clip64.dll; rundll32 ...clip64.dll, Main swaps crypto wallets in the clipboard",
            "cred64.dll steals browser credentials",
            "Pulls StealC (protected.zip) from the hijacked GitLab, PowerShell Expand-Archive, runs x64_protect.exe -> exfil to 158.94.208.130",
            "v5 RAT options: screenshots, SOCKS proxy, RDP + hidden admin + firewall rule; historically LockBit 3.0",
        ],
        "sources": ["trellix2025", "vt", "binan", "asec2022"],
        "techniques": [
            {"id": "T1105", "how": "Plugins and StealC downloaded (clip64.dll, protected.zip)", "status": "SYSMON", "confidence": "high"},
            {"id": "T1218.011", "how": "rundll32 <path>\\clip64.dll, Main", "status": "RULE", "confidence": "high"},
            {"id": "T1115", "how": "Clipper plugin replaces wallet addresses", "status": "RULE", "confidence": "high"},
            {"id": "T1555.003", "how": "cred64.dll and StealC steal browser credentials", "status": "RULE", "confidence": "high"},
            {"id": "T1059.001", "how": "PowerShell Expand-Archive unpacks protected.zip", "status": "DATA", "confidence": "high"},
            {"id": "T1113", "how": "v5 screen capture; screenshot upload URL index.php?scr=1 seen in VT relations of d7a366fa", "status": "BLIND", "confidence": "medium"},
            {"id": "T1090", "how": "v5 command: SOCKS proxy through the victim", "status": "SYSMON", "confidence": "medium"},
            {"id": "T1021.001", "how": "v5 command: enable RDP (fDenyTSConnections=0)", "status": "SYSMON", "confidence": "medium"},
            {"id": "T1136.001", "how": "v5 command: hidden local admin account", "status": "DATA", "confidence": "medium"},
            {"id": "T1686", "how": "v5 command: firewall rule for RDP (was T1562.004 before v19)", "status": "DATA", "confidence": "medium"},
            {"id": "T1486", "how": "LockBit 3.0 delivered by Amadey (ASEC 2022) - customer-dependent impact", "status": "BLIND", "confidence": "medium"},
        ],
    },
]

# how each Week 3 IOC (family, role) maps to a phase
IOC_PHASE = {
    ("Amadey", "context"): 2,              # build config: bot ID, string key
    ("Amadey-campaign", "payload-host"): 3,
    ("StealC", "payload-host"): 7,
    ("Amadey-campaign", "sample"): 4,      # Talos campaign hashes: JS downloaders (Emmenhtal) + loader
    ("Amadey", "sample"): 5,
    ("Amadey", "host-artefact"): 5,
    ("Amadey", "c2"): 6,
    ("Amadey-campaign", "c2"): 6,
    ("Amadey-campaign", "network-unlabelled"): 6,
    ("Amadey", "plugin"): 7,
    ("StealC", "sample"): 7,
    ("StealC", "c2"): 7,
    ("StealC", "host-artefact"): 7,
}


def load_attack(path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading {STIX_URL} ...")
        urllib.request.urlretrieve(STIX_URL, path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objs = bundle["objects"]

    def ext(o):
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                return r.get("external_id")
    tech, tactics, order = {}, {}, []
    byref = {o["id"]: o for o in objs}
    for o in objs:
        if o["type"] == "attack-pattern" and ext(o):
            tech.setdefault(ext(o), []).append(o)
        if o["type"] == "x-mitre-tactic":
            tactics[o["x_mitre_shortname"]] = {"id": ext(o), "name": o["name"]}
        if o["type"] == "x-mitre-matrix":
            order = [byref[r]["x_mitre_shortname"] for r in o["tactic_refs"]]
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")
    return tech, tactics, order, version


def resolve(tid, tech):
    cands = [t for t in tech.get(tid, []) if not t.get("revoked") and not t.get("x_mitre_deprecated")]
    if not cands:
        state = "revoked/deprecated" if tid in tech else "unknown"
        raise SystemExit(f"ATT&CK validation failed: {tid} is {state} in v{ATTACK_VERSION}")
    t = cands[0]
    return t["name"], [p["phase_name"] for p in t.get("kill_chain_phases", [])]


def ioc_counts():
    counts = Counter()
    if not IOC_CSV.exists():
        return counts, 0
    rows = list(csv.DictReader(IOC_CSV.open(encoding="utf-8")))
    for r in rows:
        counts[IOC_PHASE.get((r["family"], r["role"]), 0)] += 1
    return counts, len(rows)


def build(stix_path):
    tech, tactics, order, version = load_attack(stix_path)
    counts, total_iocs = ioc_counts()
    out = {"title": "Amadey intrusion (2025) mapped to the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK",
           "attack_version": version, "status_legend": {k: v["label"] for k, v in STATUS.items()},
           "sources": SOURCES, "phases": []}
    for ph in KILL_CHAIN:
        p = {k: v for k, v in ph.items() if k != "techniques"}
        p["iocs_from_week3"] = counts.get(ph["phase"], 0)
        p["techniques"] = []
        for t in ph["techniques"]:
            name, tac = resolve(t["id"], tech)
            p["techniques"].append({**t, "name": name, "tactics": tac,
                                    "tactic_names": [tactics[x]["name"] for x in tac]})
        out["phases"].append(p)
    out["iocs_total_week3"] = total_iocs
    out["iocs_unmapped"] = counts.get(0, 0)
    return out, tactics, order


def layers(mapping, tactics):
    phase_colors = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
    merged = OrderedDict()
    for ph in mapping["phases"]:
        for t in ph["techniques"]:
            m = merged.setdefault(t["id"], {"phases": [], "how": [], "status": t["status"], "name": t["name"]})
            m["phases"].append(ph["phase"])
            m["how"].append(f"KC{ph['phase']} {ph['name']}: {t['how']}")
            if STATUS[t["status"]]["score"] > STATUS[m["status"]]["score"]:
                m["status"] = t["status"]
    base = {
        "versions": {"attack": ATTACK_VERSION, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [{"name": "project", "value": "github.com/sheinorshin/amadey-threat-hunting (Week 4)"}],
    }
    kc = dict(base, name="Amadey - Cyber Kill Chain phases",
              description="Techniques of the analysed Amadey intrusion, coloured by Lockheed Martin kill-chain phase (first phase if several).",
              gradient={"colors": ["#ffffff", "#2a78d6"], "minValue": 0, "maxValue": 7},
              legendItems=[{"label": f"KC{p['phase']} {p['name']}", "color": phase_colors[p["phase"] - 1]}
                           for p in mapping["phases"]],
              techniques=[{"techniqueID": tid, "color": phase_colors[m["phases"][0] - 1], "score": m["phases"][0],
                           "comment": " | ".join(m["how"]), "enabled": True, "showSubtechniques": False}
                          for tid, m in merged.items()])
    cov = dict(base, name="Amadey - detection coverage in my SIEM lab",
               description="3 = Sigma rule + data now, 2 = data now (huntable), 1 = needs Sysmon, 0 = blind / CTI only.",
               gradient={"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 3},
               legendItems=[{"label": v["label"], "color": v["color"]} for v in STATUS.values()],
               techniques=[{"techniqueID": tid, "score": STATUS[m["status"]]["score"], "color": STATUS[m["status"]]["color"],
                            "comment": f"{STATUS[m['status']]['label']} | " + " | ".join(m["how"]),
                            "enabled": True, "showSubtechniques": False}
                           for tid, m in merged.items()])
    return kc, cov, merged


def figures(mapping, merged, order, tactics, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    import textwrap

    INK, INK2, MUTED, SURF, PANEL, EDGE = "#0b0b0b", "#52514e", "#8a8984", "#fcfcfb", "#f3f2ee", "#d9d8d2"
    plt.rcParams.update({"font.family": "DejaVu Sans"})

    # ---------- figure 1: kill chain columns
    fig = plt.figure(figsize=(22, 12.4), dpi=110)
    fig.patch.set_facecolor(SURF)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 22); ax.set_ylim(0, 12.4); ax.axis("off")
    ax.text(0.4, 11.85, "Amadey intrusion (2025) on the Lockheed Martin Cyber Kill Chain", fontsize=21, weight="bold", color=INK)
    ax.text(0.4, 11.4, "Talos (delivery, 2025) + Trellix (Amadey 5.70 -> StealC, Dec 2025) + my VirusTotal / Maltego / MISP work.  "
            "Chips = ATT&CK v19 techniques, colour = what my SIEM lab can see today.", fontsize=11.5, color=INK2)
    colw, gap, x0, top = 2.95, 0.12, 0.4, 10.95
    for i, ph in enumerate(mapping["phases"]):
        x = x0 + i * (colw + gap)
        ax.add_patch(FancyBboxPatch((x, 0.95), colw, top - 0.95, boxstyle="round,pad=0,rounding_size=0.12",
                                    fc=PANEL, ec=EDGE, lw=1))
        ax.text(x + 0.15, top - 0.42, f"{ph['phase']}", fontsize=22, weight="bold", color=MUTED)
        ax.text(x + 0.62, top - 0.38, "\n".join(textwrap.wrap(ph["name"], 15)), fontsize=13.5, weight="bold", color=INK, va="center")
        y = top - 1.05
        for line in textwrap.wrap(ph["summary"], 34)[:5]:
            ax.text(x + 0.15, y, line, fontsize=9.6, color=INK2, style="italic"); y -= 0.3
        y -= 0.1
        for a in ph.get("fig_actions", ph["actions"]):
            wrapped = textwrap.wrap(a, 36)[:3]
            for j, line in enumerate(wrapped):
                ax.text(x + 0.15, y, ("- " if j == 0 else "  ") + line, fontsize=9.1, color=INK); y -= 0.27
            y -= 0.08
        # technique chips (bottom-up)
        cy = 1.15
        for t in reversed(ph["techniques"]):
            st = STATUS[t["status"]]
            ax.add_patch(FancyBboxPatch((x + 0.12, cy), colw - 0.24, 0.36, boxstyle="round,pad=0,rounding_size=0.06",
                                        fc=st["color"], ec=SURF, lw=2))
            txt = f"{t['id']}  {t['name']}"
            if len(txt) > 31:
                txt = txt[:30] + "..."
            ax.text(x + 0.22, cy + 0.18, txt, fontsize=8.6, color="#0b0b0b" if t["status"] != "BLIND" else "#ffffff",
                    va="center", weight="bold")
            cy += 0.42
        ax.text(x + 0.15, cy + 0.08, f"ATT&CK ({len(ph['techniques'])})   IOCs: {ph['iocs_from_week3']}", fontsize=9.2, color=MUTED, weight="bold")
        if i < len(mapping["phases"]) - 1:
            ax.annotate("", xy=(x + colw + gap + 0.02, top - 0.35), xytext=(x + colw - 0.05, top - 0.35),
                        arrowprops=dict(arrowstyle="-|>", color=MUTED, lw=1.4))
    # legend
    lx = 0.4
    for k, v in STATUS.items():
        ax.add_patch(FancyBboxPatch((lx, 0.35), 0.34, 0.3, boxstyle="round,pad=0,rounding_size=0.05", fc=v["color"], ec=SURF))
        ax.text(lx + 0.45, 0.5, f"{v['label']}", fontsize=10.5, color=INK, va="center")
        lx += 0.45 + 0.115 * len(v["label"]) + 0.6
    ax.text(21.6, 0.5, "KC7 of Amadey = KC3 (Delivery) of StealC: a nested kill chain", fontsize=10.5, color=INK2, ha="right", va="center", style="italic")
    fig.savefig(outdir / "amadey_kill_chain.png", facecolor=SURF)
    plt.close(fig)

    # ---------- figure 2: ATT&CK v19 matrix view
    cols = [t for t in order if any(t in merged_tac(merged, tid, mapping) for tid in merged)]
    per = {c: [tid for tid in merged if c in merged_tac(merged, tid, mapping)] for c in cols}
    nrow = max(len(v) for v in per.values())
    cw, rh = 1.62, 0.78
    W, H = 0.4 + cw * len(cols) + 0.3, 1.9 + rh * nrow + 0.9
    fig = plt.figure(figsize=(W, H), dpi=120)
    fig.patch.set_facecolor(SURF)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
    ax.text(0.4, H - 0.5, f"Amadey intrusion techniques in the ATT&CK v{mapping['attack_version']} Enterprise matrix - detection coverage in my lab",
            fontsize=15, weight="bold", color=INK)
    ax.text(0.4, H - 0.9, f"{len(merged)} techniques across {len(cols)} of 15 tactics (v19: Defense Evasion split into Stealth TA0005 and Defense Impairment TA0112). "
            "Label under the name = kill-chain phase(s).", fontsize=9.5, color=INK2)
    for j, c in enumerate(cols):
        x = 0.4 + j * cw
        ax.text(x + cw / 2 - 0.04, H - 1.35, "\n".join(textwrap.wrap(tactics[c]["name"], 14)), fontsize=8.8, weight="bold",
                color=INK, ha="center", va="center")
        ax.text(x + cw / 2 - 0.04, H - 1.68, f"{tactics[c]['id']} ({len(per[c])})", fontsize=7.6, color=MUTED, ha="center")
        for r, tid in enumerate(per[c]):
            m = merged[tid]; st = STATUS[m["status"]]
            y = H - 2.0 - (r + 1) * rh
            ax.add_patch(FancyBboxPatch((x + 0.04, y + 0.04), cw - 0.12, rh - 0.1, boxstyle="round,pad=0,rounding_size=0.06",
                                        fc=st["color"], ec=SURF, lw=2))
            fg = "#ffffff" if m["status"] == "BLIND" else "#0b0b0b"
            ax.text(x + 0.12, y + rh - 0.2, tid, fontsize=8.2, weight="bold", color=fg)
            nm = textwrap.wrap(m["name"], 20)[:2]
            ax.text(x + 0.12, y + rh - 0.42, "\n".join(nm), fontsize=6.9, color=fg, va="top")
            ax.text(x + cw - 0.14, y + rh - 0.2, "KC" + ",".join(str(p) for p in sorted(set(m["phases"]))), fontsize=6.6, color=fg, ha="right")
    lx = 0.4
    for k, v in STATUS.items():
        ax.add_patch(FancyBboxPatch((lx, 0.3), 0.32, 0.26, boxstyle="round,pad=0,rounding_size=0.05", fc=v["color"], ec=SURF))
        ax.text(lx + 0.42, 0.43, v["label"], fontsize=9, color=INK, va="center")
        lx += 0.42 + 0.1 * len(v["label"]) + 0.55
    fig.savefig(outdir / "attack_matrix_coverage.png", facecolor=SURF)
    plt.close(fig)


def merged_tac(merged, tid, mapping):
    for ph in mapping["phases"]:
        for t in ph["techniques"]:
            if t["id"] == tid:
                return t["tactics"]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", default=os.path.expanduser("~/.cache/attack/enterprise-attack-19.2.json"))
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args()
    mapping, tactics, order = build(Path(args.stix))
    (WEEK / "data").mkdir(exist_ok=True)
    public = dict(mapping, phases=[{k: v for k, v in ph.items() if k != "fig_actions"} for ph in mapping["phases"]])
    (WEEK / "data" / "amadey_kill_chain.json").write_text(json.dumps(public, indent=2, ensure_ascii=False), encoding="utf-8")
    kc, cov, merged = layers(mapping, tactics)
    (WEEK / "navigator").mkdir(exist_ok=True)
    (WEEK / "navigator" / "amadey_kill_chain_layer.json").write_text(json.dumps(kc, indent=2, ensure_ascii=False), encoding="utf-8")
    (WEEK / "navigator" / "amadey_detection_coverage_layer.json").write_text(json.dumps(cov, indent=2, ensure_ascii=False), encoding="utf-8")
    if not args.no_figures:
        (WEEK / "figures").mkdir(exist_ok=True)
        figures(mapping, merged, order, tactics, WEEK / "figures")

    # summary
    print(f"ATT&CK v{mapping['attack_version']}: all technique IDs valid (exist, not revoked/deprecated)")
    total = Counter()
    for ph in mapping["phases"]:
        st = Counter(t["status"] for t in ph["techniques"])
        total.update(st)
        print(f"KC{ph['phase']} {ph['name']:<22} techniques={len(ph['techniques']):>2}  iocs={ph['iocs_from_week3']:>2}  " +
              " ".join(f"{k}={st.get(k, 0)}" for k in STATUS))
    uniq = Counter(m["status"] for m in merged.values())
    tac_used = sorted({tac for m in mapping["phases"] for t in m["techniques"] for tac in t["tactics"]}, key=order.index)
    print(f"technique entries={sum(total.values())} unique techniques={len(merged)} tactics used={len(tac_used)}/15: {tac_used}")
    print("unique by status: " + " ".join(f"{k}={uniq.get(k, 0)}" for k in STATUS))
    print(f"IOCs mapped {mapping['iocs_total_week3'] - mapping['iocs_unmapped']}/{mapping['iocs_total_week3']} (unmapped={mapping['iocs_unmapped']})")


if __name__ == "__main__":
    main()
