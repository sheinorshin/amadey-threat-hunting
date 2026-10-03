# Week 4 — The Cyber Kill Chain · Assignment 2

**Lifecycle stage:** Analysis → planning defences\
**Syllabus tasks:** (1) analyze a real-world cyberattack using the stages of the Kill Chain · (2) map each stage to corresponding ATT&CK TTPs · lecture sources: Lockheed Martin whitepaper, MITRE ATT&CK comparison · reading: Lockheed Martin *Intelligence-Driven Defense* (Hutchins, Cloppert & Amin, 2011)

**Attack analysed:** an **Amadey → StealC** intrusion (2025). Cisco Talos documented the delivery side (phishing → Emmenhtal → Amadey, Feb–Apr 2025). Trellix documented Amadey 5.70 pulling StealC from a hijacked GitLab (Dec 2025). I cross-checked both with my own VirusTotal, Maltego and MISP work from Weeks 2–3.

## Deliverables

| File | Content |
|---|---|
| [`01-kill-chain-model.md`](01-kill-chain-model.md) | Lockheed Martin model: 7 phases, indicators, Courses of Action, **Kill Chain vs ATT&CK** comparison, phase ↔ tactic rules, limits (MaaS, Unified Kill Chain) |
| [`02-amadey-kill-chain-analysis.md`](02-amadey-kill-chain-analysis.md) | **Task 1** — the real-world attack phase by phase: what happened, evidence, IOCs, what a defender sees; nested kill chain and MaaS actors |
| [`03-attack-mapping.md`](03-attack-mapping.md) | **Task 2** — 42 phase × technique rows, ATT&CK v19, validated against the official STIX bundle; matrix view + Navigator layers |
| [`04-courses-of-action.md`](04-courses-of-action.md) | Detect / Deny / Disrupt / Degrade / Deceive / Destroy per phase, lab coverage, priorities, Week 5 hypotheses |
| [`figures/`](figures/) | `amadey_kill_chain.png` (7-phase diagram), `attack_matrix_coverage.png` (ATT&CK v19 matrix) |
| [`navigator/`](navigator/) | ATT&CK Navigator layers: by kill-chain phase, and by detection coverage (one-click links in `03`) |
| [`data/amadey_kill_chain.json`](data/amadey_kill_chain.json) | Machine-readable mapping (phases, procedures, sources, tactics, coverage, IOC counts) |
| [`scripts/build_kill_chain.py`](scripts/build_kill_chain.py) | One source of truth → validates IDs against ATT&CK v19.2 → writes JSON, layers, figures |

## Results in numbers

| Metric | Value |
|---|---|
| Kill-chain phases with evidence | **7 / 7** (phase 1 inferred, low confidence) |
| ATT&CK techniques | **40 unique** (42 phase entries) — all **17** official S1025 techniques + **23** added from reports and my analysis |
| ATT&CK v19 tactics touched | **15 / 15** |
| Week 3 IOCs assigned to a phase | **81 / 81** — 68 (84 %) belong to phases 5–7 |
| Coverage in my lab (unique techniques) | ✅ rule 4 · data, no rule 6 · ⚠️ Sysmon 8 · ❌ blind 16 · CTI only 6 |
| Earliest phase I can break today | **4 — Exploitation** (data collected, rule missing) |

## Key findings

1. **The exploit is a human.** No CVE anywhere in the chain. The user runs a JavaScript file, then `mshta` and PowerShell do the rest. Patching doesn't break this chain; controlling script hosts does.
2. **Public IOCs describe the end of the chain.** 84 % of the vendor IOCs belong to phases 5–7, after the malware already runs. Breaking the chain early needs **behaviour**, not hash lists.
3. **C2 is my biggest blind spot.** 9 of 11 C2-phase techniques are invisible. The `index.php` Sigma rule already exists; there is just no proxy feeding it. That's a sensor gap, not a rule gap.
4. **Nested chains and split actors.** Amadey's *Actions on Objectives* **is** StealC's *Delivery*. The developer, the affiliate and the payload customer each run different phases. Stopping the loader early stops both chains.
5. **Kill Chain + ATT&CK together.** The Kill Chain says *where* to break (7 phases, Courses of Action). ATT&CK says *what* to look for (40 techniques in 15 tactics). Discovery, Collection and Credential Access all collapse into phases 6–7, which is exactly where hunting needs ATT&CK's detail.

## How to rebuild

```bash
cd week-04-kill-chain/scripts
pip install matplotlib
python build_kill_chain.py        # downloads ATT&CK v19.2 STIX once (~54 MB) to ~/.cache/attack
```

---

## Defense notes (7–8 min) — Assignment 2

| Time | Point | Show |
|---|---|---|
| 0:00–1:00 | Lockheed Martin model in one slide: 7 phases, "defender needs one break", Courses of Action | `01`, §1.2–1.3 |
| 1:00–2:00 | Which attack and why: Talos + Trellix 2025, own evidence; the stated intelligence gap | `02`, §2.1–2.2 |
| 2:00–4:30 | Walk the chain on the figure: phishing JS → mshta/PowerShell → hex folder + 1-min task → `index.php` C2 → plugins + StealC | `figures/amadey_kill_chain.png` |
| 4:30–5:30 | ATT&CK mapping: 40 techniques, 15/15 tactics, v19 changes (Stealth, Defense Impairment, T1686), validated by script | `03`, matrix figure / Navigator link |
| 5:30–6:30 | Coverage: where my lab can break the chain (phase 4), blind C2, Sysmon unlocks 8 | `04`, §4.2–4.3 |
| 6:30–7:30 | Lessons: no exploit, IOCs = late phases, nested chains → Week 5 hypotheses H1–H3 | `04`, §4.4 |

**Likely questions**

- *What's the difference between the Kill Chain and ATT&CK?* — Kill Chain = 7 linear phases, strategic (where to break, which defence). ATT&CK = 15 tactics with hundreds of techniques, operational (what exactly to detect). I use the first for structure and the second for detection.
- *Where's the "exploitation" if there's no exploit?* — The model defines exploitation as *triggering the intruder's code*. Here the user runs the script, and Windows binaries (`mshta`, PowerShell) execute it — T1204.002, T1218.005, T1059.x.
- *Why is Discovery in the C2 phase?* — Amadey collects the host profile and sends it in its first C2 request, so in this intrusion discovery happens *inside* the beacon.
- *Why does Weaponization have ATT&CK techniques if it happens on the attacker's side?* — ATT&CK's Resource Development tactic covers it: developing/buying malware (T1587.001/T1588.001), staging payloads (T1608.001), hijacking servers (T1584.004). Only CTI sees it.
- *What would you fix first?* — Rules on the data I already have (phase 4), then Sysmon (+8 techniques), then ASR/AppLocker to move from detection to prevention.
- *What's a limitation of the Kill Chain for this case?* — It assumes one attacker and one linear chain. MaaS gives a developer, an affiliate and a payload customer, and nested chains (Amadey → StealC). Post-compromise activity is squeezed into two phases.
- *How do you know the ATT&CK IDs are right?* — The build script loads the official ATT&CK v19.2 STIX bundle and stops if an ID is unknown, revoked or deprecated. For example, T1562.004 (revoked in v19 → T1686) and T1158 (deprecated → T1564.001) would both fail.
