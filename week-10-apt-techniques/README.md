# Week 10 — APT Techniques · Assignment 6

**Lifecycle stage:** Strategic analysis\
**Syllabus tasks:** analyse the TTPs used by APT29 or APT41 and map them to MITRE ATT&CK · readings: Mandiant *APT1: Exposing One of China's Cyber Espionage Units* (2013), CrowdStrike *Global Threat Report* (2026)

**What this week does:** maps **both** APT29 (G0016) and APT41 (G0096) to ATT&CK v19.2 from the official STIX data, including the campaigns attributed to them (SolarWinds, Operation Ghost, C0017, APT41 DUST). It tells each group's operations along Mandiant's Attack Lifecycle from the APT1 reading. It then compares both with **Amadey** (my Week 4 analysis), the two groups ATT&CK lists as Amadey users (**TA505**, **Kimsuky**) and **APT1** as a 2013 reference point. Finally it estimates what my SIEM lab can see of each, lays my Week 3/5/7 detections on top, and turns the result into a ranked list of detections to build next.

## Deliverables

| File | Content |
|---|---|
| [`01-apt-concepts.md`](01-apt-concepts.md) | What "APT" means; **APT1 reading** (key numbers, Mandiant Attack Lifecycle vs Kill Chain vs ATT&CK); **CrowdStrike 2026 GTR** numbers and what they mean here; group names across vendors; method |
| [`02-apt29-mapping.md`](02-apt29-mapping.md) | **Task** — APT29: identity card, 119 techniques by tactic, SolarWinds along the Attack Lifecycle, what my lab sees, 3 findings |
| [`03-apt41-mapping.md`](03-apt41-mapping.md) | **Task** — APT41: identity card, 105 techniques by tactic, C0017 + APT41 DUST along the Attack Lifecycle, what my lab sees, 3 findings |
| [`04-comparison-and-priorities.md`](04-comparison-and-priorities.md) | APT29 vs APT41, overlap with Amadey / TA505 / Kimsuky / APT1, my lab coverage (with bounds and a check against Week 4), **nominal vs real coverage**, priorities P1–P7, limitations |
| [`scripts/build_apt_profiles.py`](scripts/build_apt_profiles.py) | reads ATT&CK v19.2 + Week 4 + Week 7 data → everything in `data/`, `navigator/`, `figures/` |
| [`data/`](data/) | `apt_profiles.json` (every technique with procedure text and source), `comparison.json`, `apt_techniques.csv`, [`ttp_tables.md`](data/ttp_tables.md) (full tables by tactic) |
| [`navigator/`](navigator/) | `apt29_layer.json`, `apt41_layer.json`, `apt29_vs_apt41_layer.json`, `apt_lab_coverage_layer.json` |
| [`figures/`](figures/) | `tactic_profile.png`, `overlap_matrix.png`, `lab_coverage.png` |

## Results in numbers

| Metric | Value |
|---|---|
| APT29 techniques (ATT&CK v19.2) | **119** = 66 on the group page + **53 only via its campaigns** (SolarWinds alone: 71) · 49 software · 15 aliases |
| APT41 techniques | **105** = 82 group + 23 via campaigns (C0017, APT41 DUST) · 32 software |
| APT29 ∩ APT41 | **40** shared · Jaccard **0.22** (sub-technique) / **0.49** (parent technique) |
| Heaviest tactic | APT29: Persistence 18, Credential Access 16 (identity abuse) · APT41: **Stealth 21** (packers, bootkit, side-loading) |
| Closest to Amadey | **TA505 0.30**, **Kimsuky 0.22** (= the groups ATT&CK lists as Amadey users) · APT41 0.18 · APT29 0.13 · APT1 0.10 |
| Used by APT29, APT41 **and** Amadey | **12** techniques · **7** used by all five current actors (PowerShell, ingress tool transfer, web C2, decode, rundll32, browser credentials, spearphishing attachment) |
| APT1 (2013) techniques still used by both APTs | **7 of 23** |
| My lab vs APT29 + APT41 (184 techniques) | visible today **64 (35 %)** → with Sysmon **141 (77 %)** · 17 cloud/identity/non-Windows · 9 blind |
| My detections vs each APT | **11** technique IDs mapped, only **6** would really fire (the rest are Amadey-specific or need a missing sensor) |
| Automatic visibility vs my manual Week 4 statuses | agree on **17 / 40**: visibility belongs to the procedure, not the technique |
| New detections with data I already have | **5** (P1–P5): telemetry tampering, web server → shell, masqueraded tasks, discovery bursts, password spraying |

## How to reproduce

```bash
cd week-10-apt-techniques/scripts
pip install matplotlib                  # figures only
python build_apt_profiles.py            # ATT&CK v19.2 (cached in ~/.cache/attack) -> data/, navigator/, figures/
```

Open the layers at <https://mitre-attack.github.io/attack-navigator/> → *Open Existing Layer* → *Upload from local* (or *Load from URL* with the raw GitHub link).

---

## Defense notes (7–8 min)

| Time | Point | Show |
|---|---|---|
| 0:00–1:00 | What makes an APT; APT1 reading: Unit 61398, 141 victims, 356 days average dwell time; Attack Lifecycle has a **loop** the Kill Chain lacks | `01`, §1.1–1.2 |
| 1:00–2:00 | CrowdStrike 2026: 29-minute breakout, China-nexus +38 % (edge devices), state-nexus cloud +266 %: why these two groups look the way they do | `01`, §1.3 |
| 2:00–3:30 | APT29: 119 techniques, 53 only from SolarWinds; identity abuse; SolarWinds along the lifecycle; `auditpol` attacks my logs | `02`, APT29 layer |
| 3:30–4:30 | APT41: 105 techniques, starts on servers, Stealth 21, crime + espionage; masqueraded task names | `03`, APT41 layer |
| 4:30–6:00 | Comparison: 0.22 vs 0.49 Jaccard; Amadey closest to TA505/Kimsuky; 7 techniques shared by all five actors | `04`, overlap matrix, tactic profile |
| 6:00–7:30 | My lab: 35 % → 77 % with Sysmon; 11 mapped vs 6 real; 17/40 check; P1–P5 | `04`, coverage figure + layer |

**Likely questions**

- *Why both APT29 and APT41 when the syllabus says "or"?* — The comparison is the useful part. One espionage-only group that starts with identities, and one dual-purpose group that starts on servers, show which detections are group-specific and which are shared. The extra cost was one more row in the script.
- *Why add campaigns to the group's techniques?* — ATT&CK records the SolarWinds procedures under campaign C0024, which is attributed to APT29. Leaving it out drops 53 techniques, including DCSync and SAML token forgery, from APT29's profile.
- *Why not add the techniques of the group's software?* — A tool's ATT&CK entry lists everything the tool *can* do, for all its users. Mimikatz alone would add dozens of techniques. APT29's 49 tools add 131 techniques no report ties to APT29.
- *What does Jaccard 0.22 vs 0.49 mean?* — Shared ÷ union. At sub-technique level the groups share 22 % of their techniques, at parent level 49 %. They do similar things (dump credentials, persist with tasks) in different detailed ways. Detection at parent level generalises better.
- *Is "visible in my lab" a measurement?* — No, it is an estimate from ATT&CK's analytics, with explicit bounds (10 to 83 of APT29's 94 Windows techniques, depending on the rule). It agrees with my hand-made Week 4 statuses on only 17/40, mostly because Amadey uses API calls where ATT&CK assumes command lines. Week 9's tests measure the techniques that matter.
- *What is "nominal coverage"?* — A rule mapped to a technique ID that would not fire on another actor's procedure. My Week 3 rundll32 rule maps to T1218.011 but matches only Amadey's `cred64.dll`/`clip64.dll`. Counting by IDs would almost double my claimed APT coverage.
- *What would you build first, and why?* — P1: alerts on `auditpol` changes, 1102 and 4719. Both APTs tamper with Windows logging (T1685.001, T1685.005), and every other rule I have depends on those logs.
- *What did APT1 teach that still holds?* — 7 of its 23 techniques are still used by both APTs 13 years later (spearphishing attachment, RDP, `cmd`, archive-then-exfiltrate). What changed is cloud and identity, supply chains, and C2 hidden in legitimate services.

← [Project overview](../README.md) · previous: [Week 9](../week-09-atomic-red-team/)
