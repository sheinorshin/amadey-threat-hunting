# 4. Findings & new detections (PEAK: Act with Knowledge)

> The point of a hunt is not the hunt — it's what you leave behind: new detections, closed gaps, and knowledge for the next analyst. This closes the Threat Hunting Loop by feeding results back into the Week 3 detection pipeline.

## 4.1 Findings

1. **The intrusion was found three independent ways.** H1 (exploitation), H2 (installation) and H3 (actions on objectives) each located WIN-FIN-07 on their own. Independent confirmation is what makes a hunt result credible — a single noisy rule could be a fluke; three disjoint behaviours on one host within six minutes is not.
2. **Behaviour beats content.** The naive "search all PowerShell for a download cradle" returned **27** hits (mostly benign admin activity). Adding one behavioural condition — *parent is a script host* — cut it to **1** with no false negatives. This is the Pyramid-of-Pain lesson made concrete: hunting the TTP is both more precise and more durable than hunting a string.
3. **The lab can break the chain at exploitation (KC4).** The earliest confirmation (H1, 11:14) happens on data the lab already collects — **before** the loader installs (11:15) and long before StealC runs (11:17). Confirms the Week 4 conclusion that the first viable break is phase 4, with no new sensors.
4. **Correlation turns noise into signal.** In H3 the individual events (a new account, a firewall rule) are ordinary admin noise — 6 such events in the day. Their **co-occurrence on one host within minutes** is the detection. A hunt (or an EQL rule) sees this; a single-event alert does not.
5. **Two Week-3 Sigma rules are validated; two new detections are needed.** See below.

## 4.2 Detection engineering output

Closing the loop into Week 3's [`sigma/`](../week-03-data-processing/sigma/) pipeline:

| Hunt | Status | Detection action |
|---|---|---|
| **H1** script host → PowerShell → remote content | **Gap → new rule** | No Week-3 rule covered this. Promote the H1 candidate query to a scheduled detection: *PowerShell with a script-host parent* (high value, very low volume). Enrich-only with the 4104 cradle match to raise severity. |
| **H2** hex-folder EXE | **Validated** | Matches Week-3 `proc_creation_win_amadey_hex_folder_exe.yml`. The hunt confirmed it fires on the v5 path `…\067640a009\Yfgfwb.exe` with no false positives in a day of noise. |
| **H2** 1-minute task | **Validated** | Matches Week-3 `proc_creation_win_amadey_schtasks_every_minute.yml`; the 4698 `PT1M` angle is an additional data source the rule can add for defence-in-depth. |
| **H3** new admin + firewall | **Gap → new correlation rule** | No single-event rule captures it. Needs a **correlation / EQL sequence** rule (account-to-Administrators **and** 4946 within 30 min). Kibana supports this as an EQL rule; Sigma supports it via `correlation`. |

**Promoting H1 to a Sigma rule** (sketch — to be added and converted with the Week 3 `convert_sigma.py`):
```yaml
title: PowerShell Spawned by a Windows Script Host
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith: '\powershell.exe'
    ParentImage|endswith: ['\wscript.exe','\cscript.exe','\mshta.exe','\wmic.exe','\regsvr32.exe']
  condition: selection
level: high
tags: [attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1218.005]
```

## 4.3 Metrics

| Metric | Value |
|---|---|
| Events hunted | 976 across 5 hosts (1 day) |
| Hypotheses tested | 3 (all confirmed on the planted intrusion) |
| True positives | 1 host / 1 intrusion |
| False positives after triage | **0** (3 near-misses correctly rejected) |
| New detections produced | **2** (H1 rule, H3 correlation rule) |
| Existing detections validated | **2** (Week-3 hex-folder + 1-minute task) |
| Visibility gaps re-confirmed | C2 (no proxy), registry/ADS/DNS (no Sysmon) |
| Hunting maturity exercised | **HMM2 → HMM4 loop** (ran known TTP hunts → produced automatable rules) |

## 4.4 Limitations & honesty

- **The dataset is synthetic.** My Elastic lab collects the right sources but has no Amadey activity in it yet — generating real telemetry is Week 9 (Atomic Red Team). The synthetic set is built from the *documented* Amadey behaviour (Weeks 1–4) using the exact ECS fields the Elastic integrations produce, so the queries are the real ones; only the data is simulated.
- **The queries are written for Elastic 9.x** (ES\|QL / EQL / KQL). They are logic-equivalent to Splunk SPL; a Splunk shop would translate the syntax, not the idea.
- **Blind spots remain by design.** H-level C2 behaviour isn't hunted here because the lab can't see it (no proxy/NSM). That's a sensor gap, documented in Week 4, not an oversight.

## 4.5 Next step — run it in the real lab (with Oracle VM screenshots)

The reproducible plan for the live defense, together:
1. Bulk-load [`data/dataset.ndjson`](data/dataset.ndjson) into the lab Elasticsearch (`_bulk`) under an index like `logs-system.security-default` / `logs-windows.powershell_operational-default`, or point the queries at the real `logs-*`.
2. Run each query in **Kibana → Discover (ES\|QL)** and **Security → Timelines (EQL)**.
3. Screenshot: the H1 single hit, the H2 three indicators, the H3 EQL sequence, and the reconstructed timeline → save to `evidence/` and commit.
4. (Week 9) replace the synthetic data with **real** telemetry from Atomic Red Team tests of T1059/T1053.005/T1136.001 and re-run the same queries — same hunt, real events.

## 4.6 Feeds forward

- → **Week 6 (ATT&CK deep-dive):** take **T1053.005** (the H2 technique) apart — data sources, sub-behaviours, a focused analytic.
- → **Week 7 (MITRE CAR):** express the H1/H3 analytics as CAR analytics and map their data model.
- → **Week 9 (Atomic Red Team):** generate the real events these hunts expect and re-run them in the lab.
