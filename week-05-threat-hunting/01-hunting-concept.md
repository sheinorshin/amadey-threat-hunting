# 1. The Threat Hunting Concept

> **Syllabus (Week 5):** *Hunting models (Intel-driven, Hypothesis-driven)* — sources: SANS Threat Hunting Summit, *Practical Threat Hunting* (P. Smith).
> Recommended reading: Microsoft Threat Hunting guidance; Valentina Costa-Gazcón, *Practical Threat Intelligence and Data-Driven Threat Hunting* (Packt, 2021).

## 1.1 What threat hunting is — and isn't

**Threat hunting is the proactive, hypothesis-led search for attacker activity that has *already evaded* existing automated detections.** The hunter assumes a breach and goes looking for it, instead of waiting for an alert.

| | Alerting / monitoring | Incident response | **Threat hunting** |
|---|---|---|---|
| Trigger | A rule fires | An alert / report | **A hypothesis** |
| Assumption | "Tell me when X happens" | "Something happened" | "They may already be in — where?" |
| Direction | Reactive | Reactive | **Proactive** |
| Output | An alert | Containment & recovery | New detections, new knowledge, (maybe) an incident |
| Measures success by | True positives | Time to recover | **Coverage gaps closed**, even when nothing is found |

A hunt that finds nothing is **not** a failed hunt: it still produces a tested hypothesis, a reusable query, and evidence about a visibility gap. That feedback is the real deliverable.

## 1.2 Two ways to start a hunt

| | **Intel-driven hunting** | **Hypothesis-driven hunting** |
|---|---|---|
| Starts from | CTI: IOCs, a report, a new campaign | A statement about adversary **behaviour (TTPs)** |
| Example | "Search for these 20 Amadey hashes and C2 IPs from the Trellix report" | "If Amadey is here, a script host will have spawned PowerShell that downloads a file" |
| Pyramid of Pain | Low — hashes/IPs (easy for the attacker to change) | High — TTPs (hard to change) |
| Lifespan | Short (IOCs rotate) | Long (behaviour is stable across builds) |
| Where I used it | **Weeks 2–3** (collect IOCs → MISP → Sigma) | **This week** |

Both are valid and they feed each other: Week 3's intel-driven IOC work tells me *who* to hunt for; this week's hypotheses tell me *how* they behave so I can catch the **next** build whose hash I don't have yet. That is the whole point of climbing the **Pyramid of Pain** (Bianco, 2013): hash → IP → domain → host/network artifact → tool → **TTP**. Detecting a TTP causes the adversary the most pain because they'd have to change *how they operate*, not just rotate a server.

## 1.3 Hunting models and frameworks

### Hunting Maturity Model (HMM) — Bianco, 2015
Where a SOC sits:

| Level | Name | Capability | My project |
|---|---|---|---|
| HMM0 | Initial | Relies only on automated alerts | — |
| HMM1 | Minimal | Adds threat-intel indicator searches | **Weeks 2–3** (IOC/MISP searches) |
| HMM2 | Procedural | Follows hunts others have written | **This week** (I apply known Amadey TTP hunts) |
| HMM3 | Innovative | Creates new hunting procedures | Goal for Weeks 6–9 (my own analytics, emulation) |
| HMM4 | Leading | Automates its successful hunts | A found hunt → a Sigma rule (Week 3 feedback loop) |

### The Threat Hunting Loop — Sqrrl / Bianco
1. **Create a hypothesis** → 2. **Investigate** via tools & techniques → 3. **Uncover** new patterns & TTPs → 4. **Inform & enrich** automated analytics → back to 1.
My Week 4 kill-chain gap analysis produced the hypotheses (step 1); this week runs steps 2–4, and step 4 feeds new rules back into the Week 3 Sigma/MISP pipeline.

### PEAK — Prepare, Execute, Act with Knowledge (Splunk, 2023)
The structure each hunt in [`02-hunt-plan.md`](02-hunt-plan.md) follows:
- **Prepare** — pick the hypothesis, scope, data sources, timeframe, success criteria.
- **Execute** — gather, query, analyse, triage candidates to true positives.
- **Act with Knowledge** — document findings, create/upgrade detections, note gaps, hand off.

PEAK names three hunt types; this week uses the first:
1. **Hypothesis-driven** (what I do here).
2. **Baseline / exploratory data analysis** (profile "normal", find outliers) — e.g. a baseline of which parents normally start `powershell.exe`.
3. **Model-assisted (M-ATH)** — ML/analytics-assisted — out of scope for the lab.

## 1.4 A good hypothesis (the ABLE test)

A usable hunting hypothesis is **A**ctionable, **B**ehaviour-focused, **L**imited in scope, and **E**vidence-testable:

- **Actionable** — if true, it leads to a detection or a response.
- **Behavioural** — about *what the adversary does* (a TTP), not a single IOC.
- **Limited** — one testable idea, one timeframe, defined data sources.
- **Evidence-testable** — the data to prove or disprove it actually exists in my logs.

Bad: *"Amadey is on the network."* (too broad, not testable)
Good: *"A Windows script host spawned PowerShell that downloaded or executed remote content in the last 7 days."* (one behaviour, specific data: 4688 + 4104, testable, maps to ATT&CK T1059/T1218/T1105).

## 1.5 Where my three hypotheses come from

They are not invented — they are the **earliest, cheapest breaks** identified in the Week 4 Courses-of-Action analysis ([`../week-04-kill-chain/04-courses-of-action.md`](../week-04-kill-chain/04-courses-of-action.md) §4.4), chosen because the data already exists in my lab:

| Hypothesis | Kill-chain phase | ATT&CK v19 | Lab data |
|---|---|---|---|
| **H1** script host → PowerShell → remote content | 4 Exploitation | T1059.001/.007, T1218.005, T1105 | 4688 + 4104 |
| **H2** hex-folder EXE + 1-minute scheduled task | 5 Installation | T1053.005, T1204.002 | 4688 + 4698 |
| **H3** new admin + firewall rule, same host, minutes apart | 7 Actions on Objectives | T1136.001, T1021.001, T1686 | 4720/4732 + 4946 |

H1 is exactly the syllabus's own example ("suspicious PowerShell activity"), reached by analysis rather than picked at random.

## 1.6 Tooling — Splunk vs ELK, and what my lab uses

The syllabus allows **Splunk or ELK**. My SIEM lab is **Elastic** (Elasticsearch + Kibana 9.x, Elastic Agent on a Windows Server VM), so the hunt queries are written for Kibana in three languages, matched to the task:

| Language | Best for | Where I use it |
|---|---|---|
| **KQL** (Kibana Query Language) | fast filter-bar pivots in Discover | quick look at candidates |
| **ES\|QL** (Elasticsearch Query Language) | filter → transform → aggregate, like SPL/SQL | the main hunt + triage tables |
| **EQL** (Event Query Language) | **sequences / correlation** across events | the multi-step chains (H1, H3) |

Splunk's equivalent would be SPL (`index=win | where ...`, `transaction`, `| stats`). The *logic* is identical; only the syntax differs.

### Sources
- D. J. Bianco, *The Pyramid of Pain* (2013) — https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- D. J. Bianco, *A Simple Hunting Maturity Model* (2015) — https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html
- Sqrrl / D. J. Bianco, *The Threat Hunting Loop*
- Splunk, *PEAK Threat Hunting Framework* (2023) — https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
- V. Costa-Gazcón, *Practical Threat Intelligence and Data-Driven Threat Hunting*, Packt, 2021 (syllabus SIS reading)
- TaHiTI — *Threat Hunting Methodology*, https://www.betaalvereniging.nl/en/safety/tahiti/
- Microsoft, *Advanced hunting* guidance — https://learn.microsoft.com/defender-xdr/advanced-hunting-overview
