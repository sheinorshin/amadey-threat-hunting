# 1. The Lockheed Martin Cyber Kill Chain

> **Syllabus (Week 4):** *Lockheed Martin Kill Chain Model* — sources: Lockheed Martin whitepaper, MITRE ATT&CK comparison.
> Recommended reading: Hutchins, Cloppert & Amin, *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains* (Lockheed Martin, 2011).

## 1.1 Core idea

The paper borrows the military idea of a *kill chain*: an intrusion is not one event but a **sequence of dependent steps**. The adversary must complete **every** step to succeed; the defender only has to **break one**. This reverses the usual "defender must be right every time" view.

Defence becomes **intelligence-driven**: every intrusion — including the ones that failed — is analysed phase by phase, so the next one can be stopped *earlier* in the chain.

## 1.2 The seven phases

| # | Phase | What the adversary does | Typical evidence for a defender |
|---|---|---|---|
| 1 | **Reconnaissance** | Research, identify and select targets (people, organisations, technology) | Web-server logs, OSINT about our own exposure — mostly invisible |
| 2 | **Weaponization** | Couple a trojan with an exploit/lure into a deliverable payload (done on the attacker's side) | Only via CTI: malware analysis, builders, staging infrastructure |
| 3 | **Delivery** | Transmit the weapon: e-mail attachment, link, web download, USB | Mail gateway, proxy, download logs |
| 4 | **Exploitation** | Trigger the code: exploit a vulnerability, or let the user / OS auto-execute it | Process creation, script logs, EDR |
| 5 | **Installation** | Install a backdoor or persistence on the host | Files, registry, scheduled tasks, services |
| 6 | **Command & Control (C2)** | Compromised host beacons to an Internet controller ("hands on keyboard") | DNS, proxy, NetFlow, firewall |
| 7 | **Actions on Objectives** | Achieve the goal: steal data, destroy, move laterally, use the host as a hop | Credential use, exfiltration, lateral movement |

## 1.3 Ideas from the paper used in this project

| Concept | Meaning | Where I use it |
|---|---|---|
| **Indicators**: atomic / computed / behavioural | Atomic = IP, domain, e-mail; computed = hashes, regexes; behavioural = combinations that describe *how* the actor operates | Week 3 IOCs (atomic/computed) vs Sigma rules (behavioural) — [`02-amadey-kill-chain-analysis.md`](02-amadey-kill-chain-analysis.md) |
| **Courses of Action matrix** | For each phase pick actions: **Detect, Deny, Disrupt, Degrade, Deceive, Destroy** | [`04-courses-of-action.md`](04-courses-of-action.md) |
| **Earlier is better** | Mitigating at phase 3–4 costs less than at phase 7 | Coverage analysis: where my lab can first break the chain |
| **Campaign analysis** | Intrusions sharing indicators across phases belong to one campaign → reuse of tools/infrastructure is the adversary's weakness | Week 2 pivot: Amadey C2 and StealC C2 in the same ASN (AS202412) |
| **Analyse failed intrusions too** | A blocked attack still reveals the earlier phases | Talos campaign data covers phases 1–4 that Trellix did not see |

## 1.4 Kill Chain vs MITRE ATT&CK

| | Lockheed Martin Cyber Kill Chain | MITRE ATT&CK (Enterprise v19) |
|---|---|---|
| Published | 2011 (Lockheed Martin) | 2013 internally, public 2015; v19 in 2026 |
| Unit | 7 **phases** | 15 **tactics** → ~200 techniques → sub-techniques → procedures |
| Granularity | Coarse — *where* in the intrusion | Fine — *exactly how* each step is done |
| Shape | Linear sequence | Matrix — tactics can repeat and come in any order |
| Coverage | Strong before compromise (phases 1–4); everything after installation is squeezed into phases 6–7 | Strong after compromise (Discovery, Lateral Movement, Collection …); pre-compromise only via Reconnaissance and Resource Development |
| Main use | Strategy: decide where to break the chain, plan defences (Courses of Action), communicate to management | Operations: detection engineering, threat hunting, emulation, coverage gaps |
| Weakness | Perimeter/malware-centric; insider, cloud and post-compromise activity fit poorly | Large, can hide the "story" of one intrusion; no built-in priority |

**They answer different questions:** the Kill Chain tells me *where* to break an intrusion; ATT&CK tells me *what* to look for in the logs. This week maps one to the other.

## 1.5 How I map phases to ATT&CK v19 tactics

ATT&CK v19 split *Defense Evasion* into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, so there are 15 tactics.

| Kill Chain phase | ATT&CK v19 tactics | My rule for this project |
|---|---|---|
| 1 Reconnaissance | Reconnaissance TA0043 | Only what the reports document; inferred items get *low* confidence |
| 2 Weaponization | Resource Development TA0042 (+ Stealth T1027 for obfuscated builds) | Everything done on the attacker's side before anything reaches the victim |
| 3 Delivery | Initial Access TA0001 (+ C2 T1105 when the next stage is downloaded) | Transport of a file to the victim |
| 4 Exploitation | Execution TA0002 (+ Stealth for LOLBins such as mshta) | First code execution on the victim |
| 5 Installation | Persistence TA0003, Privilege Escalation TA0004, Stealth TA0005, Defense Impairment TA0112 | Everything that keeps the implant alive and hidden |
| 6 Command & Control | Command and Control TA0011 (+ Discovery TA0007, Exfiltration TA0010 for the beacon content) | Amadey's host discovery is part of its check-in message, so it sits here |
| 7 Actions on Objectives | Credential Access TA0006, Collection TA0009, Lateral Movement TA0008, Exfiltration TA0010, Impact TA0040 | What the operator/customer actually wants |

## 1.6 Limits of the model (and why it still matters for hunting)

1. **Post-compromise is compressed.** Discovery, credential theft, lateral movement and exfiltration all land in phases 6–7. Threat hunting happens mostly *inside* those phases, so I use ATT&CK for the detail.
2. **Malware/perimeter-centric.** Insiders, valid-account abuse and cloud attacks often have no "delivery" or "installation".
3. **One chain ≠ one actor.** With MaaS (Amadey), initial-access brokers and ransomware affiliates, different criminals run different phases. One intrusion contains **nested chains**: Amadey's *Actions on Objectives* is StealC's *Delivery*.
4. **Linear vs reality.** Real intrusions loop (C2 → discovery → more C2). The **Unified Kill Chain** (Paul Pols, 2017) extends the model to 18 phases in three cycles (*In → Through → Out*) for this reason.

Still useful: the Kill Chain gives a story the teacher, a manager or a SOC lead understands in one slide, and a structure for the **Courses of Action** (where to spend money first).

### Sources
- Hutchins, E. M., Cloppert, M. J., Amin, R. M. (2011). *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains.* Lockheed Martin — https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
- Lockheed Martin, *The Cyber Kill Chain* — https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- MITRE ATT&CK Enterprise v19 (STIX bundle 19.2) — https://attack.mitre.org/ · https://github.com/mitre-attack/attack-stix-data
- Pols, P. *The Unified Kill Chain* — https://www.unifiedkillchain.com/
