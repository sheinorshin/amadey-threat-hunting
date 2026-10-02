# Week 1 — Cyber Threat Intelligence Fundamentals

**Lifecycle stage:** Planning & Direction\
**Syllabus tasks:** (1) create a glossary of key CTI terms · (2) classify different types of threats and their sources · reading: ENISA Threat Landscape

## Deliverables

| File | What it contains |
|---|---|
| [`01-cti-glossary.md`](01-cti-glossary.md) | 40 CTI terms in 5 groups, each with an Amadey example |
| [`02-threat-classification.md`](02-threat-classification.md) | Threats classified by actor, ENISA category, malware type; CTI sources rated with the Admiralty Code; ENISA ETL 2025 notes |
| [`03-amadey-profile.md`](03-amadey-profile.md) | Threat profile: timeline 2018–2026, infection chain, persistence, C2 protocol, plugins, full ATT&CK S1025 mapping |

## Intelligence requirements for the project

These questions drive Weeks 2–10:

| ID | Requirement | Answered in |
|---|---|---|
| PIR-1 | How does Amadey get in, and how can it be detected **before** the second-stage payload runs? | W1 profile → W5 hunt |
| PIR-2 | Which current infrastructure (C2, payload hosts) is linked to Amadey? | W2 OSINT |
| PIR-3 | Which log sources in my SIEM lab can see Amadey's behaviour? | W2 data-source mapping |
| PIR-4 | How can public reports be turned into usable, clean detection content? | W3 MISP + normalisation |

## Key takeaways

1. Amadey = **MaaS loader/botnet → modular RAT (v5)**, financially motivated, active since 2018, disrupted by Operation Endgame in June 2026.
2. It sits between ENISA's #1 entry vector (**phishing**) and #1 impact (**ransomware**) — that's why it matters.
3. Its IOCs change fast; its **TTPs don't** → the hunting in later weeks targets behaviour (Pyramid of Pain).

---

## Defense notes (7–8 min)

| Time | Point |
|---|---|
| 0:00–1:00 | Topic + why Amadey: loader that sells access to stealers/ransomware; ATT&CK S1025; in the news (Operation Endgame, June 2026). |
| 1:00–3:00 | Glossary — show 4 terms with Amadey examples: IOC vs IOA, TTP, Pyramid of Pain, MaaS. |
| 3:00–5:00 | Classification table — actor (cybercrime, also Kimsuky/TA505), ENISA category, malware type → verdict. |
| 5:00–6:30 | Sources table with Admiralty ratings — which ones I use in Week 2. |
| 6:30–8:00 | ENISA 2025 numbers → link to Amadey chain; show PIRs = plan for next weeks. |

**Likely questions**

- *IOC vs IOA?* — IOC = artefact after the fact (hash, IP); IOA = behaviour during the attack (rundll32 loading a DLL from `%APPDATA%\<hex>\`). IOAs survive recompilation.
- *Strategic vs tactical intel?* — Strategic = for management (trend, risk); tactical = TTPs for defenders.
- *Why is a hash at the bottom of the Pyramid of Pain?* — the attacker changes it by recompiling or repacking; Amadey has dozens of builds (5.60 → 5.87 in one report).
- *Is Amadey a virus?* — No: it doesn't self-replicate. It's a Trojan loader/botnet.
- *Why can Kimsuky (a state actor) use crimeware?* — Cheap, deniable, blends in with criminal noise.
- *Which tactic is T1027 (obfuscation)?* — Since ATT&CK v19 (2026): **Stealth (TA0005)**. The old *Defense Evasion* tactic was split into Stealth and **Defense Impairment (TA0112)**.
