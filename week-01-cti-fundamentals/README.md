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
