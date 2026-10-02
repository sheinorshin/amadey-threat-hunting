# 2. Classification of Threats and Their Sources

> **Syllabus task (Week 1):** *Classify different types of threats and their sources.*
> **Recommended reading:** ENISA Threat Landscape (ETL) — I used **ETL 2025** (latest edition).

I classify along **four axes**, then place Amadey on each one.

---

## 2.1 By threat actor (who)

| Actor type | Motivation | Typical capability | Example | Where Amadey fits |
|---|---|---|---|---|
| **Cybercriminals** | Financial | Medium–high, commoditised tools | Ransomware affiliates, infostealer crews | ✅ **Primary.** Amadey is sold/rented as MaaS to criminals. |
| **State-nexus / APT** | Espionage, sabotage | High, custom tooling | APT29, APT41, Kimsuky | ⚠️ ATT&CK lists **Kimsuky (G0094)** using Amadey — states also buy crimeware. |
| **Hacktivists** | Ideology | Low–medium (DDoS, defacement) | NoName057(16), CyberVolk | ❌ Not typical. |
| **Hackers-for-hire / brokers** | Financial (as a service) | Varies | Initial Access Brokers | ✅ Amadey operators effectively *sell installs* to other criminals. |
| **Insiders** | Revenge, money, negligence | Privileged access | Disgruntled admin | ❌ — but a negligent user running a crack starts the chain. |

## 2.2 By threat category (what) — ENISA ETL 2025 view

| ENISA threat category | Short description | Amadey relevance |
|---|---|---|
| **Ransomware** | Encrypt/steal data for extortion | **Indirect** — Amadey delivered LockBit 3.0 (ASEC, 2022). |
| **Malware** (incl. infostealers, loaders) | Malicious code in general | **Direct** — Amadey *is* a loader/botnet; v5 is a modular RAT. |
| **Social engineering** (phishing) | Manipulating people | **Delivery vector** — phishing archives with JS (Emmenhtal; Talos 2025 links it to Amadey), ClickFix, fake software. |
| **Threats against data** | Breach/leak of data | **Via payloads** — StealC/`cred.dll` steal credentials. |
| **Threats against availability (DDoS)** | Service disruption | Low — Amadey can run any payload, but not its purpose. |
| **Information manipulation** | Disinformation | ❌ |
| **Supply-chain threats** | Compromise via third parties | **Partial** — abuse of trusted platforms (GitHub repos, a compromised self-hosted GitLab) to host payloads. |

## 2.3 By malware type (how it works)

| Type | Key behaviour | Amadey? |
|---|---|---|
| Virus / worm | Self-replication | ❌ No self-spreading |
| **Trojan** | Disguised as legitimate software | ✅ Delivered as fake/cracked software |
| **Loader / downloader** | Fetch + run next stage | ✅ **Core function** |
| **Bot / botnet client** | Polls C2 for tasks | ✅ |
| **RAT / backdoor** | Interactive remote control | ✅ **v5**: 19 commands (IDs 10–29) incl. cmd/PowerShell, VNC, SOCKS proxy, RDP enable, hidden admin |
| **Infostealer** | Credentials, cookies, clipboard | ✅ via plugins `cred.dll`, `clip.dll` |
| Ransomware | Encrypt for ransom | ❌ itself — ✅ as payload |
| Rootkit / wiper | Stealth / destruction | ❌ |

**Verdict:** Amadey = **financially-motivated, MaaS-distributed Trojan loader + botnet**, which since version 5 behaves as a **modular RAT**. Its real danger is as the **first stage** that hands the machine over to infostealers or ransomware.

## 2.4 Sources of threat intelligence (where the intel comes from)

Rated with the **Admiralty Code** (reliability A–F / credibility 1–6).

| Source class | Examples | Pros | Cons | Used for Amadey | Rating |
|---|---|---|---|---|---|
| **OSINT – vendor research** | Talos, Microsoft, Trellix, ASEC, Splunk blogs | Free, deep technical detail | Delayed, vendor bias | ✅ main source of TTPs + IOCs | A–B / 2 |
| **OSINT – community platforms** | MalwareBazaar, ThreatFox, URLhaus, VirusTotal, ANY.RUN | Fresh, high volume | Noise, unverified submissions | ✅ hash/C2 lookups (Week 2) | B–C / 3 |
| **OSINT – internet scanning** | Shodan, Censys, InternetDB | Find live infrastructure | Point-in-time | ✅ C2 host checks (Week 2) | B / 3 |
| **OSINT – registries** | RIPE/ARIN WHOIS, RIPEstat, passive DNS | Authoritative ownership data | Privacy-redacted | ✅ ASN/netblock pivots | A / 2 |
| **Frameworks / knowledge bases** | MITRE ATT&CK, Malpedia | Structured, curated | Lag behind new versions | ✅ S1025 mapping | A / 2 |
| **Government / LE** | Europol, CISA, national CERTs (KZ-CERT) | Authoritative, legal action data | Little technical detail | ✅ Operation Endgame (Jun 2026) | A / 1 |
| **Commercial feeds** | Recorded Future, Mandiant, Intel 471 | Curated, high fidelity | Expensive | ❌ (not available to me) | A–B / 2 |
| **Sharing communities** | ISACs, MISP communities | Peer-validated, sector-specific | Membership needed | ⚙️ MISP feeds in Week 3 | B / 2 |
| **Internal telemetry** | SIEM, EDR, proxy, DNS logs | 100 % relevant to *the defender* | Needs collection + analysis | ⚙️ Data-source mapping in Week 2 | A / 1 |
| **Dark web / HUMINT** | Forum ads, actor chats | Early warning, pricing | Legal/OPSEC risk | ❌ (cited second-hand: ~$500 forum price, Malpedia) | C / 3 |

---

## 2.5 ENISA Threat Landscape 2025 — reading notes

| Item | Finding |
|---|---|
| Period / scope | July 2024 – June 2025, ≈ **4,900** curated incidents |
| Initial access | **Phishing ≈ 60 %** of intrusion vectors; AI-assisted phishing > 80 % of social-engineering activity by early 2025 |
| Most frequent | **Hacktivist DDoS ≈ 80 %** of incidents — but mostly low impact |
| Most damaging | **Ransomware** (double/triple extortion) |
| Most targeted sector | **Public administration ≈ 38 %** |
| Trend | Convergence of criminal ecosystems; crime **as-a-service** lowers the skill barrier |

**Link to Amadey:** ENISA's two big themes — phishing as #1 entry point and ransomware as #1 impact — are exactly the two ends of an Amadey chain: *phishing / fake software → Amadey → stealer or ransomware*. Amadey is the “glue” between initial access and impact, which is why I chose it.

---

### Sources
- ENISA Threat Landscape 2025 (summary): https://securityaffairs.com/182978/security/reading-the-enisa-threat-landscape-2025-report.html · https://www.enisa.europa.eu/topics/threat-landscape
- MITRE ATT&CK S1025: https://attack.mitre.org/software/S1025/
- Microsoft (24 Jun 2026) — Amadey v5 command set: https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/
- Help Net Security — Operation Endgame vs StealC/Amadey: https://www.helpnetsecurity.com/2026/06/24/operation-endgame-stealc-amadey-malware-disrupted/
- AhnLab ASEC — LockBit 3.0 via Amadey: https://asec.ahnlab.com/en/41450/
