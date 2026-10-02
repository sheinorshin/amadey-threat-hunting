# 1. CTI Glossary (applied to Amadey)

> **Syllabus task (Week 1):** *Create a glossary of key CTI terms.*
> Every term below has a short definition **and** a concrete example from my case study — the Amadey loader/botnet — so the glossary is not just theory.

---

## A. Core concepts

| # | Term | Definition | Amadey example |
|---|------|-----------|----------------|
| 1 | **Threat** | Any circumstance or actor with the *intent* and *capability* to harm an asset. | An Amadey operator who buys access to the panel (intent: money; capability: the malware). |
| 2 | **Vulnerability** | A weakness that a threat can exploit. | Users running “cracked” software or opening phishing archives — the human weakness Amadey's distributors rely on. |
| 3 | **Risk** | Likelihood × impact of a threat exploiting a vulnerability. | High: one Amadey infection can lead to StealC credential theft or ransomware (LockBit 3.0 was delivered via Amadey in 2022). |
| 4 | **Threat actor** | The person/group behind malicious activity. | The Amadey *developer* (sells the kit) vs. many *operators/affiliates* (run campaigns). ATT&CK also links Amadey to **TA505** and **Kimsuky**. |
| 5 | **Cyber Threat Intelligence (CTI)** | Evidence-based knowledge about threats (context, mechanisms, indicators, implications) that supports decisions. | This repo: turning raw Amadey reports into IOCs, TTPs and detections a SOC can use. |
| 6 | **Information vs. intelligence** | Information = raw data; intelligence = processed, analysed and *relevant* to a decision. | A list of 8 hashes from Talos = information. “Block these 6 valid hashes; 2 are malformed; C2s on AS202412” = intelligence. |
| 7 | **Intelligence lifecycle** | Planning/Direction → Collection → Processing → Analysis → Dissemination → Feedback. | Week 1 = direction, Week 2 = collection, Week 3 = processing. The project's weekly structure follows the lifecycle. |
| 8 | **Intelligence requirement (IR / PIR)** | The question the intelligence must answer (Priority IR = most critical). | *PIR-1: “How does Amadey get into an environment and how can it be detected before the second-stage payload runs?”* |

## B. Types / levels of intelligence

| # | Term | Definition | Amadey example |
|---|------|-----------|----------------|
| 9 | **Strategic intelligence** | High-level, non-technical; for executives (trends, risk, business impact). | “MaaS loaders like Amadey were the target of Operation Endgame (June 2026); infostealer-to-ransomware chains remain a top risk.” |
| 10 | **Operational intelligence** | About specific campaigns/attacks: who, when, how. | Talos (Jul 2025): a MaaS operation used GitHub repos to host Amadey payloads targeting Ukrainian entities. |
| 11 | **Tactical intelligence** | TTPs — how the adversary operates; for defenders/hunters. | Amadey copies itself to `%TEMP%\<10-hex>\<name>.exe` and creates a scheduled task that runs every minute. |
| 12 | **Technical intelligence** | Atomic, machine-readable indicators; short lifespan. | C2 URL `hxxp://91.92.243[.]129/0gjSy4hf3/index.php`, mutex `f936986d553273aef6eeaeef713ad28f`. |

## C. Indicators & behaviour

| # | Term | Definition | Amadey example |
|---|------|-----------|----------------|
| 13 | **Observable** | Any measurable event or property (no judgement yet). | A POST request to `/xxxx/index.php`. |
| 14 | **Indicator of Compromise (IOC)** | An observable known to be associated with malicious activity. | SHA-256 `d7a366fa…cf64e7` (Amadey loader, Trellix Dec 2025). |
| 15 | **Indicator of Attack (IOA)** | Behaviour showing an attack *in progress*, independent of specific files/IPs. | `rundll32.exe` loading `clip64.dll` from `%APPDATA%\<hex>\` — works even when hashes change. |
| 16 | **TTP** | Tactics (why), Techniques (how), Procedures (exact implementation). | Tactic: Persistence → Technique: T1053.005 Scheduled Task → Procedure: `schtasks /Create /SC MINUTE /MO 1 /TN <name> /TR <path> /F`. |
| 17 | **Pyramid of Pain** | Model (D. Bianco) ranking indicators by how painful they are for the attacker to change: hashes → IPs → domains → network/host artefacts → tools → TTPs. | Amadey hashes change per build (trivial); the C2 protocol (`st=s`, `r=<hex>`, `<c>…<d>` tags) and persistence pattern are much harder to change → the hunt targets them. |
| 18 | **Indicator decay / TTL** | IOCs lose value over time; they need expiry dates. | Many Amadey C2s were seized in June 2026 — a 2025 C2 IP blocked today may now belong to someone innocent. |
| 19 | **False positive** | An alert on benign activity. | Blocking `github.com` because Amadey payloads were hosted there would break the business. |

## D. Frameworks & standards

| # | Term | Definition | Amadey example |
|---|------|-----------|----------------|
| 20 | **MITRE ATT&CK** | Knowledge base of adversary tactics and techniques from real observations. | Amadey = software **S1025**, 17 techniques listed (v1.1, modified 12 May 2026). Note: ATT&CK **v19** split *Defense Evasion* into **Stealth** and **Defense Impairment**. |
| 21 | **Cyber Kill Chain** | Lockheed Martin 7-phase model: Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives. | Amadey lives mostly in *Installation* and *C2*, and enables the *Actions* of the next payload. (Deep dive in Week 4.) |
| 22 | **Diamond Model** | Every intrusion event = Adversary, Capability, Infrastructure, Victim. | Trellix case: Adversary = Amadey affiliate; Capability = Amadey 5.70 + StealC; Infrastructure = compromised GitLab + `91.92.243.129`; Victim = Windows users. |
| 23 | **STIX 2.1** | JSON language for describing CTI objects (indicator, malware, attack-pattern, report…). | Talos published its Amadey IOCs as a STIX 2.1 bundle (stored in `week-02/.../raw`). |
| 24 | **TAXII** | Transport protocol for exchanging STIX over HTTPS. | A SOC could subscribe to a TAXII collection that pushes new Amadey indicators. |
| 25 | **TLP 2.0** | Traffic Light Protocol — sharing limits: CLEAR, GREEN, AMBER, AMBER+STRICT, RED. | This project's IOCs come from public reports → **TLP:CLEAR**. |
| 26 | **Admiralty Code** | Rates source reliability (A–F) and information credibility (1–6). | Microsoft/Talos report = **A2**; anonymous paste-site IOC list = **E3/F6**. |
| 27 | **MISP** | Open-source threat-intel sharing platform (events, attributes, correlation, feeds). | Week 3: the normalised Amadey IOCs are loaded into MISP as one event. |

## E. Malware-ecosystem terms (needed for Amadey)

| # | Term | Definition | Amadey example |
|---|------|-----------|----------------|
| 28 | **Loader / downloader** | Malware whose main job is to fetch and run *other* malware. | Amadey's core function: deliver StealC, RedLine, Lumma, LockBit, AsyncRAT, miners. |
| 29 | **Botnet** | Network of infected hosts controlled via C2. | Each Amadey victim registers with a panel and polls for tasks. |
| 30 | **Command and Control (C2)** | Infrastructure/channel the attacker uses to control victims. | HTTP POST to `/<random>/index.php`, data RC4-encrypted and hex-encoded (v5). |
| 31 | **Malware-as-a-Service (MaaS)** | Criminals rent/sell malware + panel to other criminals. | Amadey has been sold on Russian-speaking forums since ~2018 (≈ $500, Malpedia). |
| 32 | **Infostealer** | Malware that steals credentials, cookies, wallets. | StealC — Amadey's most common payload; Amadey's own `cred.dll` plugin. |
| 33 | **Plugin / module** | Optional DLL that extends malware capability. | `cred.dll`/`cred64.dll` (credentials), `clip.dll`/`clip64.dll` (clipboard), VNC plugin (v5). |
| 34 | **Bulletproof hosting** | Hosting that ignores abuse complaints. | `185.215.113.0/24` (AS56873 “ELITETEAM / 1337TEAM”, registered in Seychelles) hosted both the Amadey C2 and the payload server in the 2025 Talos campaign. |
| 35 | **Fast flux** | Rapidly changing DNS records to hide C2 servers. | ATT&CK lists **T1568.001 Fast Flux DNS** for Amadey. |
| 36 | **Sinkhole** | Redirecting malicious domains to a defender-controlled server. | Domains seized in Operation Endgame (June 2026) now resolve to law-enforcement/Microsoft sinkholes. |
| 37 | **Defanging** | Making IOCs non-clickable (`hxxp`, `[.]`). | `185[.]215[.]113[.]43` — refanged automatically by the Week 3 pipeline. |
| 38 | **Pivoting** | Using one indicator to discover related ones. | C2 IP `91.92.243.129` → AS202412 OMEGATECH → StealC C2 `158.94.208.130` in the same AS (Week 2). |
| 39 | **Threat hunting** | Proactive, hypothesis-driven search for threats that evaded existing controls. | *“If Amadey is present, some host will have a 1-minute scheduled task pointing into `%TEMP%\<hex>\`.”* |
| 40 | **Enrichment** | Adding context to an indicator (WHOIS, ASN, geo, reputation). | `185.215.113.43` → AS56873, country SC, netname SC-ELITETEAM-20201113 (RIPEstat). |

---

### Sources
- MITRE ATT&CK — Amadey (S1025): https://attack.mitre.org/software/S1025/
- Cisco Talos (17 Jul 2025): https://blog.talosintelligence.com/maas-operation-using-emmenhtal-and-amadey-linked-to-threats-against-ukrainian-entities/
- Trellix (18 Dec 2025): https://www.trellix.com/blogs/research/amadey-exploiting-self-hosted-gitlab-to-distribute-stealc/
- Microsoft Security Blog (24 Jun 2026): https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/
- AhnLab ASEC — LockBit 3.0 via Amadey (Nov 2022): https://asec.ahnlab.com/en/41450/
- D. Bianco, *The Pyramid of Pain* (2013); FIRST TLP 2.0 standard; Recorded Future, *The Threat Intelligence Handbook*.
