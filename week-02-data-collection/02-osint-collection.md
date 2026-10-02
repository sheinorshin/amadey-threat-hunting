# 2. OSINT Collection — VirusTotal, Shodan, Maltego

> **Syllabus task (Week 2):** *Perform OSINT data collection using Shodan, VirusTotal, and Maltego.*
> Seeds: [`data/vt_targets.txt`](data/vt_targets.txt) (12 indicators), [`data/ip_targets.txt`](data/ip_targets.txt) (7 IPs).

---

## 2.1 VirusTotal

**Goal:** confirm the samples are Amadey, get first-seen dates, file names, sandbox behaviour, and network relations for pivoting.

### Manual procedure (GUI)

| Step | Where in VT | What I record |
|---|---|---|
| 1 | Search the SHA-256 | Detection ratio, *popular threat label* (expect `trojan.amadey/…`), first submission date |
| 2 | **Details** tab | File type, size, PE compile time, other file names (`Yfgfwb.exe`, …) |
| 3 | **Behavior** tab | Process tree (`schtasks.exe`, `rundll32.exe`), registry keys, mutexes, dropped files under `%TEMP%\<hex>\` |
| 4 | **Relations** tab | Contacted URLs/IPs/domains → new C2 candidates; *Dropped files* → plugins |
| 5 | Search IP / domain | Passive DNS, communicating files, detection ratio |

### Scripted procedure (API v3)

```bash
# Windows: set VT_API_KEY=xxxx   |  Linux/macOS: export VT_API_KEY=xxxx
python scripts/vt_lookup.py data/vt_targets.txt -o data/enrichment/vt_results.csv
```
Read-only (no uploads), respects the free quota (4 req/min) — 12 targets ≈ 3 minutes.

### What to look for (hunting value)

| Field in VT | Why it matters for this hunt |
|---|---|
| `popular_threat_classification` | Confirms family → the report's attribution is corroborated by a second source (raises confidence) |
| Behavior → *Scheduled tasks* | Verifies the 1-minute task TTP for **these** samples, not just the reports |
| Behavior → *Mutexes* | Host-based IOC that can be hunted with EDR |
| Relations → *Contacted URLs* matching `/<8–12 chars>/index.php` | New Amadey C2s not in any report → **new intelligence** |

---

## 2.2 Shodan

**Goal:** check whether the reported infrastructure is still alive and what it runs (passive — data comes from Shodan's own scans).

### Queries

| # | Query / lookup | Purpose |
|---|---|---|
| Q1 | `internetdb.shodan.io/<ip>` (no key) | Quick: open ports, hostnames, CPEs |
| Q2 | Host page / `shodan host <ip>` | Banners, HTTP title, server software, last scan date |
| Q3 | `net:185.215.113.0/24` | Whole bulletproof range that hosted Amadey C2 + payload server |
| Q4 | `asn:AS202412 http.title:"login"` | Panels in the same ASN as the Trellix Amadey C2 — *candidates only*, verify in VT |
| Q5 | `hostname:bzctoons.net` / `ssl.cert.subject.cn:"gitlab.bzctoons.net"` | Compromised GitLab server details |

> Free accounts can't use every filter (Q3/Q4 may need a membership). Q1 works without an account; Q2 with a free API key via `scripts/shodan_lookup.py`.

```bash
python scripts/shodan_lookup.py data/ip_targets.txt --internetdb -o data/enrichment/internetdb.csv
python scripts/shodan_lookup.py data/ip_targets.txt -o data/enrichment/shodan_hosts.csv   # needs SHODAN_API_KEY
```

### Results already collected (2026-10-02)

Combined with RIPEstat registry data → [`data/enrichment/infrastructure_enrichment_2026-10-02.csv`](data/enrichment/infrastructure_enrichment_2026-10-02.csv)

| IP | Role (source) | ASN / holder | Country | Still announced? | Shodan InternetDB |
|---|---|---|---|---|---|
| `185.215.113.43` | Amadey C2 (Talos) | AS56873 ELITETEAM / 1337TEAM | SC | ❌ last seen **2025-05-02** | no data |
| `185.215.113.16` | Payload host `amnew.exe` (Talos) | AS56873 | SC | ❌ | — |
| `185.156.73.73` | Network IOC (Talos) | AS39238 OKB PROGRESS | RU | ✅ | — |
| `91.92.243.129` | Amadey C2 (Trellix) | **AS202412 Omegatech LTD** | US | ✅ | no data |
| `158.94.208.130` | StealC C2 (Trellix) | **AS202412 Omegatech LTD** | DE | ✅ | ports 22, 80, 135, 443, 9090 · hostname `natureofarizona.com` · Apache + OpenSSH 9.2p1 (Debian) |

### Findings

1. **Shared hosting provider:** the Amadey C2 and the StealC C2 of the same campaign sit in the **same ASN and org (AS202412, ORG-OL329-RIPE)** even though they are registered in different countries (US/DE). Hosting choice is a *procedure* — more stable than a single IP.
2. **Dead infrastructure:** the whole `185.215.113.0/24` range (AS56873) **stopped being announced in BGP on 2025-05-02** — right after the Talos campaign window (Feb–Apr 2025). Blocking those IPs today has near-zero value.
3. **IOC decay / re-use:** `158.94.208.130` now answers with an unrelated-looking hostname and a normal web stack — the IP was probably **re-assigned**. Blocking it blindly could hit an innocent site → in Week 3 such IOCs get `to_ids = false` and an expiry date.

---

## 2.3 Maltego

**Goal:** visual link analysis — show how samples, C2s, IPs, netblocks and ASNs connect, and find pivots.

### Procedure

1. Install **Maltego** (free Community licence) → *New Graph*.
2. *Import → Import Graph from Table* → select [`data/maltego_graph_import.csv`](data/maltego_graph_import.csv) → map columns: `source_type/source_value` → source entity, `target_type/target_value` → target entity, `link_label` → link label. (33 links, 32 entities.)
3. Run transforms (free standard set + *VirusTotal Public API* hub item with your VT key):
   - URL → *To Domain* / *To IP Address [DNS]*
   - IPv4 → *To Netblock* → *To AS number*
   - Domain → *To DNS Name – passive* / *To WHOIS*
   - Hash → *VirusTotal: To Files / To Contacted IPs*
4. Use *Organic* layout, colour Amadey vs StealC entities, export PNG to [`evidence/`](evidence/) and save `amadey.mtgz`.

### Expected pivot graph

```mermaid
flowchart LR
    AM(["Amadey S1025"]) --> H1["SHA256 d7a366fa… v5.70"]
    AM --> H2["SHA256 b7d1f172… v5.87"]
    AM --> P1["clip64.dll bae0f38f…"]
    AM --> MX["mutex f936986d…"]
    H1 --> GL["gitlab.bzctoons.net<br/>/suau/fds/-/raw/main/protected.zip"]
    GL --> SC1["StealC b5d4cc84…"]
    AM --> C1["91.92.243.129<br/>/0gjSy4hf3/index.php"]
    C1 --> NB1["91.92.243.0/24"] --> AS1["AS202412 Omegatech"]
    AS1 --> NB2["158.94.208.0/24"] --> C2S["158.94.208.130<br/>StealC C2"]
    C2S --> SC1
    AM --> C3["185.215.113.43<br/>/Zu7JuNko/index.php"]
    C3 --> NB3["185.215.113.0/24"] --> AS2["AS56873 1337TEAM<br/>(offline since 2025-05)"]
    AM --> GH["GitHub: Legendary99999<br/>(Talos)"]
```

**Pivot logic:** Amadey sample → its C2 → netblock → ASN → *another* malware's C2 in the same ASN (StealC). That's how one IOC turns into a picture of an operator's infrastructure — and why the **hosting ASN** is worth monitoring even after single IPs die.

---

## 2.4 Evidence

Screenshots to include for the defense are listed in [`evidence/README.md`](evidence/README.md).
