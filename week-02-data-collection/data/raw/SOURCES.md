# Raw collection log

Everything in this folder is stored **exactly as published** (defanged, unvalidated). Processing happens in `week-03-data-processing/`.

| File | Publisher | Published | Collected | Format | Admiralty | TLP |
|---|---|---|---|---|---|---|
| `talos_2025-07_emmenhtal-amadey.txt` | Cisco Talos (GitHub `Cisco-Talos/IOCs/2025/07`) | 2025-07-17 | 2026-10-02 | plain text | A2 | CLEAR |
| `talos_2025-07_emmenhtal-amadey.stix2.json` | Cisco Talos (same repo) | 2025-07-15 | 2026-10-02 | STIX 2.1 bundle | A2 | CLEAR |
| `trellix_2025-12-18_amadey-gitlab.md` | Trellix ARC blog | 2025-12-18 | 2026-10-02 | Markdown tables | A2 | CLEAR |
| `microsoft_2026-06-24_stealc-amadey.md` | Microsoft Threat Intelligence | 2026-06-24 | 2026-10-02 | Markdown table | A2 | CLEAR |
| `splunk_2023-07-25_amadey.txt` | Splunk Threat Research | 2023-07-25 | 2026-10-02 | plain text | A2 | CLEAR |

Collection method: manual download from the publisher (Talos files via `git clone --sparse` of the public IOC repo), no interaction with malicious infrastructure.

**Quality issues noticed already at collection time** (fixed in Week 3):
- Talos TXT has **2 SHA-256 values with 63 characters** (truncated) — Talos's own STIX bundle contains only the 6 valid ones.
- Talos STIX references **T1158** (Hidden Files and Directories) — a *revoked* ATT&CK ID, replaced by **T1564.001**.
- Mixed defanging styles: `hxxp://`, `[.]`, partially defanged (`185.215.113[.]16`).
- Microsoft and Trellix lists also contain **StealC** indicators — must be tagged separately, not as Amadey.
