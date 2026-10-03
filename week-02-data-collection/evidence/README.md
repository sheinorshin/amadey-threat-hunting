# Evidence (screenshots for the defense)

VirusTotal and Shodan captured on **2026-10-02** from the web GUIs (no API keys, no logins); Maltego on **2026-10-03** (free Community Edition).

## VirusTotal — [`virustotal/`](virustotal/)

| File | Shows |
|---|---|
| `vt_file_d7a366fa_amadey-5.70_detection.jpg` | Amadey 5.70 loader (Trellix): **54/70**, label `trojan.amadey/mikey`, family labels amadey / mikey / lumma |
| `vt_file_d7a366fa_amadey-5.70_details-history.jpg` | Hashes, PE64 / MSVC 2019, compile time 2025-11-11, first submission 2025-11-20 |
| `vt_file_d7a366fa_amadey-5.70_relations-urls.jpg` | Contacted URLs: C2 `/0gjSy4hf3/index.php`, plugin `/Plugins/clip64.dll`, **new** compromised GitLab `gitd3ti.vokasi.uns.ac.id` |
| `vt_file_d7a366fa_amadey-5.70_relations-ips.jpg` | Contacted domains + IPs: `91.92.243.129` (AS202412), `203.6.149.147` (AS55684, ID) |
| `vt_file_d7a366fa_amadey-5.70_behavior-summary.jpg` | Sandbox summary: tags *persistence*, *obfuscated*; ATT&CK Scheduled Task/Job (T1053), Stealth (TA0005) |
| `vt_ip_91.92.243.129_amadey-c2.jpg` | Trellix Amadey C2 IP: **10/91**, AS202412 Omegatech LTD |

## Shodan — [`shodan/`](shodan/)

| File | Shows |
|---|---|
| `shodan_158.94.208.130_stealc-c2_live.jpg` | Former StealC C2 — live, ports 22/80/135/443/445/3389/9090, hostname `natureofarizona.com` |
| `shodan_91.92.243.129_amadey-c2_live.jpg` | Amadey C2 IP — live, IIS 10.0 answering 404 |
| `shodan_185.215.113.43_amadey-c2_no-data.jpg` | Talos Amadey C2 — *no information* (range withdrawn from BGP) |
| `shodan_185.156.73.73_no-data.jpg` | Talos network IOC — *no information* |

## Maltego — [`maltego/`](maltego/) (2026-10-03, Maltego Graph (Desktop) 4.13.0 CE)

| File | Shows |
|---|---|
| `maltego_01_amadey-graph_53-entities_60-links.png` | Full graph exported from Maltego (Organic layout): reports + VT pivots + transform results — sinkholed C2 domain (`microsoftinternetsafety.net` NS), compromised GitLab → university mail server, AS202412 pivot to the StealC C2 |
| `maltego_02_ui_graph-legend_transform-log.jpg` | Maltego UI: entity-type legend, selected IPs, transform log (*To Location … 7 entities returned*, 0 credits used) |
| `maltego_03_run-transform_reverse-dns_7-ips.jpg` | Running *To DNS Name [Reverse DNS]* on the 7 selected IPv4 entities |

Graph source: [`../data/amadey_graph.mtgx`](../data/amadey_graph.mtgx) (built by `scripts/build_maltego_graph.py`); enriched graph: [`../data/amadey_graph_enriched.mtgl`](../data/amadey_graph_enriched.mtgl).

Rules: no API keys or account names in screenshots.
