# Evidence — MISP deployment and IOC import (Week 3)

Captured on **2026-10-03** (Asia/Almaty) from my own MISP 2.5.48 instance (`misp-docker` on Docker Desktop, Windows 11).
No API keys or passwords are visible; `admin@admin.test` is only the image's default account name.

| # | File | Shows |
|---|---|---|
| 1 | [`01_docker_misp-stack_all-running.jpg`](misp/01_docker_misp-stack_all-running.jpg) | All 6 containers running: MariaDB, Valkey (Redis), misp-modules, mail, **misp-core**, **misp-nginx** (8080/8443) |
| 2 | [`02_misp-core_log_misp-is-live_2.5.48.jpg`](misp/02_misp-core_log_misp-is-live_2.5.48.jpg) | misp-core log: settings applied, *MISP Version 2.5.48*, *MISP is now live*, PHP-FPM started |
| — | [`troubleshoot_misp-nginx_ssl-cert-missing_restart-loop.jpg`](misp/troubleshoot_misp-nginx_ssl-cert-missing_restart-loop.jpg) | The problem I hit: misp-nginx restart loop *SSL certificate is NOT present* (fixed with a self-signed cert, see [`01-misp-deployment.md` §1.5](../01-misp-deployment.md)) |
| 3 | [`03_events-index_3-events-galaxies-tags.jpg`](misp/03_events-index_3-events-galaxies-tags.jpg) | Event list: #1 consolidated (81 attr.), #2 raw Talos STIX (17), #3 VT pivot leads (7), with clusters and tags |
| 4 | [`04_event1_consolidated_related-13-extended-by-3.jpg`](misp/04_event1_consolidated_related-13-extended-by-3.jpg) | Event #1: TLP + Admiralty tags, *Related Events: Talos event — 13 correlations*, *Extended by event 3* |
| 5 | [`05_event1_galaxies_attack-matrix.jpg`](misp/05_event1_galaxies_attack-matrix.jpg) | Galaxies (S1025, Malpedia Amadey/StealC, 6 techniques) + ATT&CK matrix (v19 columns *Stealth*, *Defense impairment*) |
| 6 | [`06_event1_expired-ips_not-ids_comments.jpg`](misp/06_event1_expired-ips_not-ids_comments.jpg) | `185.215.113.0/24` indicators: **IDS off**, comment *expired 442 days > TTL; infrastructure offline (BGP prefix withdrawn)*, correlations to event 2 |
| 7 | [`07_event1_correlation-graph_event2.jpg`](misp/07_event1_correlation-graph_event2.jpg) | Correlation graph: event 1 ↔ 13 shared hashes/URLs/IPs ↔ event 2 |
| 8 | [`08_event2_talos-stix-raw_tlp-warning.jpg`](misp/08_event2_talos-stix-raw_tlp-warning.jpg) | Raw vendor STIX imported as-is: **MISP warns about the invalid `TLP:WHITE` tag**, galaxy tags left as bare STIX UUIDs, threat level *Undefined* → why normalisation matters |
| 9 | [`09_event3_vt-pivot_extends-event1.jpg`](misp/09_event3_vt-pivot_extends-event1.jpg) | Event #3 (my VirusTotal pivots) **extends** event #1; Admiralty B3 |
| 10 | [`10_event3_vt-pivot_attributes_retro-hunt.jpg`](misp/10_event3_vt-pivot_attributes_retro-hunt.jpg) | New leads (2nd compromised GitLab, its IP, plugin URL) — IDS off, *retro-hunt only* with the reason |
| 11 | [`11_feeds_abuse-ch_cached.jpg`](misp/11_feeds_abuse-ch_cached.jpg) | abuse.ch feeds: Feodo enabled + cached, URLhaus / MalwareBazaar / ThreatFox CSV cached for correlation |
| 12 | [`12_taxonomies_tlp-admiralty_enabled.jpg`](misp/12_taxonomies_tlp-admiralty_enabled.jpg) | Taxonomies `tlp` and `admiralty-scale` enabled |
| 13 | [`13_event1_export-formats.jpg`](misp/13_event1_export-formats.jpg) | *Download as…*: MISP JSON/XML, OpenIOC, CSV, STIX 1/2, RPZ, Suricata, Snort, Bro (Zeek) |
| 14 | [`14_event1_sighting_scheduled-task.jpg`](misp/14_event1_sighting_scheduled-task.jpg) | Sighting added to the scheduled task (confirmed again in the VirusTotal sandbox); MISP stored the path as `%WINDIR%\Tasks\Yfgfwb.job` |
