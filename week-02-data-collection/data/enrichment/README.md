# Enrichment snapshot (2026-10-02)

Passive, registry-level enrichment of the network IOCs collected in `../raw/`. No connection was made to any malicious host.

| Tool | Endpoint | Key needed |
|---|---|---|
| RIPEstat whois | `https://stat.ripe.net/data/whois/data.json?resource=<ip>` | no |
| RIPEstat AS overview | `https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>` | no |
| RIPEstat routing status | `https://stat.ripe.net/data/routing-status/data.json?resource=<prefix>` | no |
| Shodan InternetDB | `https://internetdb.shodan.io/<ip>` | no |

Reproduce with `../../scripts/ripestat_enrich.py` and `../../scripts/shodan_lookup.py --internetdb`.
