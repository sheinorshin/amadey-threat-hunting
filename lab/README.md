# Lab — Elastic + Kibana on Kali (for the hunt queries)

A minimal Elastic stack to run the project's ES|QL hunt and CAR queries on the Week 5 synthetic
dataset. No Windows and no SIEM agents needed; the data is loaded straight into Elasticsearch.

```bash
# once per boot (Elasticsearch needs it)
sudo sysctl -w vm.max_map_count=262144

# start Elasticsearch + Kibana (security off, localhost only)
cd lab
docker compose up -d           # wait ~2 min; Kibana at http://localhost:5601

# load the 976-event synthetic dataset into logs-*-default indices
python3 load_synthetic.py      # expects http://localhost:9200

# ... run queries in Kibana (Discover -> ES|QL), see the screenshot guide ...

docker compose down -v         # stop and wipe
```

In Kibana set the time range to cover **2026-10-01** (the dataset's day), e.g. an absolute range
2026-10-01 → 2026-10-02, or "Last 2 years".

Queries to run (Discover → ES|QL, paste the file contents):
- `week-05-threat-hunting/queries/h1_script_host_powershell.esql` — script host → PowerShell
- `week-05-threat-hunting/queries/h2_hexfolder_minute_task.esql` — hex-folder EXE / every-minute task
- `week-05-threat-hunting/queries/h3_new_admin_firewall.esql` — new admin + firewall rule
- `week-07-mitre-car/queries/car_tuned_hunt.esql` — the tuned CAR rule flags the Amadey task
