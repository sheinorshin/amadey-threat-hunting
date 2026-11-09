# Evidence — hunts run in Elasticsearch (Kali/Docker)

The synthetic ECS dataset loaded into a local Elasticsearch (see `lab/`) and the three hunt queries run against it.

| File | Shows |
|---|---|
| `w5_01_data_loaded_976_elasticsearch.png` | `lab/load_synthetic.py` — 976 events indexed (856 Security + 120 PowerShell) |
| `w5_02_hunts_h1_h2_h3_elasticsearch.png` | H1 (mshta→powershell), H2 (`Yfgfwb.exe` in a 10-hex folder), H3 (new admin `sysupd$` → Administrators) returning the planted Amadey intrusion |
