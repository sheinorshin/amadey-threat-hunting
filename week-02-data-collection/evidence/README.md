# Evidence (screenshots for the defense)

Put screenshots here with these names, then they show up in the docs and you can open them during the defense.

| File name | What to capture | How |
|---|---|---|
| `vt_d7a366fa_detection.png` | VirusTotal page of the Amadey 5.70 loader — detection ratio + threat label | Search `d7a366fa4d31c901ce3bcb6760d7bb5aa7cab49bb54d8c6551b3df14c8cf64e7` |
| `vt_d7a366fa_behavior.png` | **Behavior** tab — scheduled task / process tree / mutex | Same page → Behavior |
| `vt_d7a366fa_relations.png` | **Relations** tab — contacted IPs/URLs | Same page → Relations |
| `vt_91.92.243.129.png` | IP report of the Trellix C2 | Search the IP |
| `vt_results_csv.png` | Terminal output of `scripts/vt_lookup.py` | Run the script with your API key |
| `shodan_158.94.208.130.png` | Shodan host page (ports, hostname, banners) | `shodan.io/host/158.94.208.130` |
| `shodan_internetdb_run.png` | Output of `scripts/shodan_lookup.py --internetdb` | Run the script (no key) |
| `maltego_graph.png` | Maltego graph after import + transforms | `data/maltego_graph_import.csv` → transforms |

Rules: never screenshot your API keys; blur personal account names if needed.
