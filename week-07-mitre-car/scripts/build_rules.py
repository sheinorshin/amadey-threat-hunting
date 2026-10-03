#!/usr/bin/env python3
"""
build_rules.py - Week 7: Sigma (source of truth) -> Elastic EQL -> importable Kibana detection rules.

  sigma/*.yml  --pySigma EQL backend + sigma/pipelines/elastic_agent_windows_security.yml-->  queries/<rule>.eql
  queries/*.eql  -->  rules/car_2021_12_001_tuned.ndjson   (Kibana: Security -> Rules -> Import)

Post-processing of the EQL text (same idea as week-03 convert_sigma.py):
  - pySigma writes regex~ "(?i)...": EQL's regex~ is already case-insensitive and the Lucene regex engine behind
    it does not support inline flags, so "(?i)" is removed;
  - pySigma escapes "/" as "\\/" inside regexes; "/" is not special in Lucene regex, so the escape is removed.

    pip install sigma-cli pySigma-backend-elasticsearch
    python build_rules.py
"""
import json
import uuid
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

HERE = Path(__file__).resolve().parent
WEEK = HERE.parent
SIGMA = WEEK / "sigma"
NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")   # URL namespace -> deterministic rule_id

INDEX = {"win_security": ["logs-system.security-*"],
         "proc_creation": ["logs-system.security-*", "logs-windows.sysmon_operational-*"]}
THREAT = [{
    "framework": "MITRE ATT&CK",
    "tactic": {"id": tid, "name": name, "reference": f"https://attack.mitre.org/tactics/{tid}/"},
    "technique": [{"id": "T1053", "name": "Scheduled Task/Job", "reference": "https://attack.mitre.org/techniques/T1053/",
                   "subtechnique": [{"id": "T1053.005", "name": "Scheduled Task",
                                     "reference": "https://attack.mitre.org/techniques/T1053/005/"}]}],
} for tid, name in [("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation")]]

NOTE = """## Triage (CAR-2021-12-001, tuned for Amadey)

1. Read the task's action (`winlog.event_data.TaskContent` -> `<Command>` / `<Arguments>`, or the schtasks `/TR`).
   Is the program in AppData, Temp, Users\\Public, ProgramData or directly in a user-profile folder?
2. Every-minute repetition (`PT1M`, `/SC MINUTE /MO 1`) + random lowercase name equal to the EXE name = Amadey pattern.
3. Hash the action's file and look it up (VirusTotal / MISP event #1); check its signer.
4. Pivot on the host: process tree of the creator (schtasks.exe parent, or no schtasks at all = API/COM),
   rundll32 `..., Main` plugins, outbound POST to `/<random>/index.php`.
5. Benign? Allow-list by task name + signer (per-user updaters under AppData), not by folder.
"""


def eql_text(rule_file, pipeline):
    q = "\n".join(EqlBackend(pipeline).convert(SigmaCollection.from_yaml(rule_file.read_text(encoding="utf-8"))))
    return q.replace('regex~ "(?i)', 'regex~ "').replace("\\/", "/")


def kibana_rule(rule_file, query):
    r = SigmaCollection.from_yaml(rule_file.read_text(encoding="utf-8")).rules[0]
    kind = "win_security" if rule_file.name.startswith("win_security") else "proc_creation"
    return {
        "rule_id": str(uuid.uuid5(NS, f"amadey-threat-hunting/week-07/{rule_file.stem}")),
        "name": r.title,
        "description": r.description.strip(),
        "type": "eql", "language": "eql", "query": query,
        "index": INDEX[kind],
        "severity": "medium", "risk_score": 47,
        "severity_mapping": [], "risk_score_mapping": [],
        "interval": "5m", "from": "now-6m", "max_signals": 100,
        "enabled": False,
        "author": ["Sayat Abdiraiym (AITU, Intro to Threat Hunting)"],
        "references": [str(x) for x in r.references],
        "false_positives": list(r.falsepositives),
        "tags": ["Amadey", "MITRE CAR", "CAR-2021-12-001", "T1053.005", "Week 7"],
        "threat": THREAT,
        "note": NOTE,
        "version": 1,
    }


def main():
    pipeline = ProcessingPipeline.from_yaml((SIGMA / "pipelines" / "elastic_agent_windows_security.yml").read_text())
    (WEEK / "queries").mkdir(exist_ok=True)
    (WEEK / "rules").mkdir(exist_ok=True)
    lines = []
    for f in sorted(SIGMA.glob("*.yml")):
        q = eql_text(f, pipeline)
        (WEEK / "queries" / f"{f.stem}.eql").write_text(q + "\n", encoding="utf-8")
        lines.append(json.dumps(kibana_rule(f, q), ensure_ascii=False))
        print(f"{f.name:72} -> queries/{f.stem}.eql")
    (WEEK / "rules" / "car_2021_12_001_tuned.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(lines)} Kibana rules -> rules/car_2021_12_001_tuned.ndjson (imported disabled; enable after review)")


if __name__ == "__main__":
    main()
