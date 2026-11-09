# 1. What CAR is

CAR (Cyber Analytics Repository) is MITRE's library of detection ideas called analytics. Each analytic has a description, ATT&CK mapping, pseudocode, sometimes Splunk/Elastic queries, and a test.

- 102 analytics, last one added in March 2022 (not updated since)
- 5 of its ATT&CK IDs are outdated in ATT&CK v19.2, so I re-checked them

## Data model

CAR writes analytics for an abstract data model: object / action / field, for example `process / create / command_line`. To use it, I map each field to my Elastic field:

- `process/create/exe` → `process.executable`
- `process/create/command_line` → `process.command_line`
- task created (event 4698) → `winlog.event_data.TaskContent` — CAR has no "task" object, so I mapped this myself

## Analytic vs detection

- An **analytic** is a general idea of what to look for. It can be noisy.
- A **detection** is that idea tuned for my own logs, with severity, schedule, exceptions and triage steps, so it gives few false alarms.

You can't just copy a CAR analytic into a SIEM — the original CAR-2021-12-001 flags almost every normal task in my data.

Sources: https://car.mitre.org/ · https://github.com/mitre-attack/car
