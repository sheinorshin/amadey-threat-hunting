# 3. Implementing it in Elastic

## How the original works

Part A: `schtasks /create` or `/change` with a "suspicious" word in the command line.
Part B: event 4698 / 4702 with a "suspicious" word in the task XML.
Suspicious words: extensions (`.exe`, `.bat`, …), tools (`powershell`, `cmd`, …) and user folders (`AppData`, `Temp`, `Users\Public`, …).

## Problems I found

1. `.exe` and `cmd` count as suspicious, so almost every normal task triggers it.
2. The Elastic query searches `*SCHTASKS*` in capitals, and Elastic is case-sensitive, so it misses `schtasks.exe /Create`.
3. CAR has no "task" object in its data model, so part B had to be mapped by hand.
4. Amadey v5's folder (`C:\Users\<user>\<hex>\`) is not in the list.
5. Windows Defender's tasks in `ProgramData` would give false alarms.

## My version

The rule fires when the task's program is:
- in a user-writable folder (except the Defender folder), or
- directly in a user profile folder (Amadey v5), or
- a tool like cmd/powershell that runs every minute.

Severity is high when the task repeats every minute.

## In Kibana

- Sigma rules: [`sigma/`](sigma/) → converted by [`scripts/build_rules.py`](scripts/build_rules.py) to EQL ([`queries/`](queries/)), which ignores case.
- Import [`rules/car_2021_12_001_tuned.ndjson`](rules/car_2021_12_001_tuned.ndjson) in Security → Rules → Import rules. You get 2 rules (task event and schtasks process) with ATT&CK mapping and triage steps.
- Before turning them on, run [`queries/car_noise_last_30_days.esql`](queries/car_noise_last_30_days.esql) to see how many alerts each version would give in my lab.
- [`queries/car_tuned_hunt.esql`](queries/car_tuned_hunt.esql) searches old data with the same logic.
