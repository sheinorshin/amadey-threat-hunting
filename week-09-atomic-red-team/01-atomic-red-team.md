# 1. Atomic Red Team

Atomic Red Team (Red Canary) is a free library of small tests. Each test ("atomic") does one ATT&CK technique in a few commands, so I can check if my SIEM sees it and if a rule fires.

- Tests are YAML files, one per technique (`atomics/T1053.005/T1053.005.yaml`).
- Each test has commands, a cleanup command and prerequisites.
- **Invoke-AtomicRedTeam** (PowerShell) runs the tests and writes an execution log (CSV). I use this log as the record of what ran and when.

Difference from an emulation plan (Week 8): an atomic tests one technique alone; an emulation plan chains many techniques into one attacker's story.

For grading I use the ATT&CK Evaluations levels: None, Telemetry, General, Tactic, Technique.

## Safety rules

- Only on the isolated lab VM, take a snapshot first.
- Internal network only; downloads come from a lab web server.
- Read each test before running it, no extra third-party programs.
- Defender stays on (a block is also a result).
- Skip tests that turn off logging or security tools.
- One test at a time, 2 minutes apart, run cleanup after.

Sources: https://github.com/redcanaryco/atomic-red-team · https://github.com/redcanaryco/invoke-atomicredteam
