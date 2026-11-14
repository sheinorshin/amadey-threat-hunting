# 1. Atomic Red Team

Atomic Red Team is a free library of small tests made by Red Canary. Each test ("atomic") does one ATT&CK technique in a few commands, so I can check if my SIEM sees it and if a rule fires.

- Tests are YAML files, one folder per technique (`atomics/T1105/T1105.yaml`).
- Each test has a number, a GUID, commands, a cleanup command and prerequisites.
- **Invoke-AtomicRedTeam** (PowerShell) shows, runs and cleans up the tests and writes an execution log (CSV). I use this log as the record of what ran and when.

Difference from an emulation plan (Week 8): an atomic tests one technique alone; an emulation plan chains many techniques into one attacker's story.

For grading I use the ATT&CK Evaluations levels: None, Telemetry, General, Tactic, Technique.

## How I installed it (Kali)

```powershell
pwsh
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing); Install-AtomicsFolder
Import-Module invoke-atomicredteam
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="$HOME/AtomicRedTeam/atomics"}
```

Main commands: `-ShowDetails` (read a test), `-CheckPrereqs`, `-GetPrereqs`, `-TestNumbers`, `-ExecutionLogPath`, `-Cleanup`.

## Safety rules

- Only on my own lab VM.
- Read each test with `-ShowDetails` before running it.
- Skip tests that turn off logging or security tools.
- One test at a time, then run its cleanup.

Sources: https://atomicredteam.io · https://github.com/redcanaryco/atomic-red-team · https://github.com/redcanaryco/invoke-atomicredteam
