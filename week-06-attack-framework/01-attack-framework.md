# 1. ATT&CK basics

ATT&CK is MITRE's database of how real attackers work. It is a matrix: tactics (why) × techniques (how). Procedures show how a specific attacker did it.

ATT&CK v19.2 has 15 tactics, 222 techniques and 475 sub-techniques. In v19, Defense Evasion was split into Stealth and Defense Impairment.

## TTP on my example

- Tactic: Persistence (also Execution and Privilege Escalation)
- Technique: T1053 Scheduled Task/Job
- Sub-technique: T1053.005 Scheduled Task
- Procedure: Amadey makes a task named like its EXE that runs every minute

## Detection in ATT&CK

Since v18, ATT&CK describes detection as: detection strategy → analytic → log source. For T1053.005 this is DET0441 → AN1221 → Security 4698/4702 and Sysmon 1/11/13.

## T1059 (syllabus example)

The syllabus calls it "Command-Line Interface". That is the old name; since ATT&CK v7 (2020) it is **T1059 Command and Scripting Interpreter**. Old T1086 PowerShell became T1059.001.

Sub-techniques Amadey uses:
- T1059.001 PowerShell — Emmenhtal stages, v5 commands
- T1059.003 Windows Command Shell — v5 commands; my lab task also runs `cmd.exe`
- T1059.006 Python — Talos `checkbalance.py`
- T1059.007 JavaScript — Emmenhtal downloader

I studied T1053.005 instead of T1059 because T1059 is very broad (13 sub-techniques), while T1053.005 is Amadey's main persistence. My lab test still uses T1059.001 and T1059.003.

## ATT&CK Navigator

The Navigator shows the matrix. You save your marks (score, colour, comment per technique) in a JSON "layer". I made an expected layer: [`navigator/t1053_005_lab_exercise_layer.json`](navigator/t1053_005_lab_exercise_layer.json). After the lab run, `map_results.py` makes the observed layer, so I can compare the two.

Sources: https://attack.mitre.org/ · https://attack.mitre.org/techniques/T1053/005/ · https://mitre-attack.github.io/attack-navigator/
