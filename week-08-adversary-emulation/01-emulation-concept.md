# 1. What an adversary emulation plan is

An **adversary emulation plan** copies the steps of a real attacker, in order, using safe test actions, so a defender can check if they would see and stop each step. It is a purple-team exercise: red side runs the steps, blue side (me) reads the logs.

Difference from Week 9: an atomic test checks **one** technique on its own. An emulation plan chains several techniques into **one story** (an attacker's full path from getting in to stealing data).

## MITRE CALDERA (the reading)

CALDERA is MITRE's open-source tool that automates emulation:
- An **ability** = one action mapped to an ATT&CK technique (like an atomic test).
- An **adversary profile** = a list of abilities run in order.
- An **operation** = running a profile against machines that have the CALDERA agent.

I describe the plan so it can be run either with **Atomic Red Team** tests (what I already set up in Week 9) or as a **CALDERA profile** of the same abilities. Both are public and safe.

## Why Amadey

The plan follows the Amadey → StealC chain I analysed in Week 4 (kill chain) and tested per technique in Week 9. Here I put the techniques together as one attack, from initial access to exfiltration, which is what the syllabus asks for.

## Safety

- Isolated lab VM only, snapshot before, revert after.
- The "stolen" file is a **dummy text file I create myself** (`C:\ith-lab\loot\test-data.txt` with fake lines) — no real or personal data.
- Exfiltration goes to a **lab-local web server**, never the internet.
- Every step is a published Atomic Red Team test or CALDERA ability with a cleanup command.
- Defender stays on. No step turns off logging or security tools.

Sources: MITRE CALDERA — https://caldera.mitre.org/ · Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
