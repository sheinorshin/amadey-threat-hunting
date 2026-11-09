# 1. APTs and the readings

## What APT means

- Advanced — can build or buy custom tools, but often uses cheap normal tools.
- Persistent — stays inside for a long time and comes back after cleanup.
- Threat — real people with a mission, usually a state.

Amadey is crimeware sold to anyone, but ATT&CK lists two groups using it: TA505 (money) and Kimsuky (North Korea). So the difference between APT and crime is mostly who and why; the techniques are often the same.

## Reading 1 — Mandiant APT1 (2013)

- First report that linked a hacking group to a real military unit: PLA Unit 61398 in Shanghai.
- 141 victims in 20 industries; on average 356 days inside a victim (longest 1,764).
- 3,000+ indicators were published.
- It introduced the **Attack Lifecycle**: recon → compromise → foothold → escalate → internal recon → move laterally → maintain presence → complete mission. Unlike the Kill Chain (Week 4), it has a loop, which fits how APTs move around a network.

## Reading 2 — CrowdStrike Global Threat Report 2026

- Average breakout time 29 minutes (fastest 27 seconds), so detection must be fast and automatic.
- China-nexus activity +38 %, many attacks on edge devices — fits APT41.
- State actors in the cloud +266 % — fits APT29.
- North Korea incidents +130 % — Kimsuky is part of this.

## Group names

Vendors give the same group different names, e.g. APT29 = Cozy Bear = Midnight Blizzard = NOBELIUM; APT41 = Wicked Panda = Brass Typhoon.

## Method

A script takes every technique ATT&CK v19.2 links to each group and its campaigns, checks the IDs are current, and groups them by tactic. Software is kept separate, because a tool's page lists everything it can do, not what the group did.

Sources: https://attack.mitre.org/groups/G0016/ · https://attack.mitre.org/groups/G0096/ · Mandiant APT1 report · CrowdStrike 2026 GTR press release
