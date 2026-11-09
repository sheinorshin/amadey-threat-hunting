# 3. APT41 (G0096) mapped to ATT&CK

Full table: [`data/ttp_tables.md`](data/ttp_tables.md) · layer: [`navigator/apt41_layer.json`](navigator/apt41_layer.json)

## About

- Chinese state-sponsored spying group that also does crime for money; active since at least 2012.
- Targets healthcare, telecom, tech, finance, education, games in 14 countries.
- Also called Wicked Panda, Brass Typhoon, BARIUM.
- Campaigns: C0017 (US state governments via web apps), C0040 APT41 DUST.
- 105 techniques: 82 on the group page + 23 from campaigns.

## Techniques by tactic (main examples)

| Tactic | # | Examples |
|---|---|---|
| Initial Access | 5 | T1190 exploits (Citrix, Zoho), T1195.002 supply chain |
| Execution | 12 | T1059.001 PowerShell, T1059.003 cmd, T1047 WMI |
| Persistence | 13 | T1505.003 web shells, T1053.005 tasks with Windows-like names, T1542.003 bootkit |
| Privilege Escalation | 10 | T1134 token impersonation |
| Stealth | 21 | T1027 packers, T1574.001 DLL side-loading, T1014 rootkits |
| Defense Impairment | 6 | T1685 ETW bypass, T1685.005 cleared logs |
| Credential Access | 7 | T1003.001 Mimikatz, T1003.003 ntds.dit |
| Discovery | 13 | `net`, `whoami`, `systeminfo` |
| Lateral Movement | 4 | T1021.001 RDP, T1550.002 pass the hash |
| Collection | 8 | T1560.001 RAR archives |
| Command and Control | 12 | T1102.001 dead drop (GitHub, Pastebin), T1071.004 DNS |
| Exfiltration | 5 | T1048.003 data in DNS, T1567.002 OneDrive |
| Impact | 2 | T1486 ransomware, T1496.001 crypto mining |

## How APT41 works

It usually starts on servers: exploits a web app or VPN → puts a web shell → downloads tools → steals credentials → moves around. APT29 and Amadey start on users instead (phishing, fake update).

## What I found

1. APT41 needs Sysmon most: 48 % of its techniques need it.
2. One simple rule helps a lot: a web server process (`w3wp.exe`, Java) starting `cmd` or `powershell`.
3. It names tasks like Windows tasks, so I must never trust a task just because its name starts with `\Microsoft\Windows\`.
