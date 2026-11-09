# 2. APT29 (G0016) mapped to ATT&CK

Full table: [`data/ttp_tables.md`](data/ttp_tables.md) · layer: [`navigator/apt29_layer.json`](navigator/apt29_layer.json)

## About

- Russia's foreign intelligence service (SVR), active since at least 2008.
- Targets governments, NATO countries, research institutes, think tanks.
- Also called Cozy Bear, Midnight Blizzard, NOBELIUM.
- Campaigns: SolarWinds Compromise (C0024), Operation Ghost (C0023).
- 119 techniques: 66 on the group page + 53 only from campaigns.

## Techniques by tactic (main examples)

| Tactic | # | Examples |
|---|---|---|
| Initial Access | 11 | T1195.002 SolarWinds supply chain, T1190 public exploits, T1566 phishing |
| Execution | 11 | T1059.001 PowerShell, T1047 WMI |
| Persistence | 18 | T1053.005 scheduled tasks, T1546.003 WMI events, T1098 extra cloud credentials |
| Privilege Escalation | 17 | T1548.002 UAC bypass, T1078.004 cloud admin accounts |
| Stealth | 17 | T1036.004 task named like a Windows task, T1027.006 HTML smuggling |
| Defense Impairment | 8 | T1685.001 `auditpol` to stop logging, T1686 firewall rules |
| Credential Access | 16 | T1003.006 DCSync, T1558.003 Kerberoasting, T1606.002 forged SAML tokens |
| Discovery | 11 | AdFind, `Get-ADUser` |
| Lateral Movement | 8 | T1021.001 RDP, T1021.006 WinRM |
| Collection | 6 | T1114.002 mailboxes, T1560.001 7-Zip archives |
| Command and Control | 11 | T1071.001 HTTPS, T1090.003 Tor |
| Exfiltration | 1 | T1048.002 over HTTPS |
| Impact | 0 | — (spying only) |

## SolarWinds in short

Put malware into the SolarWinds Orion update → C2 over HTTP → stole credentials (Kerberoasting, AD FS keys) → moved with RDP/WinRM → turned off audit logs → forged SAML tokens to read mailboxes → zipped and downloaded data.

After getting in, APT29 mostly uses admin tools and stolen accounts, not malware.

## What I found

1. About 16 % of APT29's techniques can't be seen from a Windows PC at all (cloud, identity, domain controller).
2. APT29 turns off logging with `auditpol` — this would blind my other rules.
3. APT29 changes existing normal tasks (event 4702), which my Week 7 rule may miss.
