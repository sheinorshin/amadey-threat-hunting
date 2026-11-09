# 4. Comparison and what to build next

Data: [`data/comparison.json`](data/comparison.json) · figures: [`figures/`](figures/) · layers: [`navigator/`](navigator/)

## APT29 vs APT41

- They share 40 techniques.
- Jaccard similarity: 0.22 at sub-technique level, 0.49 at parent level. So they do similar things (tasks, PowerShell, RDP, password dumping) in different ways.
- APT29 is strongest in credentials and cloud; APT41 in stealth (packers, rootkits).

## Compared with Amadey

| Group | Similarity to Amadey |
|---|---|
| TA505 | 0.30 |
| Kimsuky | 0.22 |
| APT41 | 0.18 |
| APT29 | 0.13 |
| APT1 | 0.10 |

Amadey is closest to TA505 and Kimsuky — exactly the groups ATT&CK lists as its users.

7 techniques are used by all five (APT29, APT41, TA505, Kimsuky, Amadey): PowerShell, tool download, web C2, decoding, rundll32, browser passwords, phishing attachment.

7 of APT1's 23 techniques from 2013 are still used by both APTs (phishing, RDP, cmd, archiving).

## My lab coverage (APT29 + APT41 = 184 techniques)

- Visible now: 64 (35 %)
- Visible with Sysmon: 141 (77 %)
- Not Windows (cloud etc.): 17
- This is an estimate from ATT&CK's analytics, not a measurement. My Week 9 tests measure the important ones.

My Week 3/5/7 rules are tagged with 11 of the APTs' techniques, but only 6 would really fire — the others only match Amadey's files.

## Rules to build next

1. Alert on `auditpol` disabling logs, log cleared (1102) and audit policy change (4719).
2. Web server starting cmd/powershell.
3. New or changed tasks under `\Microsoft\Windows\` by a normal user.
4. Many discovery commands (`net`, `whoami`, `systeminfo`) in 5 minutes.
5. Password spraying: failed logons (4625) for 10+ accounts from one source.
6. Install Sysmon.

Rules 1–5 use logs I already have.
