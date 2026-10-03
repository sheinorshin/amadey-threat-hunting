# 2. APT29 (G0016) — TTPs mapped to ATT&CK v19.2

> **Syllabus task:** *analyse the TTPs used by APT29 … and map them to MITRE ATT&CK.*
> Data: [`data/apt_profiles.json`](data/apt_profiles.json) (every technique with its ATT&CK procedure text) · full table by tactic: [`data/ttp_tables.md`](data/ttp_tables.md) · Navigator: [`navigator/apt29_layer.json`](navigator/apt29_layer.json) ([open in the Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fsheinorshin%2Famadey-threat-hunting%2Fmain%2Fweek-10-apt-techniques%2Fnavigator%2Fapt29_layer.json)).
> Every technique ID and procedure below comes from ATT&CK v19.2. Lab statuses (RULE/HUNT/DATA/SYSMON/BLIND/OUT/CTI) are explained in [`04`](04-comparison-and-priorities.md) §4.1.

## 2.1 Identity card

| | |
|---|---|
| ATT&CK | **G0016**, page modified 2026-07-31 |
| Attribution | Russia's **Foreign Intelligence Service (SVR)**; the US and UK governments attributed the SolarWinds Compromise to the SVR in April 2021 |
| Active since | at least 2008 |
| Targets | government networks in Europe and NATO member countries, research institutes, think tanks; the Democratic National Committee from summer 2015 |
| Best-known names | Cozy Bear (CrowdStrike), Midnight Blizzard / NOBELIUM (Microsoft), UNC2452 / UNC3524 (Mandiant), The Dukes (15 aliases, [`01`](01-apt-concepts.md) §1.4) |
| Campaigns in ATT&CK | **C0023 Operation Ghost** (2013-09 → 2019-10, 8 techniques, 6 not on the group page) · **C0024 SolarWinds Compromise** (2019-08 → 2021-01, **71** techniques, **49** not on the group page) |
| Software | 49 entries, e.g. SUNBURST, SUNSPOT, TEARDROP, Raindrop, GoldMax, FoggyWeb, EnvyScout, WellMess, plus Mimikatz, Cobalt Strike, AdFind, Impacket, BloodHound, AADInternals, ROADTools |
| **Techniques** | **119** = 66 on the group page + **53 only through its campaigns** |
| Platforms | Windows 94 · IaaS 29 · Office Suite 27 · SaaS 26 · **Identity Provider 24** · Network Devices 23 · Linux/macOS 67 |

**First lesson from the data:** without the SolarWinds campaign, APT29's ATT&CK profile loses 53 techniques: DCSync, SAML token forgery, federation-trust changes, WinRM, Kerberoasting, the `auditpol` trick. That is why ATT&CK's group page alone is not enough, and why my script merges group and attributed campaigns.

## 2.2 Tactic profile

| Tactic | # | Most characteristic techniques (procedure from ATT&CK) |
|---|---|---|
| Reconnaissance | 2 | T1589.001 credentials gathered for access (C0024) · T1595.002 wide vulnerability scanning |
| Resource Development | 9 | T1583.001 / T1584.001 domains registered or **compromised** for C2 · T1583.006 Twitter handles for HAMMERTOSS C2 · T1586.003 Azure VMs as residential proxies |
| Initial Access | 11 | **T1195.002** trojanised SolarWinds Orion update · T1199 compromised IT/cloud/managed service providers · T1190 Citrix CVE-2019-19781, Pulse Secure, FortiGate, Zimbra · T1133 VPN/Citrix with stolen identities · T1566.001-.003 spearphishing (incl. Constant Contact) |
| Execution | 11 | T1059.001 encoded PowerShell, remote task creation · T1059.003 `cmd.exe` on remote machines · T1047 WMI · T1059.009 Microsoft Graph API · T1651 Azure Run Command |
| Persistence | **18** | T1053.005 named and **hijacked** scheduled tasks · T1546.003 WMI event subscriptions · T1547.001 Run keys · T1505.003 web shells on Exchange · T1098.001/.003/.005 extra cloud credentials, roles, **own MFA device** · T1556.007 malicious DLL in AD FS |
| Privilege Escalation | 17 | T1548.002 UAC bypass · T1068 CVE-2021-36934 · T1078.004 Azure AD global admin · T1484.002 federation trust modification |
| Stealth | 17 | T1036.004 task named `\Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager` · T1027.006 HTML smuggling · T1027.001 binary padding against scanner size limits · T1070.006 timestomping web shells · T1078.002/.003 stolen and dormant accounts |
| Defense Impairment | 8 | **T1685.001 `auditpol` to stop audit logging** · T1685 security services disabled via the service control manager · T1685.002 Purview Audit disabled · T1686 `netsh` firewall rules · T1553.005 ISO/VHDX to escape Mark-of-the-Web · T1553.002 SUNBURST signed with SolarWinds' certificate |
| Credential Access | **16** | T1003.006 **DCSync** · T1003.002/.004 `reg save` of SAM/LSA hives · T1558.003 Kerberoasting · T1606.001/.002 **forged web cookies and SAML tokens** · T1552.004 AD FS private keys · T1555.003 Chrome passwords · T1621 MFA fatigue · T1110.003 password spraying · T1649 AD CS abuse |
| Discovery | 11 | AdFind for T1018 / T1069.002 · `Get-ADUser`, `Get-ManagementRoleAssignment`, `Get-AcceptedDomain` (T1087.002, T1069, T1482) · T1680 `fsutil` free-space check |
| Lateral Movement | 8 | T1021.001 RDP · T1021.002 SMB with admin accounts · T1021.006 WinRM via PowerShell · T1550 forged SAML tokens · T1550.003 pass the ticket · T1021.007 on-prem accounts synced to Office 365 |
| Collection | 6 | **T1114.002 mailbox collection** via EWS and compromised Exchange · T1213 internal wikis · T1213.003 source code · T1560.001 7-Zip password-protected archives |
| Command and Control | 11 | T1071.001 HTTP(S) · T1090.003 Tor hidden service, T1090.004 meek domain fronting · T1102.002 social media · T1001.002 steganography · T1568 dynamic DNS |
| Exfiltration | 1 | T1048.002 HTTPS download of an archive staged on the victim's OWA server |
| Impact | 0 | none: the mission is to collect information, not to destroy anything |

Figure: [`figures/tactic_profile.png`](figures/tactic_profile.png). APT29 has the heaviest **Credential Access + Persistence + Privilege Escalation** block of all six actors I compare, and **no Impact**.

## 2.3 The SolarWinds Compromise along Mandiant's Attack Lifecycle

| Stage | What APT29 did (ATT&CK procedures, C0024 unless noted) | Techniques |
|---|---|---|
| Initial Recon | stole credentials for later access; registered and compromised domains for C2 | T1589.001, T1583.001, T1584.001 |
| Initial Compromise | SUNBURST injected into the Orion **build** (SUNSPOT), shipped as a signed update; elsewhere stolen VPN/Citrix identities and public exploits | T1195.002, T1553.002, T1133, T1190 |
| Establish Foothold | SUNBURST's HTTP C2; TEARDROP / Raindrop loaders decoded with 7-Zip; task for SUNSPOT at boot; WMI event filter → `rundll32` backdoor | T1071.001, T1140, T1053.005, T1546.003, T1218.011 |
| Escalate Privileges | Kerberoasting; gMSA passwords; Chrome passwords and cookies; AD FS private keys | T1558.003, T1555, T1555.003, T1539, T1552.004 |
| Internal Recon | AdFind; `Get-ADUser`; Exchange role and domain cmdlets | T1018, T1069.002, T1087.002, T1482 |
| Move Laterally | RDP from public-facing systems; SMB with admin accounts; WinRM; **hijack a legitimate scheduled task, run the tool, put the task back** | T1021.001/.002/.006, T1053.005 |
| Maintain Presence | `auditpol` to stop audit logging; legitimate utilities temporarily replaced; SDelete; extra credentials on OAuth apps and service principals; federation trust changed | T1685.001, T1070, T1070.004, T1098.001, T1484.002 |
| Complete Mission | **forged SAML tokens** bypass MFA → mailboxes, wikis, source code → 7-Zip archives staged on OWA → HTTPS download | T1606.002, T1114.002, T1213, T1560.001, T1074.002, T1048.002 |

The pattern: **after initial access almost nothing is malware**. APT29 uses admin tools, PowerShell, legitimate protocols and stolen identities. Signatures and IOCs see little of this. Behaviour and identity telemetry see more.

## 2.4 What my lab can see of APT29

From [`04`](04-comparison-and-priorities.md) (automatic estimate, same scale as the Week 4 Amadey layer). Layer: [`navigator/apt_lab_coverage_layer.json`](navigator/apt_lab_coverage_layer.json).

| Status | # of 119 | Examples |
|---|---|---|
| RULE (generic rule + data) | 1 | T1053.005 — Week 7 CAR-2021-12-001 rules |
| HUNT (generic hunt + data) | 5 | T1059.001, T1105, T1218.005 (Week 5 H1) · T1021.001, T1686 (Week 5 H3) |
| DATA (logs collected, no rule) | 37 | T1078 / T1110.003 (4624/4625), T1036.004 (4698 task names), T1685.001 (`auditpol` in 4688), T1087.002 / T1069.002 (AdFind, `net`, `Get-ADUser`) |
| SYSMON (needs Sysmon) | 43 | T1546.003 WMI subscriptions, T1047, T1547.001, T1218.011, T1555.003, T1070.004 |
| BLIND (Windows, but no sensor I have) | 8 | T1003.006 DCSync, T1484.002, T1556.007, T1098.005, T1649 AD CS, T1070.006 timestomp, T1665, T1213 |
| OUT (cloud / identity / not Windows) | 14 | T1078.004, T1098.001/.003, T1528, T1550.001/.004, T1059.009, T1651, T1685.002 |
| CTI (PRE) | 11 | T1583.001, T1584.001, T1586.003, T1587.001 … |

**Three findings specific to APT29:**

1. **19 of 119 techniques (16 %) cannot be seen from a Windows endpoint at all.** 14 are not Windows techniques (OUT), and 5 BLIND ones live in identity infrastructure: DCSync, federation trust, AD FS, device registration, AD CS. To see APT29's cloud work you need Entra ID sign-in/audit logs, M365 unified audit logs and domain-controller auditing. My lab has none of these. The CrowdStrike 2026 report's +266 % state-nexus cloud targeting points the same way ([`01`](01-apt-concepts.md) §1.3).
2. **APT29 attacks my telemetry directly.** T1685.001 (`auditpol`) would stop 4688/4698, the two event IDs most of my detections rely on. One alert on `auditpol.exe` with `/set … /success:disable`, plus Security **1102** (log cleared), protects all the others. This is a cheap rule with data I already have (§4.6).
3. **My Week 7 rule would miss APT29's scheduled-task procedure.** APT29 **hijacks an existing legitimate task** (4702 *updated*, not 4698) and names its own tasks like Windows components. The tuned CAR rule fires on 4702 only when the new action is in a user-writable path or is an every-minute interpreter. A tool in a system path, run once and restored, passes. That is the same lesson as Amadey v5 (Week 6): **the procedure, not the technique ID, decides whether a rule fires.**
