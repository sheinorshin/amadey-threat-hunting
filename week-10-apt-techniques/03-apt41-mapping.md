# 3. APT41 (G0096) — TTPs mapped to ATT&CK v19.2

> **Syllabus task:** *analyse the TTPs used by … APT41 and map them to MITRE ATT&CK.*
> Data: [`data/apt_profiles.json`](data/apt_profiles.json) · full table by tactic: [`data/ttp_tables.md`](data/ttp_tables.md) · Navigator: [`navigator/apt41_layer.json`](navigator/apt41_layer.json) ([open in the Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fsheinorshin%2Famadey-threat-hunting%2Fmain%2Fweek-10-apt-techniques%2Fnavigator%2Fapt41_layer.json)).
> Every technique ID and procedure below comes from ATT&CK v19.2.

## 3.1 Identity card

| | |
|---|---|
| ATT&CK | **G0096**, page modified 2026-07-31 |
| Assessment | **Chinese state-sponsored espionage** group that **also runs financially motivated operations**; overlaps at least partly with BARIUM and Winnti Group |
| Active since | at least 2012 |
| Targets | healthcare, telecom, technology, finance, education, retail and video-game industries in **14 countries** |
| Names | Wicked Panda (CrowdStrike), Brass Typhoon / BARIUM (Microsoft) |
| Campaigns in ATT&CK | **C0017** (2021-05 → 2022-02): at least **six US state government networks** via vulnerable internet-facing web applications, incl. zero-days, some victims re-compromised (29 techniques, 13 not on the group page) · **C0040 APT41 DUST** (2023-01 → 2024-06): shipping, logistics and media in Europe, Asia, Middle East; DUSTPAN / DUSTTRAP (23 techniques, 13 new) |
| Software | 32 entries: PlugX, ShadowPad, Winnti for Linux, KEYPLUG, DUSTPAN, DUSTTRAP, MESSAGETAP, China Chopper, ASPXSpy, Cobalt Strike, Empire, PowerSploit, Mimikatz, certutil, BITSAdmin … |
| **Techniques** | **105** = 82 on the group page + **23 only through its campaigns** |
| Platforms | Windows 92 · Linux/macOS 70 · ESXi 40 · Network Devices 27 · IaaS 14 — much less cloud/identity than APT29 |

## 3.2 Tactic profile

| Tactic | # | Most characteristic techniques (procedure from ATT&CK) |
|---|---|---|
| Reconnaissance | 5 | T1595.002 Acunetix, JexBoss · T1595.003 directory brute force · T1596.005 **fofa** (Chinese Shodan-like search) · T1593.002 / T1594 research of victim servers (DUST) |
| Resource Development | 4 | T1588.002 Mimikatz, pwdump, PowerSploit · T1588.003 stolen code-signing certificates · T1583.007 Cloudflare Workers · T1586.003 compromised Google Workspace accounts |
| Initial Access | 5 | **T1190** CVE-2019-19781 (Citrix), CVE-2020-10189 (Zoho ManageEngine), ViewState deserialization (C0017) · **T1195.002** malicious code in legitimate *signed* files · T1566.001 `.chm` attachments · T1133 VPN between a service provider and the target |
| Execution | 12 | T1059.001 / .003 / .004 / .007 PowerShell, `cmd /c`, Linux shell, JScript web shells · T1047 WMIEXEC · T1569.002 service execution · T1203 Office exploits (CVE-2017-11882 …) |
| Persistence | 13 | T1505.003 web shells (JScript, ANTSWORD, BLUEBEAM) · T1053.005 tasks named `\Microsoft\Windows\PLA\Server Manager Performance Monitor`, `\Microsoft\Windows\WDI\USOShared` … · T1543.003 services such as `Windows Defend`, `StorSyncSvc` · **T1542.003 MBR bootkit** · T1546.008 sticky keys |
| Privilege Escalation | 10 | T1134 BADPOTATO named-pipe impersonation → SYSTEM (C0017) · T1078 compromised credentials · T1098.007 accounts added to Admin group |
| Stealth | **21** | T1027 VMProtect, T1027.002 Themida, T1027.013 encrypted payloads run in memory · T1036.005 files named like antivirus software · T1480.001 payloads keyed with DPAPI to one machine · T1014 Linux rootkits · T1055 injection into `iexplore.exe` · T1574.001 DLL search-order hijacking / side-loading · T1197 BITS jobs |
| Defense Impairment | 6 | **T1685 custom ETW bypass** ("invisible to Windows logging") · **T1685.005 cleared Security and System logs** · T1484.001 tasks deployed via GPO · T1553.002 malware signed with stolen certificates |
| Credential Access | 7 | T1003.001 Mimikatz, Procdump, WCE · T1003.002 SAM via `reg save` · **T1003.003 `ntdsutil` → ntds.dit** · T1056.001 keylogger · T1555.003 BrowserGhost |
| Discovery | 13 | `net`, `whoami`, `systeminfo`, `netstat`, `net share` (T1087.001/.002, T1033, T1082, T1049, T1135) · T1046 WIDETONE port scans · T1018 MiPing |
| Lateral Movement | 4 | T1021.001 RDP + NATBypass · T1021.002 admin shares + WMI · T1550.002 pass the hash · T1570 lateral tool transfer |
| Collection | 8 | T1213.006 Oracle databases with SQLULDR2 · T1074.001 CSV staging · T1560.001 RAR / makecab · T1119 automated collection |
| Command and Control | 12 | T1102.001 **dead drop resolvers** (GitHub, Pastebin, TechNet) · T1102 Google Workspace accounts · T1568.002 **monthly DGA** · T1071.004 DNS C2 · T1008 Steam page as fallback · T1090 CLASSFON proxy |
| Exfiltration | 5 | T1048.003 data **encoded into DNS subdomains** · T1567.002 OneDrive · T1567 Cloudflare · T1030 fixed-size chunks |
| Impact | 2 | **T1486** Encryptor RaaS, BitLocker, BestCrypt · **T1496.001** Monero mining — the financial side |

APT41's heaviest tactic is **Stealth (21)**: packers, signed malware, rootkits, a bootkit, DPAPI-keyed payloads. It is also the only one of the two APTs with **Impact**, because its profile mixes espionage and crime.

## 3.3 C0017 + APT41 DUST along Mandiant's Attack Lifecycle

| Stage | What APT41 did | Techniques |
|---|---|---|
| Initial Recon | scanners and fofa against victim web servers | T1595.002, T1595.003, T1596.005 |
| Initial Compromise | exploit internet-facing web apps (deserialization, Citrix, Zoho), sometimes zero-days | T1190 |
| Establish Foothold | JScript web shell via malicious ViewState → `certutil` (via web shell) downloads the DUSTPAN dropper → DLL side-loading of DUSTTRAP → services and tasks with Windows-like names | T1505.003, T1105, T1574.001, T1543.003, T1053.005, T1036.004 |
| Escalate Privileges | BADPOTATO → SYSTEM; Mimikatz, `reg save`, `ntdsutil` | T1134, T1003.001/.002/.003 |
| Internal Recon | built-in `net` / `whoami` / `systeminfo`; port scans | T1087.001, T1087.002, T1033, T1082, T1046 |
| Move Laterally | RDP (exposed with NATBypass), admin shares, pass the hash | T1021.001, T1021.002, T1550.002 |
| Maintain Presence | **re-compromise** after clean-up (C0017); C2 behind Cloudflare and Google Workspace; ETW bypass, log clearing | T1102, T1583.007, T1685, T1685.005 |
| Complete Mission | Oracle data → CSV → archive → OneDrive / DNS exfiltration; or ransomware / mining | T1213.006, T1074.001, T1560.001, T1567.002, T1048.003, T1486, T1496.001 |

The pattern: APT41 **starts on servers** (web apps, VPN, edge devices). APT29 and Amadey start on users (phishing, a trojanised update). CrowdStrike's 2026 numbers fit this ([`01`](01-apt-concepts.md) §1.3): China-nexus activity +38 %, 40 % of exploitation aimed at internet-facing edge devices.

## 3.4 What my lab can see of APT41

| Status | # of 105 | Examples |
|---|---|---|
| RULE | 1 | T1053.005 (Week 7) |
| HUNT | 5 | T1059.001, T1059.007, T1105 (Week 5 H1) · T1021.001, T1136.001 (Week 5 H3) |
| DATA | 35 | T1036.004/.005, T1087.001/.002, T1069, T1082, T1033 (`net`, `whoami`, `systeminfo` in 4688), T1685.005 (Security **1102**), T1505.003, T1197 BITS, T1110, T1550.002 |
| SYSMON | 50 | T1574.001 DLL side-loading (Sysmon 7), T1543.003 services, T1003.001 LSASS access (Sysmon 10), T1055, T1071.004 DNS (Sysmon 22), T1190 |
| BLIND | 1 | T1484.001 GPO modification (needs domain-controller auditing) |
| OUT | 4 | T1059.004 Unix shell, T1574.006 LD_PRELOAD, T1213.003 Git repos, T1599 network boundary bridging |
| CTI | 9 | T1595.002/.003, T1596.005, T1583.007, T1586.003, T1588.002/.003 … |

**Three findings specific to APT41:**

1. **APT41 needs Sysmon more than any other actor here**: 50 of 105 techniques (48 %) wait for it. DLL side-loading, service persistence, LSASS access and DNS C2 are APT41's core, and all need Sysmon events 7 / 10 / 13 / 22. Installing Sysmon was already priority #2 in Week 4. APT41 makes it #1.
2. **One generic rule would cover APT41's first step after exploitation**: a **web-server process starting a shell or LOLBin** (`w3wp.exe` / Java / Tomcat → `cmd.exe`, `powershell.exe`, `certutil.exe`). That is 4688 parent/child data I already have. My Week 5 H1 parent list (`wscript`, `cscript`, `mshta`, `wmic`, `regsvr32`) has no web-server parents, because Amadey starts on the desktop. Adding them is a small change with a large effect on T1190 → T1505.003 → T1105.
3. **APT41 also disguises task and service names**: `\Microsoft\Windows\WDI\USOShared`, `Windows Defend`. Together with APT29's `EventCacheManager` this rules out a tempting tuning shortcut: **never allow-list tasks or services by a `\Microsoft\Windows\` name prefix.** My Week 7 rule checks the task's *action* rather than its name, which is the right choice. A second rule on *new* tasks under `\Microsoft\Windows\` created by a non-system account would add the name angle ([`04`](04-comparison-and-priorities.md) §4.6).
