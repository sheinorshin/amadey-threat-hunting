# 4. Courses of Action — where to break the Amadey chain

> From the Lockheed Martin paper: for every phase choose actions — **Detect, Deny, Disrupt, Degrade, Deceive, Destroy**. The adversary has to win every phase; I only need one solid break, and earlier is cheaper.

## 4.1 Courses of Action matrix for this intrusion

*Lab* column: ✅ = working in my SIEM lab today · ⚠️ = possible after installing Sysmon · ❌ = needs a sensor I don't have (proxy, mail gateway, EDR) · CTI = outside my network.

| Phase | Detect | Deny | Disrupt | Degrade | Deceive | Destroy | Lab |
|---|---|---|---|---|---|---|---|
| 1 Recon | CTI: campaigns against my region/sector (Talos: Ukraine) | Limit public staff/e-mail exposure | — | — | Decoy mailboxes / staff pages | — | CTI |
| 2 Weaponization | CTI: new builds and bot IDs in VirusTotal/MISP, retro-hunts | — | Report abused GitHub repos and hijacked GitLab servers to owners | — | — | Law-enforcement takedown of panels (Operation Endgame, 24 Jun 2026) | CTI |
| 3 Delivery | Mail gateway: archives containing scripts; proxy: `.mp4`/EXE fetched by `mshta` or from raw IPs | Block `.js/.jse/.hta/.lnk` inside archives; block EXE downloads from bare IPs | Sandbox detonation of attachments | Strip or convert attachments | Phishing-report button + decoy inbox | — | ❌ |
| 4 Exploitation | Security 4688: `wscript/cscript/mshta → powershell`; PowerShell 4104 script blocks | ASR rules *Block JavaScript or VBScript from launching downloaded executable content* and *Block execution of potentially obfuscated scripts*; open `.js/.hta` with Notepad by default | AppLocker/WDAC: block `mshta.exe` and `wscript.exe` for standard users | PowerShell Constrained Language Mode | — | — | ✅ data, rule to write |
| 5 Installation | Sigma: EXE in `%TEMP%\<10-hex>\` ✅, task every minute ✅, Startup-folder redirect ⚠️ (Sysmon 13), MotW stream ⚠️ (Sysmon 15) | AppLocker/WDAC: no executables from `%TEMP%`, `%APPDATA%`, `%USERPROFILE%` | Remove task + files, re-image | — | — | — | ✅ / ⚠️ |
| 6 C2 | Proxy: `POST /<rand>/index.php` (rule ready) ❌; DNS (Sysmon 22) + MISP indicator match ⚠️ — any lookup of the **sinkholed** `goodpanelforgoodjob.com` = infected host | Egress filtering: no direct-to-IP HTTP; DNS RPZ fed by MISP (MISP exports RPZ) | Internal DNS sinkhole for C2 domains | Throttle traffic to new/unknown domains | Point C2 domains to an internal honeypot panel to log tasks | Sinkhole / seizure by Microsoft DCU (already done for one C2 domain) | ❌ / ⚠️ |
| 7 Actions on Objectives | rundll32 `…, Main` plugin rule ✅; 4720/4732 new admin + 4946 firewall rule ✅ data; Defender 1116 *StealC* ✅ | No local admin for users; RDP disabled by GPO | Isolate the host, reset credentials, revoke sessions | MFA everywhere → stolen passwords lose value; wallet-address checks | Canary credentials in the browser store → alert when used | — | ✅ / ⚠️ |

## 4.2 Coverage summary (40 unique techniques)

| Status in my lab | Techniques | Which |
|---|---|---|
| ✅ Rule + data now | **4** | T1053.005, T1218.011, T1115, T1555.003 |
| Data now, no rule (huntable) | **6** | T1204.002, T1059.007, T1218.005, T1059.001, T1136.001, T1686 |
| ⚠️ Needs Sysmon | **8** | T1105, T1547.001, T1112, T1553.005, T1568.001, T1041, T1090, T1021.001 |
| ❌ Blind (proxy / mail / EDR) | **16** | T1566.001, T1027, T1106, T1140, T1564.001, T1071.001, T1573.001, 6× Discovery, T1005, T1113, T1486 |
| CTI only (outside network) | **6** | T1591, T1587.001, T1588.001, T1608.001, T1584.004, T1583.001 |

**Earliest point where my lab can break the chain today: phase 4 (Exploitation)**. The data (4688, 4104) is already collected; only the detection logic is missing.

## 4.3 Priorities (earliest + cheapest first)

| # | Action | Phase | Effect |
|---|---|---|---|
| 1 | Write rules / hunts for the 6 *data, no rule* techniques | 4, 7 | Earliest break with data I already have → **Week 5 hunt** |
| 2 | Install **Sysmon** on the Windows VM | 3, 5, 6, 7 | Unlocks **8** techniques (registry, MotW stream, DNS, network, downloads) |
| 3 | ASR rules + AppLocker/WDAC for script hosts and user-writable paths | 4, 5 | Moves from *detect* to *deny* for the exact Emmenhtal → Amadey path |
| 4 | DNS logs + MISP indicator match, including sinkholed domains | 6 | Catches known C2 even after it rotates IPs |
| 5 | Proxy / Zeek sensor | 3, 6 | Closes the largest gap (9 blind C2 techniques); the Week 3 `index.php` rule starts working |

## 4.4 Seeds for Week 5 (Assignment 3 — hypothesis-driven hunt)

| Hypothesis | Phase | Data I already have |
|---|---|---|
| **H1** A script host (`wscript`, `cscript`, `mshta`) started PowerShell that downloaded or ran remote content | 4 | 4688 parent/child + command line, 4104 script blocks |
| **H2** An executable with a random name started from a user-writable folder and got a scheduled task within minutes | 5 | 4688, 4698 (refines the Week 3 rules for v5 install paths) |
| **H3** A new local administrator and a new firewall rule for RDP appeared on the same host close together | 7 | 4720, 4732, 4946 |

This matches the syllabus example for Week 5 ("suspicious PowerShell activity") and comes directly out of the kill-chain gap analysis — the hunt targets the **earliest phase I can see**.
