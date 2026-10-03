# 2. Hunt plan — three hypotheses (PEAK: Prepare)

> **Syllabus task 1:** *Build a hypothesis-driven hunting scenario (e.g. suspicious PowerShell activity).*

Each hunt is written in the **PEAK** structure. This file is the **Prepare** stage: the hypothesis, why it matters, the data, the scope, the exact queries, and — decided *before* running — what counts as a hit and how I'll triage. [`03-hunt-execution.md`](03-hunt-execution.md) is Execute; [`04-findings-and-detections.md`](04-findings-and-detections.md) is Act with Knowledge.

**Common scope**
- **Environment:** Windows endpoints shipping to Elasticsearch via Elastic Agent (System, Windows integrations). Index pattern `logs-*`.
- **Timeframe:** rolling 7 days (demonstrated here over one business day, 2026-10-01).
- **Out of scope / known blind:** network C2 (no proxy/Zeek), registry & image-load (no Sysmon) — from the Week 4 coverage analysis. Hunts are deliberately built on data the lab **has**.
- **Data to prove it:** a synthetic ECS dataset ([`data/dataset.ndjson`](data/dataset.ndjson)) with one Amadey→StealC intrusion planted in benign office noise. The [`scripts/run_hunt.py`](scripts/run_hunt.py) harness applies the same logic as the Kibana queries and self-checks the result.

---

## H1 — A script host spawned PowerShell that pulled/ran remote content

| | |
|---|---|
| **Hypothesis** | If Amadey (via Emmenhtal) is executing here, a Windows **script host** (`wscript`/`cscript`/`mshta`/`wmic`/`regsvr32`) has started **PowerShell** that downloads or decodes-and-runs remote code. |
| **Why** | This is the Exploitation phase (KC4) and the **earliest point my lab can see** (Week 4). No exploit — the user runs a script, LOLBins do the rest. |
| **ATT&CK v19** | T1059.007 JavaScript, T1218.005 Mshta, T1059.001 PowerShell, T1105 Ingress Tool Transfer |
| **Data** | `logs-system.security-*` (4688, with command line) + `logs-windows.powershell_operational-*` (4104 script blocks) |
| **Queries** | [`queries/h1_script_host_powershell.esql`](queries/h1_script_host_powershell.esql) (candidates + cradle), [`.eql`](queries/h1_script_host_powershell.eql) (full sequence), [`.kql`](queries/h1_script_host_powershell.kql) |
| **Candidate** | any `powershell.exe` (4688) whose `process.parent.name` ∈ {wscript, cscript, mshta, wmic, regsvr32} |
| **Confirm** | the candidate's command line **or** its 4104 script block shows a download cradle / encoded exec (`DownloadString`, `IEX`, `-enc`, `FromBase64String`, `Reflection.Assembly::Load`) |
| **Triage out** | PowerShell started by `explorer.exe`/`services.exe`; downloads from **internal** hosts (RFC1918); signed admin scripts run by `-File` from `C:\Scripts\` |
| **If true** | isolate host, pull the parent script, pivot to the download URL/next stage → Installation hunt (H2) |

**Note on specificity:** searching 4104 for a download cradle *alone* is noisy (admins use `Invoke-WebRequest` constantly). The hypothesis adds the **parent = script host** condition, which is what makes it precise. The execution doc shows the difference in numbers.

---

## H2 — A hex-named EXE in a user folder gets a 1-minute scheduled task

| | |
|---|---|
| **Hypothesis** | Amadey installs by copying itself to `%TEMP%\<10 hex chars>\<name>.exe` and persisting with a scheduled task that runs **every minute**. |
| **Why** | Installation phase (KC5). The 1-minute task and the hex-folder path are **stable across Amadey versions** (high on the Pyramid of Pain) — they catch builds whose hash I don't have. Two Week-3 Sigma rules already encode this; the hunt validates and tunes them. |
| **ATT&CK v19** | T1053.005 Scheduled Task, T1204.002 Malicious File |
| **Data** | `logs-system.security-*` — 4688 (process + schtasks command line) and 4698 (scheduled task created, with the task XML) |
| **Queries** | [`queries/h2_hexfolder_minute_task.esql`](queries/h2_hexfolder_minute_task.esql), [`.eql`](queries/h2_hexfolder_minute_task.eql) |
| **Candidate** | (a) 4688 `process.executable` matches `\\[a-f0-9]{10}\\…\.exe`; **or** (b) 4688 `schtasks.exe` with `/SC MINUTE /MO 1`; **or** (c) 4698 whose `TaskContent` contains `PT1M` |
| **Confirm** | on one host, a hex-folder EXE **and** an every-minute task that points at a **user-writable** path (`\Users\`, `\AppData\`, `\Temp\`, `\ProgramData\`) within ~10 min |
| **Triage out** | legitimate every-minute/hourly tasks from `C:\Program Files*` or `C:\Windows\System32` (GoogleUpdate = daily, Office update = hourly `PT1H`, not `PT1M`) |
| **If true** | the task's `Command` is the loader → hash & submit, pivot to its children (rundll32 plugins, PowerShell) → H3 and the C2 pivot |

---

## H3 — A new local admin and a firewall rule appear together

| | |
|---|---|
| **Hypothesis** | Amadey v5's RAT commands create a **hidden local admin** and open a **firewall rule for RDP** — so a new privileged account and a new firewall rule show up on the **same host within minutes**. |
| **Why** | Actions on Objectives (KC7): hands-on-keyboard / lateral-movement prep. Each event alone is normal admin noise; the **correlation in time** is the signal. |
| **ATT&CK v19** | T1136.001 Local Account, T1021.001 RDP, T1686 Disable or Modify System Firewall |
| **Data** | `logs-system.security-*` — 4720 (user created), 4732 (member added to a local group), 4946 (firewall rule added) |
| **Queries** | [`queries/h3_new_admin_firewall.eql`](queries/h3_new_admin_firewall.eql) (the correlation), [`.esql`](queries/h3_new_admin_firewall.esql) (list privileged-account changes) |
| **Candidate** | an account added to **Administrators** (4732) *or* a new account whose name ends in `$` (4720), **and** a firewall rule added (4946), on the same host within **30 min** |
| **Confirm** | the account change and the firewall rule are on the same host, close in time, and not attributable to a known admin/change ticket |
| **Triage out** | accounts added to **Remote Desktop Users** (not Administrators); firewall rules added by software installers with no account change nearby; changes made by a known helpdesk account during a change window |
| **If true** | high-severity incident: contain, disable the account, remove the rule, reset credentials, hunt for the account's use elsewhere |

---

## Success criteria (decided before running)

1. Each hypothesis **finds the planted intrusion** on the infected host.
2. Each hypothesis **rejects the near-misses** (benign internal download, Office update task, helpdesk RDP-Users account, installer firewall rule).
3. Every confirmed technique yields either a **new/validated detection rule** or a **documented visibility gap** (PEAK "Act with Knowledge").

These are checked automatically by `run_hunt.py` (7 assertions) and reported in [`03-hunt-execution.md`](03-hunt-execution.md).
