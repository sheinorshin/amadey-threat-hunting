# 3. Implementing CAR-2021-12-001 in my Elastic SIEM

> **Syllabus task 1 (part 2):** *…and implement it in a SIEM.*
> Source of truth: [`sigma/`](sigma/) (2 rules) → [`scripts/build_rules.py`](scripts/build_rules.py) → [`queries/*.eql`](queries/) + importable Kibana rules [`rules/car_2021_12_001_tuned.ndjson`](rules/car_2021_12_001_tuned.ndjson). Hunt / noise queries: [`queries/car_tuned_hunt.esql`](queries/car_tuned_hunt.esql), [`queries/car_noise_last_30_days.esql`](queries/car_noise_last_30_days.esql).

## 3.1 Reading the published analytic critically

CAR-2021-12-001 has two branches (pseudocode):

- **A — process:** `command_line` contains `SCHTASKS` **and** `/CREATE` or `/CHANGE` **and** any suspicious term;
- **B — Task Scheduler:** Security **4698** (created) / **4702** (changed) whose `TaskContent` contains any suspicious term.

Suspicious terms = 7 extensions (`.cmd .ps1 .vbs .py .js .exe .bat`), 13 interpreters/LOLBins (`powershell`, `cmd`, `mshta`, `rundll32`, …) and 14 writable paths (`%APPDATA%`, `\AppData\Local\Temp`, `C:\Users\Public`, `C:\ProgramData`, …).

| # | Finding | Effect | My fix |
|---|---|---|---|
| F1 | **`.exe` and `cmd` alone count as suspicious** — almost every legitimate task runs an `.exe` | branch B fires on nearly **every** task (14 of 15 benign task events in my Week 5 data) | require a **writable path**, a **program directly in a user-profile folder**, or an **interpreter repeating every minute** |
| F2 | **The Elastic implementation is case-sensitive**: `process.command_line:*SCHTASKS*` and `*\/CREATE*` are wildcard queries, and on ECS `keyword`/`wildcard` fields those match case-sensitively (Splunk is case-insensitive by default) | misses `schtasks.exe /Create …` — i.e. **Amadey v3/v4 and my Week 6 Method A** | EQL `:` / `like~` / `regex~` are case-insensitive; ES\|QL lower-cases first |
| F3 | Uses `winlog.event_id` instead of ECS `event.code`, and `Task:create` / `task_content`, which **is not an object in the CAR data model** (01, §1.3) | portability; the 4698 branch must be mapped by hand | map `TaskContent` → `winlog.event_data.TaskContent`, `EventID` → `event.code` in a pySigma pipeline |
| F4 | Path list misses the **user-profile root** — Amadey v5 on Windows 10/11 installs to `C:\Users\<user>\<10 hex>\<name>.exe` (Microsoft) | v5's task path matches no listed term (it is only caught by the over-broad `.exe`) | add a regex: an `.exe` exactly two folders below `C:\Users\` |
| F5 | `C:\ProgramData` is writable but also home of **Windows Defender** (its tasks run `MpCmdRun.exe` from `ProgramData\Microsoft\Windows Defender\Platform\…`) | predictable false positives once F1 is fixed | exclude that one folder |

## 3.2 The tuned analytic

| Branch | Fires when … |
|---|---|
| **Task Scheduler** (4698 / 4702) | `TaskContent` has a user-writable path (not the Defender folder) **or** a program directly in a user-profile folder **or** (`PT1M` **and** an interpreter/LOLBin) |
| **Process** (4688 / Sysmon 1) | `schtasks.exe` + `/create`/`/change` + the same three conditions on the command line (every minute = `/SC MINUTE /MO 1`) |
| **Severity** | high when the task repeats every minute (Amadey's watchdog), medium otherwise |

**Why keep both branches:** the Task Scheduler branch works for *every* creation method (schtasks, PowerShell, COM — Amadey v5); the process branch adds the **creator** (parent process, user, full command line) that 4698 does not carry, and still works on hosts where 4698 auditing is off.

## 3.3 From the CAR data model to my fields

| Analytic needs | CAR coordinate | Elastic Agent (ECS) | Index |
|---|---|---|---|
| program name | `process/create/exe` | `process.executable` / `process.pe.original_file_name` | `logs-system.security-*` (4688), `logs-windows.sysmon_operational-*` (Sysmon 1, once installed) |
| command line | `process/create/command_line` | `process.command_line` | same |
| task definition | *(none — not in the CAR model)* | `winlog.event_data.TaskContent` | `logs-system.security-*` (4698/4702) |
| event type | — | `event.code` (keyword: `"4688"`, `"4698"`, `"4702"`) | |

The mapping lives in [`sigma/pipelines/elastic_agent_windows_security.yml`](sigma/pipelines/elastic_agent_windows_security.yml) (including a type conversion, because `event.code` is a keyword, not a number).

## 3.4 Build chain (Sigma → EQL → Kibana)

```bash
cd week-07-mitre-car/scripts
pip install sigma-cli pySigma-backend-elasticsearch pyyaml
python build_rules.py        # sigma/*.yml -> queries/*.eql + rules/car_2021_12_001_tuned.ndjson
python evaluate_car.py       # runs all variants on the Week 5 dataset + test cases -> data/evaluation.json
```

Both Sigma rules pass **every pySigma validator (0 issues)**, including ATT&CK v19 tag validation (`attack.t1053.005`, `attack.execution/persistence/privilege-escalation`) and CAR tags (`car.2021-12-001`, `car.2013-08-001`).

`build_rules.py` fixes two things in pySigma's EQL output, because EQL's `regex~` runs on the **Lucene** regex engine: it removes `(?i)` (Lucene has no inline flags; `regex~` is already case-insensitive) and the `\/` escape. The regexes themselves are written in the Lucene subset — no `\s`, `\b`, `\d`, and `.*` on both sides because Lucene regexes must match the **whole** field.

## 3.5 Putting it into Kibana

1. **Security → Rules → Detection rules → Import rules** → `rules/car_2021_12_001_tuned.ndjson` → 2 EQL rules, imported **disabled**:
   - *Scheduled Task Created or Changed With a User-Writable or Every-Minute Interpreter Action (CAR-2021-12-001, tuned)* — index `logs-system.security-*`;
   - *Schtasks Creates or Changes a Task With a User-Writable or Every-Minute Interpreter Action (CAR-2021-12-001, tuned)* — `logs-system.security-*`, `logs-windows.sysmon_operational-*`.
2. Each rule carries: MITRE ATT&CK mapping (T1053 → T1053.005 under Execution, Persistence, Privilege Escalation), severity *medium* / risk 47, schedule every 5 min with 1 min overlap, references, false positives, and an **investigation guide** (triage steps 1–5).
3. Before enabling: run [`queries/car_noise_last_30_days.esql`](queries/car_noise_last_30_days.esql) (Discover → ES|QL, last 30 days) — one row: how many events each version would have alerted on in *my* lab. Then enable.
4. Check that `winlog.event_data.TaskContent` is **searchable** in my cluster: in Discover, open a known 4698 event and filter `winlog.event_data.TaskContent : *PT1M*` (or any word visible in its XML). If the value is shown but the filter finds nothing, the field is stored but not indexed for search (e.g. a keyword length limit on long XML) and the Task Scheduler branch would stay silent — then hunt with the ES|QL version and fix the mapping.

## 3.6 Hunting version

[`queries/car_tuned_hunt.esql`](queries/car_tuned_hunt.esql) lists every hit with host, user, task name, command line, task XML and severity — the same logic for hunting backwards in time (the rule only looks forward).
