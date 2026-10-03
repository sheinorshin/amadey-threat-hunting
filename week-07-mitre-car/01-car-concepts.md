# 1. MITRE CAR — analytics vs detections

> **Syllabus (Week 7):** *Using MITRE CAR (Cyber Analytics Repository) — analytics vs detections* · source: car.mitre.org · reading: *MITRE CAR documentation*.
> Numbers below come from all 102 analytics downloaded by [`scripts/car_coverage.py`](scripts/car_coverage.py) → [`data/car_analytics.json`](data/car_analytics.json).

## 1.1 What CAR is

The **Cyber Analytics Repository** is MITRE's public library of detection *analytics* — each one a hypothesis about adversary behaviour, written against a common data model, mapped to ATT&CK, with example implementations and a test.

| CAR in numbers | Value |
|---|---|
| Analytics | **102** (CAR-2013-01-002 … CAR-2022-03-001) |
| Newest analytic | **14 Mar 2022** — CAR has not been updated since |
| Analytic types | TTP 80 · Situational Awareness 23 · Anomaly 4 · Detection 1 |
| Implementations | pseudocode 91 · Splunk 66 · LogPoint 51 · DNIF 13 · EQL 12 · Sigma 9 · **Elastic 5** |
| Stale ATT&CK IDs (vs v19.2) | 5 — T1562, T1562.001/.002/.006 → now **T1685** *Disable or Modify Tools* family; T1070.001 → **T1685.005** *Clear Windows Event Logs* |

The last row matters: CAR is frozen at 2022, ATT&CK is not. Every CAR mapping has to be re-checked against the current ATT&CK version before it goes into a SIEM (my script does this automatically).

## 1.2 Anatomy of a CAR analytic (CAR-2021-12-001 as the example)

| Field | Meaning | CAR-2021-12-001 |
|---|---|---|
| `id`, `title`, `submission_date` | identity | *Scheduled Task Creation or Modification Containing Suspicious Scripts, Extensions or User Writable Paths*, 2021-12-04 |
| `description` | the **hypothesis** — what behaviour, why it matters | attackers create/modify tasks to run malicious code persistently |
| `information_domain`, `platforms`, `subtypes` | where it applies | Host · Windows · Process |
| `analytic_types` | TTP (behaviour), Situational Awareness (context), Anomaly (outlier) | TTP |
| `coverage` | ATT&CK technique / sub-technique / tactics + coverage level | T1053.005 · TA0002, TA0003, TA0004 · *Medium* |
| `implementations` | pseudocode on the CAR data model + tool-specific versions | pseudocode, Splunk, **Elastic**, LogPoint |
| `data_model_references` | the `(object, action, field)` coordinates it needs | `process/create/command_line` |
| `unit_tests` | commands that should make it fire | two `SCHTASKS /CREATE /SC MINUTE /MO 1 …` commands |
| `d3fend_mappings` | the matching defensive technique in MITRE D3FEND | D3-PSA *Process Spawn Analysis* |

## 1.3 The CAR data model

Every analytic is written against an abstract model, not a product: **(object, action, field)**, e.g. `process / create / command_line`. The model has **13 objects** — authentication, driver, email, file, flow, http, module, **process**, **registry**, service, socket, thread, user_session — each with its own actions (`create`, `terminate`, `modify`, …) and fields.

To implement an analytic, map each data-model coordinate to what the sensor actually writes:

| CAR coordinate | Windows source | Elastic Agent (ECS) field in my lab |
|---|---|---|
| `process/create/exe` | 4688 `NewProcessName` · Sysmon 1 `Image` | `process.executable`, `process.name` |
| `process/create/command_line` | 4688 `CommandLine` · Sysmon 1 `CommandLine` | `process.command_line` |
| `process/create/parent_exe` | 4688 `ParentProcessName` · Sysmon 1 `ParentImage` | `process.parent.executable` |
| *(no CAR object)* task created / changed | Security **4698 / 4702** `TaskContent` | `winlog.event_data.TaskContent`, `event.code` |
| `file/create/file_path` | Sysmon 11 | `file.path` |
| `registry/value_edit/key` | Sysmon 13 | `registry.path` |

The fourth row is a finding in itself: CAR-2021-12-001's pseudocode searches `Task:create` / `task_content`, but **the data model has no task object**, and the analytic's `data_model_references` lists only `process/create/command_line`. The Task Scheduler branch is real and useful — it just lives outside CAR's own model, so it has to be mapped by hand.

## 1.4 Analytics vs detections

| | **Analytic** (what CAR publishes) | **Detection** (what runs in my SIEM) |
|---|---|---|
| Purpose | express a **hypothesis** about behaviour, portable | raise an **alert** someone must act on |
| Written against | an abstract data model | my index patterns, field names, data quality |
| Noise | acceptable — some analytics are *Situational Awareness* by design | must be low: every alert costs analyst time |
| Tuning | none — environment-neutral | allow-lists, thresholds, severity, scope |
| Lifecycle | published once (CAR stopped in 2022) | versioned, tested, owned, reviewed after incidents |
| Extra fields | coverage, unit tests, D3FEND | severity, risk score, schedule, look-back, triage guide, response |

**In one sentence:** an analytic says *what to look for*; a detection says *what to alert on, here, and what to do next*. Week 7 turns one CAR analytic into a detection — and the evaluation in [`04`](04-evaluation-and-mapping.md) shows why that step is not a copy-paste: the analytic as published flags 14 of the 15 benign task events in my Week 5 data.

## 1.5 CAR next to the other "analytics" in this project

| Source | Unit | Used in this project |
|---|---|---|
| **MITRE CAR** | analytic (hypothesis + data model + implementations), frozen 2022 | this week |
| **ATT&CK detection strategies / analytics** (v18+) | DET#### → AN#### → log sources, part of ATT&CK itself | Week 6: DET0441 / AN1221 for T1053.005 |
| **Sigma** | vendor-neutral rule format, converted per SIEM | Weeks 3, 5, 7 |
| **MITRE D3FEND** | defensive technique taxonomy | CAR's `d3fend_mappings` (D3-PSA, D3-SJA) |

CAR and ATT&CK's own analytics answer the same question for T1053.005 from two eras: CAR (2013/2021) gives runnable queries; ATT&CK v19 (AN1221) gives the up-to-date list of log sources. My implementation uses both.

### Sources
- MITRE CAR — https://car.mitre.org/ · analytics: https://car.mitre.org/analytics/ · data model: https://car.mitre.org/data_model/
- CAR repository (analytic YAML) — https://github.com/mitre-attack/car
- MITRE D3FEND — https://d3fend.mitre.org/
