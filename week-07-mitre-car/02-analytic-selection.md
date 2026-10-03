# 2. Selecting the analytic

> **Syllabus task 1 (part 1):** *Select an analytic model from CAR.*
> Data: [`data/amadey_car_coverage.json`](data/amadey_car_coverage.json) (built by [`scripts/car_coverage.py`](scripts/car_coverage.py)) · Navigator: [`navigator/amadey_car_coverage_layer.json`](navigator/amadey_car_coverage_layer.json)

## 2.1 How much of Amadey does CAR cover?

I crossed all 102 CAR analytics with the **40 Amadey techniques** of the Week 4 kill-chain mapping (CAR's old IDs translated to ATT&CK v19.2 first).

| CAR coverage | Techniques | Which |
|---|---|---|
| **Exact** (an analytic for the technique / sub-technique) | **14** | T1053.005, T1105, T1204.002, T1059.001, T1547.001, T1112, T1140, T1082, T1016, T1033, T1518.001, T1218.011, T1021.001, T1136.001 |
| Parent technique only | 4 | T1059.007, T1218.005, T1553.005, T1564.001 |
| **None** | **22** | 6 attacker-side (T1591, T1587.001, T1588.001, T1608.001, T1584.004, T1583.001), the whole C2/beacon set (T1071.001, T1573.001, T1568.001, T1041, T1090), T1027, T1566.001, T1106, T1083, T1614, T1005, T1113, T1486, **T1115, T1555.003**, **T1686** |

Three observations:
1. CAR is **host-process-centric**: almost all coverage is `process/create`. Amadey's C2 (HTTP POST to `index.php`, RC4 profile) has no CAR analytic at all — the same blind spot my lab has (Week 4).
2. **My Week 3 rules already go beyond CAR**: the rundll32 plugin rule detects T1115 and T1555.003, which CAR does not cover.
3. **T1686** (firewall rule for RDP, new in ATT&CK v19) cannot be in CAR — CAR predates it; its closest CAR analytics map to the revoked T1562 family.

## 2.2 Candidates for Amadey's key behaviour — the every-minute scheduled task (T1053.005)

T1053.005 is the technique I studied in Week 6 and the persistence step of the Amadey chain. CAR has **six** analytics for it:

| CAR | Title | Type | Data it needs | Available in my lab? | Fit for Amadey |
|---|---|---|---|---|---|
| CAR-2013-01-002 | Autorun Differences | Situational Awareness, TTP | Autoruns snapshots (no implementation) | ❌ no collector | broad, manual |
| CAR-2013-04-002 | Quick execution of a series of suspicious commands | TTP | process create (exe, ppid, host) | ✅ 4688 | indirect (needs a burst of commands) |
| **CAR-2013-08-001** | **Execution with schtasks** | TTP | process create: exe, command_line | ✅ 4688 | catches v3/v4 (`schtasks.exe`) — **misses v5** (COM, no schtasks) |
| CAR-2015-04-002 | Remotely Scheduled Tasks via Schtasks | TTP | network flow (RPC ports) | ❌ no NSM | Amadey's task is local |
| CAR-2020-09-001 | Scheduled Task - FileAccess | Situational Awareness | file create in `\System32\Tasks` (Sysmon 11) | ⚠️ needs Sysmon | sees every task, low precision |
| **CAR-2021-12-001** | **Scheduled Task Creation or Modification Containing Suspicious Scripts, Extensions or User Writable Paths** | TTP | process create **+ Security 4698 / 4702** | ✅ 4688 + 4698/4702 | **sees both creation paths** — schtasks *and* API/COM |

## 2.3 Decision

| Criterion | CAR-2013-08-001 | **CAR-2021-12-001** |
|---|---|---|
| Uses data my lab already collects | ✅ | ✅ |
| Independent of *how* the task is created (closes the Week 6 gap) | ❌ | ✅ (4698/4702 branch) |
| Encodes Amadey's indicators (user-writable path) | ❌ | ✅ |
| Has an Elastic implementation in CAR | ❌ | ✅ (but see the review in [`03`](03-implementation.md)) |
| Unit tests | 1 | 2 (both every-minute tasks — Amadey's pattern) |
| ATT&CK tactics | Persistence only | Execution, Persistence, Privilege Escalation |

**Selected:** **CAR-2021-12-001** as the analytic to implement, with **CAR-2013-08-001** as the *baseline* to compare against — the simplest possible scheduled-task analytic, so the evaluation shows what the extra logic buys.

## 2.4 Other CAR analytics worth adding later (same data, Amadey-relevant)

| CAR | Amadey behaviour | Lab data | Week |
|---|---|---|---|
| CAR-2014-03-006 RunDLL32.exe monitoring | plugins `rundll32 …\clip64.dll, Main` (T1218.011) | ✅ 4688 | already covered by the Week 3 Sigma rule — CAR version is broader |
| CAR-2014-04-003 PowerShell Execution | Emmenhtal PowerShell stages (T1059.001) | ✅ 4688 | Week 5 H1 is a more precise version |
| CAR-2021-05-010 Create local admin accounts using net exe | v5 hidden admin (T1136.001) | ✅ 4688 | 8 / 9 (only if Amadey uses `net.exe`; Microsoft does not say) |
| CAR-2021-12-002 Modification of Default Startup Folder ('Common Startup') | Startup-folder redirect (T1547.001) — Amadey edits the **per-user** `Startup` value, CAR the machine-wide one | ⚠️ needs Sysmon 13 | 9 |
