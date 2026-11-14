# 4. Results

## Real run on Kali (Red Canary Atomic Red Team)

Tool: Red Canary's **Invoke-AtomicRedTeam** with the **atomics** library, PowerShell 7.2.6 on my Kali VM, 14 Nov 2026.
Execution log: [`data/w9-exec-log.csv`](data/w9-exec-log.csv). Screenshots: [`evidence/`](evidence/).

What I did:
1. Installed Invoke-AtomicRedTeam and the atomics folder (`~/AtomicRedTeam/atomics`).
2. Looked up the real tests for my techniques with `Invoke-AtomicTest <ID> -ShowDetails`.
3. Checked prerequisites with `-CheckPrereqs`.
4. Ran each test with `-ExecutionLogPath`, then `-Cleanup`.

| Atomic test | Name | GUID | Exit code | What happened |
|---|---|---|---|---|
| T1105-1 | rsync remote file copy (push) | 0fc6e977-cb12-44f6-b263-2824ba917409 | 255 | Failed. It needs a remote host (`victim-host`) that my lab doesn't have |
| T1105-27 | Linux Download File and Run | bdc373c5-e9cf-4563-8a7b-a9ba720a90f3 | 0 | `curl` downloaded `atomic.sh` from the Atomic Red Team GitHub and ran it ("Hello From Atomic Red Team") |
| T1082-3 | List OS Information | cccb070c-df86-4216-a5bc-9fb60c74e27c | 0 | `uname -a`, `/etc/os-release`, `uptime` showed Kali 2023.3, kernel 6.3.0 |
| T1082-8 | Hostname Discovery | 486e88ea-4f56-470f-9b57-3f4d73f39133 | 0 | `hostname` returned `Kali` |
| T1136.001-1 | Create a user account on a Linux system | 40d8eabd-e394-46f6-8785-b9bfa1d011d2 | 0 | `useradd` created `evil_user` (run as root). Cleanup deleted it |

### Analysis

- All 4 Linux tests worked, and cleanup removed the downloaded file and the new user.
- T1105-1 failed because its inputs didn't fit my lab, not because anything blocked it. Read `-ShowDetails` before picking a test.
- **SIEM result: None for all 4.** My Elastic lab only has Windows logs (Weeks 3–7). The Kali VM sends no logs to it, so nothing reached the SIEM.
- To fix it: collect Linux logs (auditd or syslog through Elastic Agent), then add rules for `useradd` (T1136.001) and `curl ... | bash` (T1105).
- Link to Amadey: it uses T1105 (loader downloads), T1082 (check-in data) and T1136.001 (hidden admin in v5). Amadey runs on Windows, so these Linux runs show the techniques but not Amadey's exact procedure.

## Windows tests (plan in 02-test-plan.md)

The same library has these tests, but they need Windows, so they were not run (no Windows host). These are the predictions only:

| ID | Technique | Predicted |
|---|---|---|
| A1 | T1059.001 PowerShell | Telemetry |
| A2 | T1059.003 Windows Command Shell | Telemetry |
| A3 | T1053.005 Scheduled Task | Technique |
| A4 | T1105 Ingress Tool Transfer | Telemetry |
| A5 | T1136.001 Local Account | Technique |
| A6 | T1686 Firewall rule | Technique |
| A7 | T1218.011 Rundll32 | Telemetry |
| A8 | T1082 System Information Discovery | Telemetry |
| B1 | T1059.007 JavaScript | Technique |
| B2 | T1218.005 Mshta | Technique |
| B3 | T1547.001 Run key | Telemetry |
| B4 | T1112 Modify Registry | Telemetry |
| C1 | T1003.002 SAM | Telemetry |
| C2 | T1003.001 LSASS | Telemetry |

## What I do with the results

- A test with no logs → fix the logging first. That is the case for the Kali runs above.
- A rule fires in the scorer but not in Kibana → the rule is off or uses the wrong index/field.
- Predictions 6 and 8 true → install Sysmon and run B3, B4, C2 again.
- C1 only Telemetry → add a rule for `reg save hklm\sam` (APT29 and APT41 use it).
