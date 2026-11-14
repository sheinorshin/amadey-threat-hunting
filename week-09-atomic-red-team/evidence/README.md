# Evidence

| File | Shows |
|---|---|
| `w9_01_scorer_selftest_12of12.png` | `build_test_plan.py` (14 tests, all IDs valid) and `score_atomic_run.py --selftest` → 12/12 PASS |
| `w9_02_toolkit_installed_atomics.png` | Invoke-AtomicRedTeam installed on Kali, atomics folder listed |
| `w9_03_showdetails_T1105.png` | `-ShowDetails` for T1105 (real tests, numbers, GUIDs, commands) |
| `w9_04_showdetails_T1082.png` | `-ShowDetails` for T1082 |
| `w9_05_showdetails_T1136_001.png` | `-ShowDetails` for T1136.001 |
| `w9_06_checkprereqs_T1105.png` | `-CheckPrereqs` / `-GetPrereqs` for T1105 |
| `w9_07_failed_run_T1105_1.png` | T1105-1 failed (exit 255, no remote host) |
| `w9_08_run_T1105_27_T1082_3_8.png` | T1105-27, T1082-3, T1082-8 run (exit 0) and cleaned up |
| `w9_09_run_T1136_001_and_log.png` | T1136.001-1 run as root (exit 0), cleanup, execution log |

The Windows atomic tests need a Windows host, so they were not run.
