# 2. Choosing the analytic

## CAR vs Amadey

I checked all 102 CAR analytics against Amadey's 40 techniques from Week 4 ([`data/amadey_car_coverage.json`](data/amadey_car_coverage.json), layer [`navigator/amadey_car_coverage_layer.json`](navigator/amadey_car_coverage_layer.json)):

- 14 techniques have a CAR analytic (e.g. T1053.005, T1059.001, T1218.011, T1136.001)
- 4 only at the parent level
- 22 have none — including all C2 techniques

## Options for the scheduled task (T1053.005)

CAR has 6 analytics for it. The two that work with my lab data:

| Analytic | Uses | Problem for Amadey |
|---|---|---|
| CAR-2013-08-001 Execution with schtasks | process creation | misses Amadey v5 (no `schtasks.exe`) |
| CAR-2021-12-001 Suspicious scheduled task | process creation + event 4698/4702 | none — sees both ways |

The other four need data I don't have (Autoruns, network flows, Sysmon file events) or are too general.

## Decision

I use **CAR-2021-12-001**. It works with 4688 and 4698, which my lab already collects, it checks user-writable folders like Amadey uses, and it catches tasks made through COM. CAR-2013-08-001 is my baseline for comparison.
