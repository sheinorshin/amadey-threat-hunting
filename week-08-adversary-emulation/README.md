# Week 8 — Adversary Emulation Plan · Assignment 4

Syllabus task: develop a simple adversary emulation plan (initial access → persistence → data exfiltration) and document it with ATT&CK. Reading: MITRE CALDERA documentation.

This is a **blue-team validation exercise**: I copy an Amadey-style chain with safe, public test commands on my isolated lab VM, using a dummy file, to check which steps my SIEM and rules catch. It is not malware — every step is an Atomic Red Team test or a CALDERA ability, and everything is cleaned up.

## Files

- [`01-emulation-concept.md`](01-emulation-concept.md) — what an emulation plan is, CALDERA, safety
- [`02-plan.md`](02-plan.md) — the plan: 5 steps, ATT&CK, the test to use for each
- [`03-detections-and-cleanup.md`](03-detections-and-cleanup.md) — expected detections, run order, cleanup

## Short summary

- Scenario: Amadey-style infection on the lab VM, goal = copy one dummy text file off the host.
- 5 steps: run a script → download a tool → scheduled task persistence → stage the file → send it out.
- Built from the Week 4 kill chain; reuses the Week 9 atomic tests and the Week 3/5/7 rules.
- Status: plan only. Running it and the screenshots are done with Week 9 (same VM).

← [Project overview](../README.md) · previous: [Week 7](../week-07-mitre-car/) · next: [Week 9](../week-09-atomic-red-team/)
