# Week 10 — APT Techniques · Assignment 6

Syllabus task: analyse the TTPs of APT29 or APT41 and map them to MITRE ATT&CK. Readings: Mandiant *APT1* (2013), CrowdStrike *Global Threat Report* (2026).

I mapped both APT29 and APT41 from ATT&CK v19.2 (including their campaigns), and compared them with Amadey and its users TA505 and Kimsuky.

## Files

- [`01-apt-concepts.md`](01-apt-concepts.md) — what an APT is, notes on the two readings
- [`02-apt29-mapping.md`](02-apt29-mapping.md) — APT29 mapped to ATT&CK
- [`03-apt41-mapping.md`](03-apt41-mapping.md) — APT41 mapped to ATT&CK
- [`04-comparison-and-priorities.md`](04-comparison-and-priorities.md) — comparison, my lab coverage, next rules
- [`data/ttp_tables.md`](data/ttp_tables.md) — full technique tables (generated)
- [`navigator/`](navigator/) — layers for APT29, APT41, both, lab coverage
- [`figures/`](figures/) — charts
- [`scripts/build_apt_profiles.py`](scripts/build_apt_profiles.py) — builds everything from ATT&CK data

## Short summary

- APT29: 119 techniques (66 on its page + 53 from campaigns like SolarWinds).
- APT41: 105 techniques (82 + 23 from campaigns).
- They share 40 techniques.
- Amadey is closest to TA505 and Kimsuky, the groups ATT&CK lists as its users.
- My lab can see about 35 % of the two APTs' techniques now, 77 % with Sysmon.

## How to run

```bash
cd week-10-apt-techniques/scripts
pip install matplotlib
python build_apt_profiles.py
```

← [Project overview](../README.md) · previous: [Week 9](../week-09-atomic-red-team/)
