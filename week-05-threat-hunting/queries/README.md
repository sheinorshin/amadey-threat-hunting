# Hunt queries (Kibana — Elastic 9.x)

The three hypotheses from [`../02-hunt-plan.md`](../02-hunt-plan.md), written in the Kibana query languages. Index pattern: `logs-*`. All use only log sources my SIEM lab already collects (Security 4688/4698/4720/4732/4946, PowerShell 4104).

| Hypothesis | ES\|QL (Discover) | EQL (Security → Timeline) | KQL (filter bar) |
|---|---|---|---|
| **H1** script host → PowerShell → remote content | [`h1_script_host_powershell.esql`](h1_script_host_powershell.esql) | [`h1_script_host_powershell.eql`](h1_script_host_powershell.eql) | [`h1_script_host_powershell.kql`](h1_script_host_powershell.kql) |
| **H2** hex-folder EXE + 1-minute task | [`h2_hexfolder_minute_task.esql`](h2_hexfolder_minute_task.esql) | [`h2_hexfolder_minute_task.eql`](h2_hexfolder_minute_task.eql) | — |
| **H3** new admin + firewall rule | [`h3_new_admin_firewall.esql`](h3_new_admin_firewall.esql) | [`h3_new_admin_firewall.eql`](h3_new_admin_firewall.eql) | — |

## How to run

- **ES\|QL** — Kibana → **Discover**, switch to ES\|QL, paste the query, set the time range. Secondary queries are commented out in each file (uncomment to run).
- **EQL** — Kibana → **Security → Timelines → Correlation**, or create a rule of type *Event Correlation*. EQL is used for the multi-step sequences (H1 chain, H3 account+firewall correlation).
- **KQL** — paste into the Discover search bar for a quick look at candidates.

## Which language for which job

- **KQL** — simple field filters, fastest for a first look.
- **ES\|QL** — `FROM … | WHERE … | KEEP … | SORT`/`STATS`: filtering, shaping and aggregating, like Splunk SPL. The main hunt + triage tables.
- **EQL** — `sequence by … with maxspan=…`: ordered, time-bounded correlation across events. This is what turns "a new account" + "a firewall rule" (each benign) into one detection.

## Splunk equivalent

The lab is Elastic, so these are the deliverable. In Splunk the same logic is SPL — e.g. H1:
```spl
index=win EventCode=4688 process_name=powershell.exe
  ParentProcessName IN (wscript.exe, cscript.exe, mshta.exe, wmic.exe, regsvr32.exe)
| table _time host user ParentProcessName CommandLine
```
Same idea; different syntax.

> Regex notes: ES\|QL `RLIKE` requires a full-string match, so the patterns are wrapped in `.*….*` and use triple-quoted strings so backslashes stay literal. EQL uses `regex~` for case-insensitive regex and `like` for `*` wildcards.
