<#
.SYNOPSIS
    Week 6 lab exercise (ITH, AITU): create and remove a harmless, clearly named scheduled task
    so the SIEM records T1053.005 Scheduled Task telemetry that can be mapped to ATT&CK.

.DESCRIPTION
    LAB VM ONLY. Nothing malicious is downloaded or executed. The task runs a 1-line .cmd that appends
    a timestamp to a log file in C:\Users\Public\ITH-W6\. Everything is named "ITH-W6" so it is easy to
    find in Kibana and impossible to confuse with real activity. All tasks and files are removed at the end.

    Method A  schtasks.exe /Create /SC MINUTE /MO 1 ...         (command-line way)
    Method B  Register-ScheduledTask (PowerShell cmdlets)         (API way - no schtasks.exe process)

    Why two methods: the Week 3 Sigma rule looks at the schtasks.exe command line; the Week 5 H2 hunt also
    looks at event 4698. Running both shows which detection sees which way of creating the same task.

    A ground-truth CSV (what was done, when, which ATT&CK technique) is written for map_results.py.

.PARAMETER Method
    A, B or Both (default Both).

.PARAMETER WaitSeconds
    How long each task is left in place so it fires at least once (default 150).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\ith-w6-task-exercise.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('A', 'B', 'Both')] [string]$Method = 'Both',
    [ValidateRange(70, 600)] [int]$WaitSeconds = 150,
    [string]$RunLog = (Join-Path (Get-Location) ("w6_run_log_{0}_{1}.csv" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
$Root     = 'C:\Users\Public\ITH-W6'
$Payload  = Join-Path $Root 'ith-w6-heartbeat.cmd'
$Action   = "cmd.exe /c $Payload"
$TaskA    = 'ITH-W6-Exercise-A'
$TaskB    = 'ITH-W6-Exercise-B'
$Rows     = New-Object System.Collections.Generic.List[object]

function Get-UtcNow { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Add-Step($Step, $Technique, $Start, $Command) {
    $Rows.Add([pscustomobject]@{
        host = $env:COMPUTERNAME; step = $Step; technique = $Technique
        utc_start = $Start; utc_end = (Get-UtcNow); command = $Command
    })
    Write-Host ("[{0}] {1}" -f (Get-UtcNow), $Step)
}

function Test-Logging {
    # Read-only checks. Nothing is changed; the script only tells you what to enable.
    $ok = $true
    $audit = (auditpol /get /subcategory:"Other Object Access Events" 2>$null | Out-String)
    if ($audit -notmatch 'Success') {
        Write-Warning 'Event 4698/4699 will NOT be logged. Enable it (admin):  auditpol /set /subcategory:"Other Object Access Events" /success:enable'
        $ok = $false
    }
    $tsLog = (wevtutil gl Microsoft-Windows-TaskScheduler/Operational 2>$null | Out-String)
    if ($tsLog -notmatch 'enabled:\s*true') {
        Write-Warning 'TaskScheduler/Operational log is disabled. Enable it (admin):  wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'
        $ok = $false
    }
    $pcl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
    if (-not $pcl -or $pcl.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
        Write-Warning 'Command lines may be missing from 4688 (policy "Include command line in process creation events" not detected).'
    }
    return $ok
}

function Remove-Exercise {
    foreach ($t in @($TaskA, $TaskB)) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            $s = Get-UtcNow
            Unregister-ScheduledTask -TaskName $t -Confirm:$false
            Add-Step "cleanup: removed task $t" 'cleanup' $s "Unregister-ScheduledTask -TaskName $t"
        }
    }
}

Write-Host '== ITH Week 6 lab exercise: T1053.005 Scheduled Task (benign) =='
if (-not (Test-Logging)) { Write-Warning 'Continuing anyway - some events will be missing from the SIEM.' }

try {
    # Setup: a harmless heartbeat script in a user-writable folder (this is what the task runs)
    $s = Get-UtcNow
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    Set-Content -Path $Payload -Encoding ASCII -Value "@echo %DATE% %TIME% ITH-W6 heartbeat>>`"$Root\heartbeat.log`""
    Add-Step 'setup: wrote heartbeat .cmd' 'setup' $s "Set-Content $Payload"

    if ($Method -in 'A', 'Both') {
        $s = Get-UtcNow
        & schtasks.exe /Create /SC MINUTE /MO 1 /TN $TaskA /TR $Action /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "schtasks.exe failed with exit code $LASTEXITCODE" }
        Add-Step "A: created $TaskA with schtasks.exe (every 1 min)" 'T1053.005' $s "schtasks /Create /SC MINUTE /MO 1 /TN $TaskA /TR `"$Action`" /F"
        $s = Get-UtcNow
        Start-Sleep -Seconds $WaitSeconds
        Add-Step "A: waited $WaitSeconds s for the task to fire" 'T1053.005;T1059.003' $s 'task action: cmd.exe /c heartbeat'
        $s = Get-UtcNow
        & schtasks.exe /Delete /TN $TaskA /F | Out-Null
        Add-Step "A: deleted $TaskA with schtasks.exe" 'cleanup' $s "schtasks /Delete /TN $TaskA /F"
    }

    if ($Method -in 'B', 'Both') {
        $s = Get-UtcNow
        $act  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $Payload"
        $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30) `
                    -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Minutes 10)
        Register-ScheduledTask -TaskName $TaskB -Action $act -Trigger $trig `
            -Description 'ITH Week 6 benign lab exercise - safe to delete' | Out-Null
        Add-Step "B: created $TaskB with Register-ScheduledTask (every 1 min)" 'T1053.005;T1059.001' $s 'Register-ScheduledTask -TaskName ITH-W6-Exercise-B (RepetitionInterval 1 min)'
        $s = Get-UtcNow
        Start-Sleep -Seconds $WaitSeconds
        Add-Step "B: waited $WaitSeconds s for the task to fire" 'T1053.005;T1059.003' $s 'task action: cmd.exe /c heartbeat'
        $s = Get-UtcNow
        Unregister-ScheduledTask -TaskName $TaskB -Confirm:$false
        Add-Step "B: deleted $TaskB with Unregister-ScheduledTask" 'cleanup' $s "Unregister-ScheduledTask -TaskName $TaskB"
    }

    $beats = if (Test-Path "$Root\heartbeat.log") { @(Get-Content "$Root\heartbeat.log").Count } else { 0 }
    Write-Host "Heartbeat lines written by the task(s): $beats (expected >= 1 per method)"
}
finally {
    Remove-Exercise
    if (Test-Path $Root) {
        $s = Get-UtcNow
        Remove-Item -Path $Root -Recurse -Force
        Add-Step "cleanup: removed $Root" 'cleanup' $s "Remove-Item $Root -Recurse"
    }
    $Rows | Export-Csv -Path $RunLog -NoTypeInformation -Encoding UTF8
    Write-Host "Ground-truth log: $RunLog"
    Write-Host 'Next: export the events with queries/w6_exercise_events.esql and run scripts/map_results.py'
}
