<##############################################################################
.SYNOPSIS
Find process executions in Windows logs (Security 4688/4689 + optional Sysmon EID 1).

.DEFAULTS
-Name ping.exe
Lookback window: last 6 hours
Uses Sysmon only if Microsoft-Windows-Sysmon/Operational is present & readable.

.PARAMETERS
-ProcessId / -pid : Match by numeric ProcessId (overrides -Name)
-Name             : Match by executable name, default is ping.exe
-h                : Look back x hours (overrides default)
-d                : Look back x days  (overrides default; days wins over hours (-h) if both supplied)
-Csv              : Export results to YYYYMMDD-HHMMSS.csv in current directory

.NOTES
    Version: 1.0
    Updated: 30 January 2026
    Author: Ian Reynolds : ianxreynolds@outlook.com

##############################################################################>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Name = "ping.exe",

    [Parameter(Mandatory = $false)]
    [Alias('pid')]
    [int]$ProcessId,

    [Parameter(Mandatory = $false)]
    [int]$h,

    [Parameter(Mandatory = $false)]
    [int]$d,

    [Parameter(Mandatory = $false)]
    [switch]$Csv
)

# -------------------------
# Progress helpers
# -------------------------
$script:Processed = 0
$script:Hits      = 0

function Update-ScanProgress {
    param(
        [Parameter(Mandatory=$true)][string]$Phase,
        [int]$Every = 250
    )

    # Throttle updates for performance
    if (($script:Processed % $Every) -ne 0) { return }

    # PercentComplete unknown (streaming query), so keep at 0 with useful status text
    Write-Progress -Activity "Scanning event logs" `
        -Status "$Phase | processed: $($script:Processed) | hits: $($script:Hits)" `
        -PercentComplete 0
}

function Complete-ScanProgress {
    Write-Progress -Activity "Scanning event logs" -Completed
}

# -------------------------
# Utility functions
# -------------------------
function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Convert-HexPidToDecimal {
    param([string]$HexPid)
    if (-not $HexPid) { return $null }
    [Convert]::ToInt32(($HexPid -replace '^0x',''), 16)
}

function Get-LeafExeName {
    param([string]$Value)
    if (-not $Value) { return $null }
    try { Split-Path -Path $Value -Leaf } catch { $Value }
}

function Test-EventLogReadable {
    param([Parameter(Mandatory=$true)][string]$LogName)

    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        if (-not $log.IsEnabled) { return $false }

        # If the log exists but is empty, treat as readable
        try {
            $null = Get-WinEvent -FilterHashtable @{ LogName = $LogName } -MaxEvents 1 -ErrorAction Stop
            return $true
        } catch {
            if ($_.Exception.Message -match "No events were found") { return $true }
            throw
        }
    }
    catch {
        return $false
    }
}

function Get-WinEventSafe {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Filter,
        [Parameter(Mandatory=$true)][string]$Label
    )
    try {
        Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read $Label log. $($_.Exception.Message)"
        @()
    }
}

# -------------------------
# Admin check (Security log requires elevation)
# -------------------------
if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator to read the Security event log (4688/4689). Right-click PowerShell and choose 'Run as Administrator'."
    exit 1
}

# -------------------------
# Time window (default 6 hours; -d wins over -h)
# -------------------------
if ($PSBoundParameters.ContainsKey('d')) {
    if ($d -le 0) { Write-Error "-d must be a positive integer."; exit 1 }
    $since = (Get-Date).AddDays(-$d)
    $windowDesc = "$d day(s)"
}
elseif ($PSBoundParameters.ContainsKey('h')) {
    if ($h -le 0) { Write-Error "-h must be a positive integer."; exit 1 }
    $since = (Get-Date).AddHours(-$h)
    $windowDesc = "$h hour(s)"
}
else {
    $since = (Get-Date).AddHours(-3)
    $windowDesc = "3 hour(s)"
}

# -------------------------
# Matching logic
# -------------------------
$matchByPid  = $PSBoundParameters.ContainsKey('ProcessId')
$targetName  = Get-LeafExeName $Name
$escapedName = if ($targetName) { [Regex]::Escape($targetName) } else { $null }
$statusTarget = if ($matchByPid) { "PID $ProcessId" } else { $targetName }

# -------------------------
# Sysmon autodetection
# -------------------------
$sysmonLog = "Microsoft-Windows-Sysmon/Operational"
$useSysmon = Test-EventLogReadable -LogName $sysmonLog

Write-Host "Target: $statusTarget | Window: last $windowDesc"
Write-Host ("Sysmon: " + ($(if ($useSysmon) { "detected (will query)" } else { "not present / not readable (skipping)" })))

$results = New-Object System.Collections.Generic.List[object]

# -------------------------
# SECURITY: 4688 / 4689
# -------------------------
$secEvents = Get-WinEventSafe -Label "Security" -Filter @{
    LogName   = "Security"
    Id        = 4688,4689
    StartTime = $since
}

$secEvents | ForEach-Object {
    $script:Processed++
    Update-ScanProgress -Phase "Security (4688/4689)"

    $e = $_
    [xml]$xml = $e.ToXml()
    $data = @{}
    foreach ($n in $xml.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }

    if ($e.Id -eq 4688) {
        $procName = $data["NewProcessName"]
        $hexPid   = $data["NewProcessId"]
        $parent   = $data["ProcessId"]
        $etype    = "Start"
    } else {
        $procName = $data["ProcessName"]
        $hexPid   = $data["ProcessId"]
        $parent   = $null
        $etype    = "Stop"
    }

    $procPid    = Convert-HexPidToDecimal $hexPid
    $procParent = Convert-HexPidToDecimal $parent

    if ($matchByPid) {
        if ($procPid -ne $ProcessId) { return }
    } else {
        if (-not $procName -or $procName -notmatch "(?i)\\$escapedName$") { return }
    }

    $script:Hits++
    $results.Add([PSCustomObject]@{
        Time        = $e.TimeCreated
        Source      = "Security"
        EventID     = $e.Id
        Event       = $etype
        ProcessName = $procName
        ProcessId   = $procPid
        ParentPID   = $procParent
        User        = $data["SubjectUserName"]
        CommandLine = $data["CommandLine"]
    })
}

# -------------------------
# SYSMON: Event ID 1 (only if detected)
# -------------------------
if ($useSysmon) {

    $sysEvents = Get-WinEventSafe -Label "Sysmon" -Filter @{
        LogName   = $sysmonLog
        Id        = 1
        StartTime = $since
    }

    $sysEvents | ForEach-Object {
        $script:Processed++
        Update-ScanProgress -Phase "Sysmon (Event ID 1)"

        $e = $_
        [xml]$xml = $e.ToXml()
        $data = @{}
        foreach ($n in $xml.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }

        $procName = $data["Image"]
        $procPid  = if ($data["ProcessId"]) { [int]$data["ProcessId"] } else { $null }
        $ppidVal  = if ($data["ParentProcessId"]) { [int]$data["ParentProcessId"] } else { $null }

        if ($matchByPid) {
            if ($procPid -ne $ProcessId) { return }
        } else {
            if (-not $procName -or $procName -notmatch "(?i)\\$escapedName$") { return }
        }

        $script:Hits++
        $results.Add([PSCustomObject]@{
            Time        = $e.TimeCreated
            Source      = "Sysmon"
            EventID     = 1
            Event       = "Start"
            ProcessName = $procName
            ProcessId   = $procPid
            ParentPID   = $ppidVal
            User        = $data["User"]
            CommandLine = $data["CommandLine"]
        })
    }
}

Complete-ScanProgress

$sorted = $results | Sort-Object Time, Source, EventID

if ($Csv) {
    $outFile = "$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $sorted | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "CSV written to $outFile"
} else {
    $sorted | Format-Table -AutoSize
}
