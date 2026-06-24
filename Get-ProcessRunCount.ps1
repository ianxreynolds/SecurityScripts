<##############################################################################
.SYNOPSIS
Counts:
  1) How many instances of a process are currently running
  2) How many times that process executed within a lookback window

LOGIC CHANGE:
- We no longer attempt cross-log de-duplication.
- We count Security 4688 and Sysmon 1 separately.
- If both are available and counts differ, we alert (Write-Warning).
- Total executions reported = max(4688_count, sysmon1_count).

.PARAMETERS
ProcessName : process name with or without .exe
-h          : look back N hours
-d          : look back N days (wins over -h)
-now        : only count current running processes (no logs, no admin needed)
-Verbose    : show per-source counts and log status

.NOTES
    Version: 1.0
    Updated: 30 January 2026
    Author: Ian Reynolds : ianxreynolds@outlook.com

##############################################################################>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ProcessName,

    [Parameter(Mandatory = $false)]
    [int]$h,

    [Parameter(Mandatory = $false)]
    [int]$d,

    [Parameter(Mandatory = $false)]
    [switch]$now
)

function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
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

        # If the log exists but is empty, treat as readable.
        try {
            $null = Get-WinEvent -FilterHashtable @{ LogName = $LogName } -MaxEvents 1 -ErrorAction Stop
            return $true
        } catch {
            if ($_.Exception.Message -match "No events were found") { return $true }
            throw
        }
    } catch {
        return $false
    }
}

# -------------------------
# Normalize process name
# -------------------------
$procBase = ($ProcessName -replace '\.exe$', '')
$procExe  = "$procBase.exe"

# -------------------------
# Count currently running (always allowed)
# -------------------------
$instances = Get-Process -Name $procBase -ErrorAction SilentlyContinue
$runningCount = if ($instances) { $instances.Count } else { 0 }

# -------------------------
# -now mode: no logs, no admin required
# -------------------------
if ($now) {
    Write-Host ("{0} | Running: {1} | Executions: skipped (-now)" -f $procExe, $runningCount)
    return
}

# -------------------------
# Admin required for Security log
# -------------------------
if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator unless -now is specified. Security event log access is required (Event ID 4688). Exiting."
    exit 1
}

# -------------------------
# Time window (default 24h; -d wins)
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

Write-Verbose "Target process: $procExe"
Write-Verbose "Lookback window: last $windowDesc (since $($since.ToString('u')))"

# -------------------------
# Count Security 4688
# -------------------------
$securityReadable = Test-EventLogReadable -LogName "Security"
if (-not $securityReadable) {
    Write-Error "Security log is not readable (even though elevated). Cannot continue."
    exit 1
}

$sec4688Count = 0
try {
    $secEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = $since
    } -ErrorAction Stop

    foreach ($e in $secEvents) {
        [xml]$xml = $e.ToXml()
        $data = @{}
        foreach ($n in $xml.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }

        $img = $data["NewProcessName"]
        if (-not $img) { continue }

        if ((Get-LeafExeName $img) -ieq $procExe) {
            $sec4688Count++
        }
    }
}
catch {
    Write-Error "Failed querying Security 4688: $($_.Exception.Message)"
    exit 1
}

# -------------------------
# Count Sysmon Event ID 1 (if available)
# -------------------------
$sysmonLog      = "Microsoft-Windows-Sysmon/Operational"
$sysmonReadable = Test-EventLogReadable -LogName $sysmonLog

$sysmon1Count = $null
if ($sysmonReadable) {
    $sysmon1Count = 0
    try {
        $sysEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $sysmonLog
            Id        = 1
            StartTime = $since
        } -ErrorAction Stop

        foreach ($e in $sysEvents) {
            [xml]$xml = $e.ToXml()
            $data = @{}
            foreach ($n in $xml.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }

            $img = $data["Image"]
            if (-not $img) { continue }

            if ((Get-LeafExeName $img) -ieq $procExe) {
                $sysmon1Count++
            }
        }
    }
    catch {
        Write-Warning "Sysmon log looked readable, but query failed: $($_.Exception.Message). Proceeding with Security-only."
        $sysmonReadable = $false
        $sysmon1Count   = $null
    }
}

# -------------------------
# Total executions = higher of the two (conservative)
# -------------------------
if ($sysmonReadable -and $null -ne $sysmon1Count) {
    if ($sec4688Count -ne $sysmon1Count) {
        Write-Warning ("Execution count mismatch for {0} in last {1}: Security(4688)={2}, Sysmon(1)={3}. Reporting the higher value." `
            -f $procExe, $windowDesc, $sec4688Count, $sysmon1Count)
    }

    $execTotal = [Math]::Max($sec4688Count, $sysmon1Count)
    Write-Verbose ("Counts | Security4688={0} | Sysmon1={1} | Total(max)={2}" -f $sec4688Count, $sysmon1Count, $execTotal)
} else {
    $execTotal = $sec4688Count
    Write-Verbose ("Counts | Security4688={0} | Sysmon1=unavailable | Total={0}" -f $sec4688Count)
}

# -------------------------
# Output: single line
# -------------------------
Write-Host ("{0} | Running: {1} | Executions (last {2}): {3}" -f $procExe, $runningCount, $windowDesc, $execTotal)
