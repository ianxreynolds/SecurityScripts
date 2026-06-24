<##############################################################################
.SYNOPSIS
    Reviews the local machine Security log and collects logon / logoff data

.DESCRIPTION
    The tool scans the Security log looking for event IDs 4624, 4634, and 4647
	By default log entries from the last day are searched.
	The results are output on a single line as shown below.
LogonTime           User                                      Type Meaning               SourceIP  Process                          LogoffTime LogoffEvent Dura
                                                                                                                                                           tion
---------           ----                                      ---- -------               --------  -------                          ---------- ----------- ----
2026-01-30 09:04:06 MicrosoftAccount\ianxreynolds@outlook.com    7 Unlock                Local     C:\Windows\System32\lsass.exe    N/A        N/A         N/A
2026-01-30 09:04:06 MicrosoftAccount\ianxreynolds@outlook.com   11 Cached Interactive    127.0.0.1 C:\Windows\System32\svchost.exe  N/A        N/A         N/A

.PARAMETER -d
    Optional parameter to specify how many days of data should be searched

.PARAMETER -h 
    Optional parameter to specify how many hours of data should be searched
	
.PARAMETER -IncludeOrphans
	If there is a logoff event without a corresponding logon event then the script will highlight
	It doesn't mean it is malicious and usually the logon event is outside of the time window chosen
	
.PARAMETER -csv
	Push a copy of the output to a .csv file named LogonActivity-YYYYMMDD-HHMMSS.csv
	
.NOTES
    Version: 1.2
    Updated: 30 January 2026
    Author: Ian Reynolds : ianxreynolds@outlook.com

##############################################################################>


[CmdletBinding()]
param(
    [Alias('h')]
    [int]$Hours,

    [Alias('d')]
    [int]$Days,

    [switch]$IncludeOrphans,

    [switch]$Csv,

    [string]$CsvPath
)

# --- Safety check: must be running as Administrator ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host ""
    Write-Host " ERROR: This script must be run as Administrator " `
        -ForegroundColor Yellow `
        -BackgroundColor Red
    Write-Host " Please re-run PowerShell using 'Run as administrator' " `
        -ForegroundColor Yellow `
        -BackgroundColor Red
    Write-Host ""

    exit 1
}

# Default: last 24 hours
if (-not $Hours -and -not $Days) { $Hours = 24 }

# If both specified, Hours wins
if ($Hours -gt 0) {
    $StartTime = (Get-Date).AddHours(-1 * $Hours)
} elseif ($Days -gt 0) {
    $StartTime = (Get-Date).AddDays(-1 * $Days)
} else {
    $StartTime = (Get-Date).AddHours(-24)
}

# Human logon types
$LogonTypeMap = @{
    2  = 'Interactive (Console)'
    7  = 'Unlock'
    10 = 'Remote Desktop (RDP)'
    11 = 'Cached Interactive'
}

function Get-EventDataMap {
    param([Parameter(Mandatory=$true)]$Event)

    $xml = [xml]$Event.ToXml()
    $m = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $m[$d.Name] = $d.'#text'
    }
    return $m
}

# Pull relevant events once
$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624,4634,4647
    StartTime = $StartTime
} -ErrorAction Stop | Sort-Object TimeCreated

# Sessions keyed by "LogonId|User"
$Sessions = @{}
$Orphans  = New-Object System.Collections.Generic.List[object]

foreach ($ev in $Events) {

    $data = Get-EventDataMap -Event $ev

    if ($ev.Id -eq 4624) {

        # Session start
        $lt = 0
        [void][int]::TryParse($data.LogonType, [ref]$lt)

        if (-not $LogonTypeMap.ContainsKey($lt)) { continue }

        $user = ('{0}\{1}' -f $data.TargetDomainName, $data.TargetUserName)
        $logonId = $data.TargetLogonId
        if ([string]::IsNullOrWhiteSpace($logonId)) { continue }

        $key = ($logonId + '|' + $user)

        $sourceIP = 'Local'
        if ($data.IpAddress -and $data.IpAddress -ne '-' -and $data.IpAddress -ne '::1') {
            $sourceIP = $data.IpAddress
        }

        $proc = 'N/A'
        if ($data.ProcessName -and $data.ProcessName -ne '-') {
            $proc = $data.ProcessName
        }

        # Keep earliest logon for the key within window
        if (-not $Sessions.ContainsKey($key)) {
            $Sessions[$key] = [PSCustomObject]@{
                LogonTime   = $ev.TimeCreated
                User        = $user
                Type        = $lt
                Meaning     = $LogonTypeMap[$lt]
                SourceIP    = $sourceIP
                LogonProc   = $proc
                LogonId     = $logonId
                LogoffTime  = $null
                LogoffEvent = $null
            }
        }

    } elseif ($ev.Id -eq 4634 -or $ev.Id -eq 4647) {

        # Session end
        $user = ('{0}\{1}' -f $data.SubjectDomainName, $data.SubjectUserName)
        $logonId = $data.SubjectLogonId
        if ([string]::IsNullOrWhiteSpace($logonId)) { continue }

        $key = ($logonId + '|' + $user)

        if ($Sessions.ContainsKey($key)) {
            $s = $Sessions[$key]

            # Prefer 4647 over 4634 if both exist
            if ($ev.Id -eq 4647) {
                $s.LogoffTime  = $ev.TimeCreated
                $s.LogoffEvent = '4647 (User initiated logoff)'
            } else {
                # Only set 4634 if we don't already have 4647
                if (-not $s.LogoffEvent) {
                    $s.LogoffTime  = $ev.TimeCreated
                    $s.LogoffEvent = '4634 (Logoff / session ended)'
                }
            }

        } elseif ($IncludeOrphans) {

            $etype = if ($ev.Id -eq 4647) { '4647 (Orphan user logoff)' } else { '4634 (Orphan logoff)' }
            $Orphans.Add([PSCustomObject]@{
                Time    = $ev.TimeCreated
                User    = $user
                Event   = $etype
                LogonId = $logonId
            }) | Out-Null
        }
    }
}

# Output
$Output = foreach ($s in $Sessions.Values) {

    if ($s.LogoffTime) {
        $ts = New-TimeSpan -Start $s.LogonTime -End $s.LogoffTime
        $duration = $ts.ToString()
        $logoffTimeStr = Get-Date $s.LogoffTime -Format 'yyyy-MM-dd HH:mm:ss'
        $logoffEventStr = $s.LogoffEvent
    } else {
        $duration = 'N/A'
        $logoffTimeStr = 'N/A'
        $logoffEventStr = 'N/A'
    }

    [PSCustomObject]@{
        LogonTime   = Get-Date $s.LogonTime -Format 'yyyy-MM-dd HH:mm:ss'
        User        = $s.User
        Type        = $s.Type
        Meaning     = $s.Meaning
        SourceIP    = $s.SourceIP
        Process     = $s.LogonProc
        LogoffTime  = $logoffTimeStr
        LogoffEvent = $logoffEventStr
        Duration    = $duration
        LogonId     = $s.LogonId
    }
}

# Sort once, reuse
$SortedOutput = $Output | Sort-Object LogonTime -Descending

# Console output
$SortedOutput | Format-Table -AutoSize

# CSV export (optional)
if ($Csv) {

    if (-not $CsvPath) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $CsvPath = Join-Path (Get-Location) ("LogonActivity-$timestamp.csv")
    }

    $SortedOutput |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    Write-Host ''
    Write-Host ("CSV exported to: {0}" -f $CsvPath)
}

# Orphan logoffs (optional)
if ($IncludeOrphans -and $Orphans.Count -gt 0) {
    Write-Host ''
    Write-Host 'Orphan logoff events (no matching human logon in this time window):'
    $Orphans | Sort-Object Time -Descending | Format-Table -AutoSize
}
