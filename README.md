# SecurityScripts
Scripts to make life simpler

## Get-MicrosoftCriticalPatches.ps1
Pull this month's Microsoft security updates and identify Critical CVEs, including public disclosure / exploitation signals.

## Get-LogonActivity.ps1
Reviews the local machine Security log and collects logon / logoff data

## Get-ProcessExecution.ps1
Find process executions in Windows logs (Security 4688/4689 + optional Sysmon EID 1).

## Get-ProcessRunCount.ps1
Counts:
  1) How many instances of a process are currently running
  2) How many times that process executed within a lookback window
