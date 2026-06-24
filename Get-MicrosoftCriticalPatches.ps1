<#
.SYNOPSIS
    Pull this month's Microsoft security updates and identify Critical CVEs,
    including public disclosure / exploitation signals.

.DESCRIPTION
    Uses the Microsoft MSRC CVRF API for the selected month, then enriches
    results with CISA Known Exploited Vulnerabilities (KEV).

    By default, outputs only Critical vulnerabilities.

.EXAMPLES
    .\Get-MicrosoftCriticalPatches.ps1
    .\Get-MicrosoftCriticalPatches.ps1 -Month 2026-Jun
    .\Get-MicrosoftCriticalPatches.ps1 -Month 2026-06
    .\Get-MicrosoftCriticalPatches.ps1 -AllSeverities
	
.NOTES
    Version: 1.0
    Updated: 24 June 2026
    Author: Ian Reynolds : ianxreynolds@outlook.com
#>

[CmdletBinding()]
param(
    [string]$Month = (Get-Date -Format "yyyy-MMM"),

    [string]$OutputCsv = ".\MicrosoftPatchTuesday-Critical-$((Get-Date).ToString('yyyy-MMM')).csv",

    [switch]$AllSeverities
)

$ErrorActionPreference = "Stop"

function Convert-ToArray {
    param($InputObject)

    if ($null -eq $InputObject) {
        return @()
    }

    if ($InputObject -is [System.Array]) {
        return $InputObject
    }

    return @($InputObject)
}

function Test-HasProperty {
    param(
        $Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $false
    }

    return $null -ne ($Object.PSObject.Properties[$PropertyName])
}

function Get-PropertyValueSafe {
    param(
        $Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    if (Test-HasProperty -Object $Object -PropertyName $PropertyName) {
        return $Object.$PropertyName
    }

    return $null
}

function Get-TextValue {
    param($Object)

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [string]) {
        return $Object
    }

    if (Test-HasProperty -Object $Object -PropertyName "Value") {
        return $Object.Value
    }

    if (Test-HasProperty -Object $Object -PropertyName "#text") {
        return $Object."#text"
    }

    return $Object.ToString()
}

function Invoke-JsonGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $headers = @{
        "Accept"     = "application/json"
        "User-Agent" = "PatchTuesdayCriticalCheck/1.5"
    }

    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Get-MsrcMonthId {
    param(
        [Parameter(Mandatory)]
        [string]$InputMonth
    )

    $monthMap = @{
        "jan" = "Jan"; "january" = "Jan"; "01" = "Jan"; "1" = "Jan"
        "feb" = "Feb"; "february" = "Feb"; "02" = "Feb"; "2" = "Feb"
        "mar" = "Mar"; "march" = "Mar"; "03" = "Mar"; "3" = "Mar"
        "apr" = "Apr"; "april" = "Apr"; "04" = "Apr"; "4" = "Apr"
        "may" = "May"; "05" = "May"; "5" = "May"
        "jun" = "Jun"; "june" = "Jun"; "06" = "Jun"; "6" = "Jun"
        "jul" = "Jul"; "july" = "Jul"; "07" = "Jul"; "7" = "Jul"
        "aug" = "Aug"; "august" = "Aug"; "08" = "Aug"; "8" = "Aug"
        "sep" = "Sep"; "sept" = "Sep"; "september" = "Sep"; "09" = "Sep"; "9" = "Sep"
        "oct" = "Oct"; "october" = "Oct"; "10" = "Oct"
        "nov" = "Nov"; "november" = "Nov"; "11" = "Nov"
        "dec" = "Dec"; "december" = "Dec"; "12" = "Dec"
    }

    $year = (Get-Date).Year
    $monthPart = $null

    if ($InputMonth -match '^(\d{4})[-/ ]([A-Za-z0-9]+)$') {
        $year = [int]$matches[1]
        $monthPart = $matches[2]
    }
    elseif ($InputMonth -match '^([A-Za-z0-9]+)[-/ ](\d{4})$') {
        $monthPart = $matches[1]
        $year = [int]$matches[2]
    }
    elseif ($InputMonth -match '^[A-Za-z0-9]+$') {
        $monthPart = $InputMonth
    }
    else {
        throw "Month format not recognised. Use examples like 2026-Jun, Jun, June, 2026-06, or 06-2026."
    }

    $key = $monthPart.ToLowerInvariant()

    if (-not $monthMap.ContainsKey($key)) {
        throw "Month value '$monthPart' was not recognised."
    }

    return "$year-$($monthMap[$key])"
}

function Get-ThreatDescriptions {
    param(
        $Threats,
        [object[]]$TypeMatches
    )

    $results = New-Object System.Collections.Generic.List[string]

    foreach ($threat in Convert-ToArray $Threats) {
        $threatType = Get-PropertyValueSafe -Object $threat -PropertyName "Type"

        $matched = $false

        foreach ($typeMatch in $TypeMatches) {
            if ("$threatType" -eq "$typeMatch") {
                $matched = $true
            }
        }

        if (-not $matched) {
            continue
        }

        $description = Get-PropertyValueSafe -Object $threat -PropertyName "Description"
        $text = Get-TextValue -Object $description

        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $results.Add($text)
        }
    }

    return $results.ToArray()
}

function Get-SeverityRank {
    param([string[]]$SeverityValues)

    $values = Convert-ToArray $SeverityValues

    if ($values -contains "Critical") {
        return "Critical"
    }

    if ($values -contains "Important") {
        return "Important"
    }

    if ($values -contains "Moderate") {
        return "Moderate"
    }

    if ($values -contains "Low") {
        return "Low"
    }

    return ""
}

function Get-MaxCvss {
    param($CvssScoreSets)

    $scores = New-Object System.Collections.Generic.List[double]

    foreach ($scoreSet in Convert-ToArray $CvssScoreSets) {
        $baseScore = Get-PropertyValueSafe -Object $scoreSet -PropertyName "BaseScore"

        if ($null -ne $baseScore -and $baseScore -ne "") {
            try {
                $scores.Add([double]$baseScore)
            }
            catch {
                # Ignore malformed scores
            }
        }
    }

    if ($scores.Count -gt 0) {
        return ($scores | Measure-Object -Maximum).Maximum
    }

    return $null
}

function Get-NoteValue {
    param(
        $Notes,
        [string]$Title
    )

    foreach ($note in Convert-ToArray $Notes) {
        $noteTitle = Get-PropertyValueSafe -Object $note -PropertyName "Title"

        if ($noteTitle -eq $Title) {
            return Get-TextValue -Object $note
        }
    }

    return $null
}

function Get-KbsFromRemediations {
    param($Remediations)

    $kbList = New-Object System.Collections.Generic.List[string]

    foreach ($remediation in Convert-ToArray $Remediations) {
        $description = Get-PropertyValueSafe -Object $remediation -PropertyName "Description"
        $url = Get-PropertyValueSafe -Object $remediation -PropertyName "URL"

        foreach ($candidate in @((Get-TextValue -Object $description), $url)) {
            if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                $matches = [regex]::Matches($candidate, 'KB\d{6,8}|\b\d{6,8}\b')

                foreach ($match in $matches) {
                    $value = $match.Value

                    if ($value -notmatch '^KB') {
                        $value = "KB$value"
                    }

                    if (-not $kbList.Contains($value)) {
                        $kbList.Add($value)
                    }
                }
            }
        }
    }

    return ($kbList | Sort-Object) -join "; "
}

function Get-ProductMap {
    param($ProductTree)

    $map = @{}

    function Walk-Node {
        param($Node)

        foreach ($nodeItem in Convert-ToArray $Node) {
            if ($null -eq $nodeItem) {
                continue
            }

            $fullProductName = Get-PropertyValueSafe -Object $nodeItem -PropertyName "FullProductName"

            foreach ($product in Convert-ToArray $fullProductName) {
                $productId = Get-PropertyValueSafe -Object $product -PropertyName "ProductID"
                $productName = Get-TextValue -Object $product

                if (-not [string]::IsNullOrWhiteSpace($productId) -and
                    -not [string]::IsNullOrWhiteSpace($productName)) {
                    $map[$productId] = $productName
                }
            }

            $branch = Get-PropertyValueSafe -Object $nodeItem -PropertyName "Branch"
            if ($null -ne $branch) {
                Walk-Node -Node $branch
            }

            $items = Get-PropertyValueSafe -Object $nodeItem -PropertyName "Items"
            if ($null -ne $items) {
                Walk-Node -Node $items
            }
        }
    }

    Walk-Node -Node $ProductTree

    return $map
}

function Get-ProductIdsFromVulnerability {
    param($Vulnerability)

    $set = New-Object System.Collections.Generic.HashSet[string]

    $productStatuses = Get-PropertyValueSafe -Object $Vulnerability -PropertyName "ProductStatuses"
    $statusProductIds = Get-PropertyValueSafe -Object $productStatuses -PropertyName "ProductID"

    foreach ($productIdValue in Convert-ToArray $statusProductIds) {
        if (-not [string]::IsNullOrWhiteSpace($productIdValue)) {
            [void]$set.Add([string]$productIdValue)
        }
    }

    foreach ($propertyName in @("Threats", "Remediations", "CVSSScoreSets")) {
        $items = Get-PropertyValueSafe -Object $Vulnerability -PropertyName $propertyName

        foreach ($item in Convert-ToArray $items) {
            $productIds = Get-PropertyValueSafe -Object $item -PropertyName "ProductID"

            foreach ($productIdValue in Convert-ToArray $productIds) {
                if (-not [string]::IsNullOrWhiteSpace($productIdValue)) {
                    [void]$set.Add([string]$productIdValue)
                }
            }
        }
    }

    return $set
}

function Get-ProductNamesForVulnerability {
    param(
        $Vulnerability,
        [hashtable]$ProductMap
    )

    $productIds = Get-ProductIdsFromVulnerability -Vulnerability $Vulnerability

    $names = foreach ($productIdValue in $productIds) {
        if ($ProductMap.ContainsKey($productIdValue)) {
            $ProductMap[$productIdValue]
        }
        else {
            $productIdValue
        }
    }

    return ($names | Sort-Object -Unique) -join "; "
}

function Get-ExploitStatusText {
    param($Threats)

    # In MSRC CVRF, exploit status is normally Threat Type 1.
    # Some older or transformed responses may use text labels, so this accepts both.
    $values = Get-ThreatDescriptions -Threats $Threats -TypeMatches @(1, "1", "Exploit Status")

    return ($values | Sort-Object -Unique) -join "; "
}

function Test-MsrcExploited {
    param([string]$ExploitStatusText)

    if ([string]::IsNullOrWhiteSpace($ExploitStatusText)) {
        return $false
    }

    return $ExploitStatusText -match 'Exploited\s*:\s*Yes'
}

function Test-MsrcPubliclyDisclosed {
    param([string]$ExploitStatusText)

    if ([string]::IsNullOrWhiteSpace($ExploitStatusText)) {
        return $false
    }

    return $ExploitStatusText -match 'Publicly\s+Disclosed\s*:\s*Yes'
}

try {
    $monthId = Get-MsrcMonthId -InputMonth $Month

    Write-Host "Pulling Microsoft security update data for $monthId..."

    $msrcUri = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$monthId"
    $cvrf = Invoke-JsonGet -Uri $msrcUri

    Write-Host "Pulling CISA KEV catalog..."

    $kevUri = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    $kev = Invoke-JsonGet -Uri $kevUri

    $kevByCve = @{}

    foreach ($kevEntryCandidate in Convert-ToArray (Get-PropertyValueSafe -Object $kev -PropertyName "vulnerabilities")) {
        $cveId = Get-PropertyValueSafe -Object $kevEntryCandidate -PropertyName "cveID"

        if (-not [string]::IsNullOrWhiteSpace($cveId)) {
            $kevByCve[$cveId] = $kevEntryCandidate
        }
    }

    $productTree = Get-PropertyValueSafe -Object $cvrf -PropertyName "ProductTree"
    $productMap = Get-ProductMap -ProductTree $productTree

    $vulnerabilities = Get-PropertyValueSafe -Object $cvrf -PropertyName "Vulnerability"

    if ($null -eq $vulnerabilities) {
        throw "No Vulnerability collection was found in the MSRC response for $monthId."
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($vuln in Convert-ToArray $vulnerabilities) {
        $cve = Get-PropertyValueSafe -Object $vuln -PropertyName "CVE"

        if ([string]::IsNullOrWhiteSpace($cve)) {
            continue
        }

        $title = Get-TextValue -Object (Get-PropertyValueSafe -Object $vuln -PropertyName "Title")
        $threats = Get-PropertyValueSafe -Object $vuln -PropertyName "Threats"
        $remediations = Get-PropertyValueSafe -Object $vuln -PropertyName "Remediations"
        $cvssScoreSets = Get-PropertyValueSafe -Object $vuln -PropertyName "CVSSScoreSets"
        $notes = Get-PropertyValueSafe -Object $vuln -PropertyName "Notes"

        # MSRC CVRF threat type mapping commonly used by Microsoft's own module:
        # Type 3 = Severity
        # Type 0 = Impact
        # Type 1 = Exploit Status
        $severityValues = Get-ThreatDescriptions -Threats $threats -TypeMatches @(3, "3", "Severity")
        $impactValues   = Get-ThreatDescriptions -Threats $threats -TypeMatches @(0, "0", "Impact")

        $severity = Get-SeverityRank -SeverityValues $severityValues
        $impact = ($impactValues | Sort-Object -Unique) -join "; "

        $exploitStatusText = Get-ExploitStatusText -Threats $threats
        $msExploited = Test-MsrcExploited -ExploitStatusText $exploitStatusText
        $msPubliclyDisclosed = Test-MsrcPubliclyDisclosed -ExploitStatusText $exploitStatusText

        $maxCvss = Get-MaxCvss -CvssScoreSets $cvssScoreSets

        $cisaKev = $kevByCve.ContainsKey($cve)

        $kevDateAdded = $null
        $kevDueDate = $null
        $kevRansomware = $null
        $kevRequiredAction = $null

        if ($cisaKev) {
            $kevEntry = $kevByCve[$cve]
            $kevDateAdded = Get-PropertyValueSafe -Object $kevEntry -PropertyName "dateAdded"
            $kevDueDate = Get-PropertyValueSafe -Object $kevEntry -PropertyName "dueDate"
            $kevRansomware = Get-PropertyValueSafe -Object $kevEntry -PropertyName "knownRansomwareCampaignUse"
            $kevRequiredAction = Get-PropertyValueSafe -Object $kevEntry -PropertyName "requiredAction"
        }

        if ($msExploited -or $cisaKev) {
            $exploitSignal = "Known exploited"
        }
        elseif ($msPubliclyDisclosed) {
            $exploitSignal = "Publicly disclosed"
        }
        else {
            $exploitSignal = "No public exploit signal found in MSRC/CISA"
        }

        $row = [pscustomobject]@{
            Month                       = $monthId
            CVE                         = $cve
            Title                       = $title
            Severity                    = $severity
            RawSeverityValues           = ($severityValues | Sort-Object -Unique) -join "; "
            MaxCVSS                     = $maxCvss
            Impact                      = $impact
            ExploitStatusText           = $exploitStatusText
            MicrosoftExploited          = $msExploited
            MicrosoftPubliclyDisclosed  = $msPubliclyDisclosed
            CISA_KEV                    = $cisaKev
            CISA_KEV_DateAdded          = $kevDateAdded
            CISA_KEV_DueDate            = $kevDueDate
            CISA_RansomwareUse          = $kevRansomware
            ExploitSignal               = $exploitSignal
            KBs                         = Get-KbsFromRemediations -Remediations $remediations
            Products                    = Get-ProductNamesForVulnerability -Vulnerability $vuln -ProductMap $productMap
            ExecutiveSummary            = Get-NoteValue -Notes $notes -Title "Description"
            Mitigations                 = Get-NoteValue -Notes $notes -Title "Mitigations"
            Workarounds                 = Get-NoteValue -Notes $notes -Title "Workarounds"
            MSRCUrl                     = "https://msrc.microsoft.com/update-guide/vulnerability/$cve"
            CISARequiredAction          = $kevRequiredAction
        }

        $rows.Add($row)
    }

    $allRows = $rows.ToArray()

    Write-Host ""
    Write-Host "Total CVEs found before severity filtering: $((Convert-ToArray $allRows).Length)"

    $severityBreakdown = $allRows |
        Group-Object Severity |
        Select-Object Name, Count |
        Sort-Object Count -Descending

    Write-Host ""
    Write-Host "Severity breakdown:"
    $severityBreakdown | Format-Table -AutoSize

    $outputRows = $allRows

    if (-not $AllSeverities) {
        $outputRows = @($outputRows | Where-Object { $_.Severity -eq 'Critical' })
    }

    $outputRows = @(
        $outputRows | Sort-Object `
            @{ Expression = { $_.CISA_KEV }; Descending = $true },
            @{ Expression = { $_.MicrosoftExploited }; Descending = $true },
            @{ Expression = { $_.MicrosoftPubliclyDisclosed }; Descending = $true },
            @{ Expression = { $_.MaxCVSS }; Descending = $true },
            CVE
    )

    $outputRows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Report written to: $OutputCsv"
    Write-Host ""

    $outputRows |
        Select-Object `
            CVE,
            Severity,
            MaxCVSS,
            Impact,
            MicrosoftExploited,
            MicrosoftPubliclyDisclosed,
            CISA_KEV,
            ExploitSignal,
            KBs |
        Format-Table -AutoSize

    Write-Host ""
    if ($AllSeverities) {
        Write-Host "Vulnerabilities exported: $((Convert-ToArray $outputRows).Length)"
    }
    else {
        Write-Host "Critical vulnerabilities exported: $((Convert-ToArray $outputRows).Length)"
    }

    Write-Host ""
    Write-Host "Tip: run with -AllSeverities if you want to confirm the full monthly data set:"
    Write-Host ".\Get-MicrosoftCriticalPatches.ps1 -Month $monthId -AllSeverities"
}
catch {
    Write-Error $_
    exit 1
}