#requires -Version 3
<#
.SYNOPSIS
CHAPS Analysis Tool -- converts a CHAPS Markdown report into a structured
findings analysis with recommendations and MITRE ATT&CK mappings.

.DESCRIPTION
Parses a CHAPS-generated Markdown report, matches negative findings against
a bundled JSON knowledge base, and emits structured Markdown suitable for
human review or ingestion into AI reporting and threat-modeling tools.

The output is deliberately neutral-factual. Defender AI tools reframe it
into remediation plans or executive summaries; pentest AI tools reframe it
into attack plans. The source document serves both audiences.

.PARAMETER InputReport
Path to a CHAPS-generated Markdown report (the file produced by redirecting
chaps_PSv3.ps1, chaps_PSv2.ps1, or chaps.bat output).

.PARAMETER KnowledgeOverride
Optional path to a JSON file whose entries override or extend the bundled
knowledge base. Entries with the same key as a bundled entry replace it;
new keys are added.

.EXAMPLE
.\chaps-analyze.ps1 -InputReport Win10-chaps.md > Win10-analysis.md

.EXAMPLE
.\chaps-analyze.ps1 -InputReport report.md -KnowledgeOverride myorg-findings.json > analysis.md

.NOTES
No external dependencies. No logging, no telemetry, no network calls.
Output goes to stdout; redirect to capture.

Author: Cutaway Security, LLC
License: GNU GPL v3
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputReport,

    [Parameter(Mandatory=$false)]
    [string]$KnowledgeOverride
)

$scriptVersion = '1.0.0'

function Fail {
    param([string]$Message, [int]$Code = 2)
    [Console]::Error.WriteLine("chaps-analyze: $Message")
    exit $Code
}

# ----------------------------------------------------------------------------
# Input validation
# ----------------------------------------------------------------------------

if (-not (Test-Path -Path $InputReport -PathType Leaf)) {
    Fail "Input report not found: $InputReport"
}

$reportLines = Get-Content -Path $InputReport

# Accept both PSv3/PSv2 header ("# CHAPS Report: ...") and CMD header ("# CHAPS Report")
if ($reportLines.Count -eq 0 -or $reportLines[0] -notmatch '^# CHAPS Report(\b|:)') {
    Fail "Input does not appear to be a CHAPS report (first line does not start with '# CHAPS Report')."
}

# ----------------------------------------------------------------------------
# Load knowledge base (bundled + optional override)
# ----------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$bundledKbPath = Join-Path -Path $scriptDir -ChildPath 'knowledge\findings.json'

if (-not (Test-Path -Path $bundledKbPath -PathType Leaf)) {
    Fail "Bundled knowledge base not found at: $bundledKbPath" 3
}

$kb = @{}

Try {
    $bundledRaw = Get-Content -Path $bundledKbPath -Raw
    $bundledJson = $bundledRaw | ConvertFrom-Json
    foreach ($prop in $bundledJson.PSObject.Properties) {
        $kb[$prop.Name] = $prop.Value
    }
}
Catch {
    Fail "Failed to parse bundled knowledge base: $($_.Exception.Message)" 3
}

if ($KnowledgeOverride) {
    if (-not (Test-Path -Path $KnowledgeOverride -PathType Leaf)) {
        Fail "Override knowledge base not found: $KnowledgeOverride" 3
    }
    Try {
        $overrideRaw = Get-Content -Path $KnowledgeOverride -Raw
        $overrideJson = $overrideRaw | ConvertFrom-Json
        foreach ($prop in $overrideJson.PSObject.Properties) {
            $kb[$prop.Name] = $prop.Value
        }
    }
    Catch {
        Fail "Failed to parse override knowledge base: $($_.Exception.Message)" 3
    }
}

# ----------------------------------------------------------------------------
# Parse CHAPS report: metadata + sections + findings
# ----------------------------------------------------------------------------

$metadata = @{
    hostname  = ''
    starttime = ''
    psversion = ''
    osversion = ''
    admin     = ''
    company   = ''
    site      = ''
    script    = ''
}

$sections = [ordered]@{}
$currentSection = 'Preamble'
$sections[$currentSection] = @{ Positive = @(); Negative = @(); Info = @(); Error = @() }

foreach ($line in $reportLines) {
    # Metadata table rows (format: | Field | Value |)
    # PSv3/PSv2 use: Hostname, Start Time, PS Version, OS Version, Admin Status, Auditing Company, Site/Plant
    # CMD uses:      Script, Computer, Date, Admin, Company, Site
    if ($line -match '^\|\s*(Hostname|Computer|Start Time|Date|PS Version|OS Version|Admin Status|Admin|Auditing Company|Company|Site/Plant|Site|Script)\s*\|\s*(.+?)\s*\|\s*$') {
        $field = $Matches[1]
        $value = $Matches[2].Trim()
        switch ($field) {
            'Hostname'         { $metadata.hostname  = $value }
            'Computer'         { $metadata.hostname  = $value }
            'Start Time'       { $metadata.starttime = $value }
            'Date'             { $metadata.starttime = $value }
            'PS Version'       { $metadata.psversion = $value }
            'OS Version'       { $metadata.osversion = $value }
            'Admin Status'     { $metadata.admin     = $value }
            'Admin'            { $metadata.admin     = $value }
            'Auditing Company' { $metadata.company   = $value }
            'Company'          { $metadata.company   = $value }
            'Site/Plant'       { $metadata.site      = $value }
            'Site'             { $metadata.site      = $value }
            'Script'           { $metadata.script    = $value }
        }
        continue
    }

    # Section heading: "## Section Name"
    if ($line -match '^##\s+(.+?)\s*$') {
        $currentSection = $Matches[1].Trim()
        if (-not $sections.Contains($currentSection)) {
            $sections[$currentSection] = @{ Positive = @(); Negative = @(); Info = @(); Error = @() }
        }
        continue
    }

    # Finding line: "[+] text", "[-] text", "[*] text", "[x] text"
    if ($line -match '^\[(\+|\-|\*|x)\]\s*(.*)$') {
        $prefix = $Matches[1]
        $text   = $Matches[2].TrimEnd()
        if (-not $sections.Contains($currentSection)) {
            $sections[$currentSection] = @{ Positive = @(); Negative = @(); Info = @(); Error = @() }
        }
        switch ($prefix) {
            '+' { $sections[$currentSection].Positive += $text }
            '-' { $sections[$currentSection].Negative += $text }
            '*' { $sections[$currentSection].Info     += $text }
            'x' { $sections[$currentSection].Error    += $text }
        }
    }
}

# ----------------------------------------------------------------------------
# Match negative findings against the knowledge base
# ----------------------------------------------------------------------------

# Canonical section order for output stability
$canonicalSections = @(
    'System Info Checks',
    'Security Checks',
    'Authentication Checks',
    'Network Checks',
    'PowerShell Checks',
    'Logging Checks'
)

$matchedFindings = @()
$unmatchedFindings = @()

foreach ($sectionName in $canonicalSections) {
    if (-not $sections.Contains($sectionName)) { continue }
    foreach ($finding in $sections[$sectionName].Negative) {
        $matchedEntry = $null
        $matchedKey = $null
        foreach ($key in $kb.Keys) {
            $entry = $kb[$key]
            if (-not $entry.matches) { continue }
            foreach ($pattern in $entry.matches) {
                if ($finding -like "*$pattern*") {
                    $matchedEntry = $entry
                    $matchedKey = $key
                    break
                }
            }
            if ($matchedEntry) { break }
        }
        if ($matchedEntry) {
            $matchedFindings += [PSCustomObject]@{
                Finding = $finding
                Section = $sectionName
                Key     = $matchedKey
                Entry   = $matchedEntry
            }
        }
        else {
            $unmatchedFindings += [PSCustomObject]@{
                Finding = $finding
                Section = $sectionName
            }
        }
    }
}

# Group matched findings by severity for ordered output
$severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
$bySeverity = [ordered]@{}
foreach ($sev in $severityOrder) { $bySeverity[$sev] = @() }
foreach ($m in $matchedFindings) {
    $sev = if ($m.Entry.severity) { [string]$m.Entry.severity } else { 'Medium' }
    if (-not $bySeverity.Contains($sev)) { $bySeverity[$sev] = @() }
    $bySeverity[$sev] += $m
}

# ----------------------------------------------------------------------------
# Emit output
# ----------------------------------------------------------------------------

Write-Output "# CHAPS Analysis Report"
Write-Output ""

# Metadata
Write-Output "## Metadata"
Write-Output ""
Write-Output "| Field | Value |"
Write-Output "|---|---|"
if ($metadata.hostname)  { Write-Output "| Target | $($metadata.hostname) |" }
if ($metadata.starttime) { Write-Output "| Collection date | $($metadata.starttime) |" }
if ($metadata.osversion) { Write-Output "| OS | $($metadata.osversion) |" }
if ($metadata.psversion) { Write-Output "| PS Version | $($metadata.psversion) |" }
if ($metadata.script)    { Write-Output "| Collected by | $($metadata.script) |" }
if ($metadata.admin)     { Write-Output "| Admin context | $($metadata.admin) |" }
if ($metadata.company)   { Write-Output "| Company | $($metadata.company) |" }
if ($metadata.site)      { Write-Output "| Site | $($metadata.site) |" }
Write-Output "| Analyzed on | $(Get-Date -Format 'yyyy-MM-dd HH:mm K') |"
Write-Output "| Analyzer version | $scriptVersion |"
Write-Output "| Source report | $(Split-Path -Leaf $InputReport) |"
Write-Output ""

# OT/ICS advisory
Write-Output "## OT/ICS Advisory"
Write-Output ""
Write-Output "This report evaluates Windows hardening against general security best practice. Some recommendations -- particularly those involving SMBv1, NTLMv1, old TLS versions, legacy script hosts, and default SMB shares -- can break legacy ICS/OT applications. Validate every change in a non-production environment before applying to production HMIs, engineering workstations, historians, or controller-adjacent systems."
Write-Output ""

# Summary table
Write-Output "## Summary"
Write-Output ""
Write-Output "| Section | Positive | Negative | Informational | Errors |"
Write-Output "|---|---:|---:|---:|---:|"
$totalPos = 0; $totalNeg = 0; $totalInfo = 0; $totalErr = 0
foreach ($sectionName in $canonicalSections) {
    if (-not $sections.Contains($sectionName)) { continue }
    $s = $sections[$sectionName]
    Write-Output "| $sectionName | $($s.Positive.Count) | $($s.Negative.Count) | $($s.Info.Count) | $($s.Error.Count) |"
    $totalPos  += $s.Positive.Count
    $totalNeg  += $s.Negative.Count
    $totalInfo += $s.Info.Count
    $totalErr  += $s.Error.Count
}
Write-Output "| **Total** | **$totalPos** | **$totalNeg** | **$totalInfo** | **$totalErr** |"
Write-Output ""

# Severity breakdown
$breakdownParts = @()
foreach ($sev in $severityOrder) {
    if ($bySeverity[$sev].Count -gt 0) {
        $breakdownParts += "$($bySeverity[$sev].Count) $sev"
    }
}
if ($unmatchedFindings.Count -gt 0) {
    $breakdownParts += "$($unmatchedFindings.Count) Unclassified"
}
if ($breakdownParts.Count -eq 0) {
    Write-Output "No negative findings detected."
}
else {
    Write-Output "Severity breakdown of negative findings: $($breakdownParts -join ', ')."
}
Write-Output ""

# Negative findings detail
if ($matchedFindings.Count -gt 0) {
    Write-Output "## Negative Findings"
    Write-Output ""
    foreach ($sev in $severityOrder) {
        foreach ($m in $bySeverity[$sev]) {
            $entry = $m.Entry
            $title = if ($entry.title) { $entry.title } else { 'Untitled finding' }
            Write-Output "### [$sev] $title"
            Write-Output ""
            $sectionLabel = if ($entry.section -and $entry.check) {
                "$($entry.section) ($($entry.check))"
            } elseif ($entry.section) {
                $entry.section
            } else {
                $m.Section
            }
            Write-Output "**Section:** $sectionLabel"
            Write-Output ""
            Write-Output "**Observation:** ``$($m.Finding)``"
            Write-Output ""
            if ($entry.technical_detail) {
                Write-Output "**Technical detail:** $($entry.technical_detail)"
                Write-Output ""
            }
            if ($entry.risk) {
                Write-Output "**Risk:** $($entry.risk)"
                Write-Output ""
            }
            if ($entry.recommendation) {
                Write-Output "**Recommendation:** $($entry.recommendation)"
                Write-Output ""
            }
            if ($entry.mitre_attack -and $entry.mitre_attack.Count -gt 0) {
                $mitreParts = @()
                foreach ($t in $entry.mitre_attack) {
                    $mitreParts += "$($t.id) $($t.name)"
                }
                Write-Output "**MITRE ATT&CK:** $($mitreParts -join '; ')"
                Write-Output ""
            }
            if ($entry.related_findings -and $entry.related_findings.Count -gt 0) {
                Write-Output "**Related findings in knowledge base:** $($entry.related_findings -join ', ')"
                Write-Output ""
            }
            if ($entry.references -and $entry.references.Count -gt 0) {
                Write-Output "**References:** $($entry.references -join ' · ')"
                Write-Output ""
            }
            Write-Output "---"
            Write-Output ""
        }
    }
}

# Unclassified findings (succinct list)
if ($unmatchedFindings.Count -gt 0) {
    Write-Output "## Unclassified Findings"
    Write-Output ""
    Write-Output "These negative findings have no knowledge-base entry. Review against docs/CHECKS.md and docs/REMEDIATION.md."
    Write-Output ""
    foreach ($u in $unmatchedFindings) {
        Write-Output "- **$($u.Section):** $($u.Finding)"
    }
    Write-Output ""
}

# Incomplete checks appendix
if ($totalErr -gt 0) {
    Write-Output "## Appendix A: Incomplete Checks"
    Write-Output ""
    Write-Output "Checks that did not complete. Common causes: non-admin execution, isolated network, feature not installed."
    Write-Output ""
    foreach ($sectionName in $canonicalSections) {
        if (-not $sections.Contains($sectionName)) { continue }
        $errs = $sections[$sectionName].Error
        if ($errs.Count -eq 0) { continue }
        Write-Output "**${sectionName}:**"
        foreach ($e in $errs) { Write-Output "- $e" }
        Write-Output ""
    }
}

# Informational summary appendix
Write-Output "## Appendix B: Informational Evidence (summary)"
Write-Output ""
Write-Output "$totalInfo informational data points captured across all sections. Full detail is in the source CHAPS report."
Write-Output ""
