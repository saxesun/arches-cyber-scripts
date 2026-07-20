Set-StrictMode -Version 2.0

if (-not (Get-Command ConvertTo-ArchesSafeEvidence -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'Privacy.psm1') -ErrorAction Stop
}

function Get-ArchesSeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 0 }
        'High'     { 1 }
        'Medium'   { 2 }
        'Low'      { 3 }
        'Info'     { 4 }
        default    { 5 }
    }
}

function New-ArchesResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Pass','Warning','Fail','Unknown','Error')][string]$Status,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity = 'Info',
        [string]$Summary,
        [object]$Evidence,
        [string]$Recommendation,
        [string]$RemediationId,
        [bool]$RequiresAdmin = $false
    )
    [PSCustomObject][ordered]@{
        Id = $Id; Category = $Category; Title = $Title; Status = $Status
        Severity = $Severity; Summary = $Summary
        Evidence = ConvertTo-ArchesSafeEvidence -Id $Id -Evidence $Evidence -DiagnosticError:($Status -eq 'Error')
        Recommendation = $Recommendation; RemediationId = $RemediationId
        RequiresAdmin = $RequiresAdmin; CheckedAt = (Get-Date).ToString('o')
    }
}

function Sort-ArchesResults {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][object[]]$Result)
    begin { $items = @() }
    process { $items += $Result }
    end { $items | Sort-Object @{Expression={ Get-ArchesSeverityRank $_.Severity }}, Category, Title }
}

function Get-ArchesProblems {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][object[]]$Result)
    begin { $items = @() }
    process { $items += $Result }
    end { $items | Where-Object { $_.Status -in @('Warning','Fail','Error','Unknown') } | Sort-ArchesResults }
}

Export-ModuleMember -Function New-ArchesResult, Get-ArchesSeverityRank, Sort-ArchesResults, Get-ArchesProblems
