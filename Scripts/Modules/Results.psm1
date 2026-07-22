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

function Get-ArchesBusinessImpact {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Category
    )
    if ($Status -eq 'Pass') {
        return 'This check did not identify a current adverse business impact.'
    }
    if ($Status -in @('Unknown', 'Error')) {
        switch ($Id) {
            'SEC-AV-001' { return 'Antivirus protection ownership or health could not be confirmed, so a protection gap could be missed until the state is reviewed.' }
            'NET-GW-001' { return 'Gateway and connectivity health could not be confirmed, so a real outage or policy block may remain hidden.' }
            'NET-DNS-001' { return 'Name-resolution reliability could not be confirmed, so access to websites and cloud services may be unreliable.' }
            'NET-INT-001' { return 'Outbound connectivity could not be confirmed, so access to cloud applications, updates, and communications may be unreliable.' }
            default { return "The $Category condition could not be confirmed, so related operational or security risk remains undetermined until reviewed." }
        }
    }

    switch ($Id) {
        'SEC-FW-001' { 'A disabled firewall profile can expose the computer to unwanted inbound network traffic, especially on untrusted networks.' }
        'SEC-AV-001' { 'Missing or uncertain antivirus protection can allow malware to remain undetected and disrupt access to business systems or data.' }
        'SEC-RDP-001' { 'Unnecessary Remote Desktop access increases the paths an attacker can use to reach the computer.' }
        'SEC-BL-001' { 'Without drive encryption, business data may be readable if the computer or its storage is lost or stolen.' }
        'SEC-SB-001' { 'Disabled Secure Boot weakens protection against malicious or unauthorized code loading before Windows starts.' }
        'SEC-ADM-001' { 'Excess administrator access increases the chance that malware or an account mistake can make system-wide changes.' }
        'NET-GW-001' { 'Gateway problems can interrupt internet, cloud, voice, and other network-dependent business services.' }
        'NET-DNS-001' { 'DNS problems can make websites and cloud services appear offline even when the underlying internet connection works.' }
        'NET-INT-001' { 'Uncertain or failed outbound connectivity can prevent access to cloud applications, updates, remote support, and communications.' }
        'SYS-DISK-001' { 'Low disk space can cause slowdowns, failed updates, application errors, and loss of productive work time.' }
        'SYS-BOOT-001' { 'Long periods without a restart can leave updates unfinished and allow temporary performance or service problems to accumulate.' }
        'SYS-UPD-001' { 'A disabled or unhealthy Windows Update service can leave known security flaws and reliability fixes unapplied.' }
        'SYS-W11-001' { 'Hardware readiness gaps can block a supported Windows 11 transition and create future support or security-planning costs.' }
        'PERF-MEM-001' { 'Low available memory can make applications slow or unstable and reduce employee productivity.' }
        'PERF-CPU-001' { 'Sustained high processor use can cause slow response times, application freezes, and reduced productivity.' }
        default { "This $Category condition may affect security, reliability, or productivity and should be reviewed." }
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
        [string]$BusinessImpact,
        [object]$Evidence,
        [string]$Recommendation,
        [string]$RemediationId,
        [bool]$RequiresAdmin = $false
    )
    if ([string]::IsNullOrWhiteSpace($BusinessImpact)) {
        $BusinessImpact = Get-ArchesBusinessImpact -Id $Id -Status $Status -Category $Category
    }
    [PSCustomObject][ordered]@{
        Id = $Id; Category = $Category; Title = $Title; Status = $Status
        Severity = $Severity; Summary = $Summary; BusinessImpact = $BusinessImpact
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
    end { $items | Where-Object { $_.Status -in @('Warning','Fail') } | Sort-ArchesResults }
}

Export-ModuleMember -Function New-ArchesResult, Get-ArchesBusinessImpact, Get-ArchesSeverityRank, Sort-ArchesResults, Get-ArchesProblems
