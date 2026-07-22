[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateSet('FIX-FW-001','FIX-DNS-001')][string]$Id,
    [switch]$Approved,
    [switch]$ManagementOwnershipAttested,
    [switch]$ExternalProtectionConfirmed
)

$moduleRoot = Join-Path $PSScriptRoot 'Modules'
@('Results.psm1','Diagnostics.psm1','Rollback.psm1','Remediation.psm1') | ForEach-Object {
    Import-Module (Join-Path $moduleRoot $_) -Force -ErrorAction Stop
}
$rollbackDirectory = Join-Path $PSScriptRoot 'Rollback'
$plan = New-ArchesRemediationPlan -Id $Id `
    -ManagementOwnershipAttested:$ManagementOwnershipAttested
Show-ArchesRemediationPlan -Plan $plan
$approvedAfterReview = $false
if (-not $WhatIfPreference) {
    if (-not $Approved) {
        throw "Remediation $Id requires explicit approval after reviewing the displayed plan. Rerun with -Approved."
    }
    $confirmation = Read-Host "Type APPROVE to run only the exact change shown above"
    $approvedAfterReview = $confirmation -ceq 'APPROVE'
    if (-not $approvedAfterReview) {
        Write-Host 'Remediation cancelled. No configuration changes were made.' -ForegroundColor Yellow
        return
    }
}
Invoke-ArchesRemediation -Plan $plan -RollbackDirectory $rollbackDirectory `
    -Approved:$approvedAfterReview -ExternalProtectionConfirmed:$ExternalProtectionConfirmed `
    -WhatIf:$WhatIfPreference -Confirm:$false
