[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateSet('FIX-FW-001','FIX-DNS-001')][string]$Id,
    [switch]$Approved,
    [switch]$ExternalProtectionConfirmed
)

$moduleRoot = Join-Path $PSScriptRoot 'Modules'
@('Results.psm1','Diagnostics.psm1','Rollback.psm1','Remediation.psm1') | ForEach-Object {
    Import-Module (Join-Path $moduleRoot $_) -Force -ErrorAction Stop
}
$rollbackDirectory = Join-Path $PSScriptRoot 'Rollback'
$plan = New-ArchesRemediationPlan -Id $Id
Show-ArchesRemediationPlan -Plan $plan
Invoke-ArchesRemediation -Plan $plan -RollbackDirectory $rollbackDirectory `
    -Approved:$Approved -ExternalProtectionConfirmed:$ExternalProtectionConfirmed `
    -WhatIf:$WhatIfPreference -Confirm:$false
