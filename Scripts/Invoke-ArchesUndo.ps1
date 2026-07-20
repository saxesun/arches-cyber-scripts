[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Approved
)

$moduleRoot = Join-Path $PSScriptRoot 'Modules'
Import-Module (Join-Path $moduleRoot 'Rollback.psm1') -Force -ErrorAction Stop

$record = Get-ArchesRollbackRecord -Path $Path
Write-Host "Rollback record: $($record.RecordId)"
Write-Host "Remediation: $($record.RemediationId)"
Write-Host "Protection tier: $($record.ProtectionTier)"
Write-Host "Computer: $($record.ComputerName)"
Write-Host 'Changes to restore:'
$record.Changes | Format-Table TargetType, Target, Property, Before, After -AutoSize

Restore-ArchesRollback -Path $Path -Approved:$Approved -WhatIf:$WhatIfPreference -Confirm:$false
