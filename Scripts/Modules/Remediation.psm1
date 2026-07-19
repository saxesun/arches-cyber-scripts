Set-StrictMode -Version 2.0

function Get-ArchesRemediationCatalog {
    @(
        [PSCustomObject]@{ Id='FIX-FW-001'; Title='Enable Windows Firewall profiles'; Risk='Low'; RequiresRestart=$false; RequiresAdmin=$true; Reversible=$true }
        [PSCustomObject]@{ Id='FIX-DNS-001'; Title='Flush the DNS resolver cache'; Risk='Low'; RequiresRestart=$false; RequiresAdmin=$false; Reversible=$false }
    )
}

function Invoke-ArchesRemediation {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][ValidateSet('FIX-FW-001','FIX-DNS-001')][string]$Id,
        [Parameter(Mandatory)][string]$RollbackDirectory,
        [switch]$Approved
    )
    if (-not $Approved) { throw "Remediation $Id requires explicit approval. Rerun with -Approved after reviewing the change." }
    switch ($Id) {
        'FIX-FW-001' {
            if (-not (Test-ArchesAdministrator)) { throw 'Administrator privileges are required to change firewall profiles.' }
            $before = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled)
            $disabledNames = @($before | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
            if (-not $disabledNames.Count) { return [PSCustomObject]@{ Id=$Id; Changed=$false; Message='All firewall profiles were already enabled.'; RollbackPath=$null } }
            $restore = ($disabledNames | ForEach-Object { "Set-NetFirewallProfile -Profile '$_' -Enabled False" }) -join '; '
            $rollback = New-ArchesRollbackRecord -Directory $RollbackDirectory -RemediationId $Id -BeforeState $before -RestoreCommand $restore -Description 'Firewall profile enabled state before remediation.'
            if ($PSCmdlet.ShouldProcess(($disabledNames -join ', '), 'Enable Windows Firewall profile(s)')) {
                Set-NetFirewallProfile -Profile $disabledNames -Enabled True -ErrorAction Stop
                Set-ArchesRollbackApplied -Path $rollback
                [PSCustomObject]@{ Id=$Id; Changed=$true; Message='Disabled firewall profiles were enabled.'; RollbackPath=$rollback }
            }
        }
        'FIX-DNS-001' {
            if ($PSCmdlet.ShouldProcess('DNS client cache', 'Clear')) {
                Clear-DnsClientCache -ErrorAction Stop
                [PSCustomObject]@{ Id=$Id; Changed=$true; Message='DNS resolver cache cleared.'; RollbackPath=$null }
            }
        }
    }
}

Export-ModuleMember -Function Get-ArchesRemediationCatalog, Invoke-ArchesRemediation
