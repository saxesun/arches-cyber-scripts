Set-StrictMode -Version 2.0

function Get-ArchesRemediationCatalog {
    @(
        [PSCustomObject][ordered]@{
            Id = 'FIX-FW-001'
            Title = 'Enable Windows Firewall profiles'
            Risk = 'Low'
            RequiresRestart = $false
            RequiresAdmin = $true
            Reversible = $true
            ProtectionTier = 'ConfigOnly'
            AllowWithoutRestorePoint = $false
        }
        [PSCustomObject][ordered]@{
            Id = 'FIX-DNS-001'
            Title = 'Flush the DNS resolver cache'
            Risk = 'Low'
            RequiresRestart = $false
            RequiresAdmin = $false
            Reversible = $false
            ProtectionTier = 'ConfigOnly'
            AllowWithoutRestorePoint = $false
        }
    )
}

function Initialize-ArchesRemediationProtection {
    param(
        [Parameter(Mandatory)][object]$CatalogItem,
        [switch]$ExternalProtectionConfirmed
    )
    switch ($CatalogItem.ProtectionTier) {
        'ConfigOnly' {
            return [PSCustomObject]@{ Tier = 'ConfigOnly'; Ready = $true; Details = 'Exact affected settings will be recorded when rollback is supported.' }
        }
        'RestorePoint' {
            try {
                Checkpoint-Computer -Description "Arches Cyber $($CatalogItem.Id)" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
                return [PSCustomObject]@{ Tier = 'RestorePoint'; Ready = $true; Details = 'Windows restore point created. Restore points do not protect personal files.' }
            }
            catch {
                if (-not $CatalogItem.AllowWithoutRestorePoint) {
                    throw "Remediation $($CatalogItem.Id) stopped because a Windows restore point could not be created. Restore points do not protect personal files. Error: $($_.Exception.Message)"
                }
                return [PSCustomObject]@{ Tier = 'RestorePoint'; Ready = $true; Details = "Restore point creation failed, but explicit policy permits continuing: $($_.Exception.Message)" }
            }
        }
        'ExternalSnapshotRequired' {
            if (-not $ExternalProtectionConfirmed) {
                throw "Remediation $($CatalogItem.Id) requires confirmation of an external backup, system image, or VM snapshot."
            }
            return [PSCustomObject]@{ Tier = 'ExternalSnapshotRequired'; Ready = $true; Details = 'External protection was explicitly confirmed. Phase 1 does not create full-machine images.' }
        }
        default {
            throw "Remediation $($CatalogItem.Id) has unknown protection tier '$($CatalogItem.ProtectionTier)'."
        }
    }
}

function Invoke-ArchesFirewallRemediation {
    param(
        [Parameter(Mandatory)][string]$RollbackDirectory
    )
    if (-not (Test-ArchesAdministrator)) {
        throw 'Administrator privileges are required to change firewall profiles.'
    }
    $before = @(Get-NetFirewallProfile -Profile Domain, Private, Public -ErrorAction Stop |
        Select-Object Name, Enabled)
    $disabled = @($before | Where-Object { -not $_.Enabled })
    if (-not $disabled.Count) {
        return [PSCustomObject]@{
            Id = 'FIX-FW-001'
            Changed = $false
            Message = 'All firewall profiles were already enabled.'
            RollbackPath = $null
        }
    }

    $changes = @($disabled | ForEach-Object {
        [PSCustomObject][ordered]@{
            TargetType = 'FirewallProfile'
            Target = [string]$_.Name
            Property = 'Enabled'
            Before = [bool]$_.Enabled
            After = $true
        }
    })
    $rollbackPath = New-ArchesRollbackRecord -Directory $RollbackDirectory `
        -RemediationId 'FIX-FW-001' -ProtectionTier ConfigOnly -Changes $changes

    try {
        foreach ($change in $changes) {
            Set-NetFirewallProfile -Profile $change.Target -Enabled $true -ErrorAction Stop
        }
        foreach ($change in $changes) {
            $profile = Get-NetFirewallProfile -Profile $change.Target -ErrorAction Stop
            if ($null -eq $profile -or -not [bool]$profile.Enabled) {
                throw "Firewall profile '$($change.Target)' was not enabled after remediation."
            }
        }
        Set-ArchesRollbackApplied -Path $rollbackPath `
            -VerificationDetails 'Every intended firewall profile was verified enabled.' | Out-Null
        [PSCustomObject]@{
            Id = 'FIX-FW-001'
            Changed = $true
            Message = 'Disabled firewall profiles were enabled and verified.'
            RollbackPath = $rollbackPath
        }
    }
    catch {
        $applicationError = $_.Exception.Message
        try {
            Restore-ArchesRollback -Path $rollbackPath -Approved -Recovery -Confirm:$false | Out-Null
        }
        catch {
            throw "Firewall remediation failed: $applicationError Targeted rollback also failed: $($_.Exception.Message)"
        }
        throw "Firewall remediation failed: $applicationError Targeted rollback succeeded."
    }
}

function Invoke-ArchesRemediation {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateSet('FIX-FW-001', 'FIX-DNS-001')][string]$Id,
        [Parameter(Mandatory)][string]$RollbackDirectory,
        [switch]$Approved,
        [switch]$ExternalProtectionConfirmed
    )
    if (-not $Approved) {
        throw "Remediation $Id requires explicit approval. Rerun with -Approved after reviewing the change."
    }
    $catalogItem = Get-ArchesRemediationCatalog | Where-Object Id -eq $Id
    if ($null -eq $catalogItem) {
        throw "Unknown remediation '$Id'."
    }

    if (-not $PSCmdlet.ShouldProcess($catalogItem.Title, "Run remediation $Id")) {
        return
    }
    Initialize-ArchesRemediationProtection -CatalogItem $catalogItem `
        -ExternalProtectionConfirmed:$ExternalProtectionConfirmed | Out-Null

    switch ($Id) {
        'FIX-FW-001' {
            Invoke-ArchesFirewallRemediation -RollbackDirectory $RollbackDirectory
        }
        'FIX-DNS-001' {
            Clear-DnsClientCache -ErrorAction Stop
            [PSCustomObject]@{
                Id = $Id
                Changed = $true
                Message = 'DNS resolver cache cleared. Cache contents cannot be restored.'
                RollbackPath = $null
            }
        }
    }
}

Export-ModuleMember -Function Get-ArchesRemediationCatalog, Invoke-ArchesRemediation
