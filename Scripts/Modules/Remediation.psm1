Set-StrictMode -Version 2.0

function Get-ArchesFirewallManagementState {
    [CmdletBinding()]
    param()
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($null -eq $computerSystem -or $null -eq $computerSystem.PartOfDomain) {
            return [PSCustomObject]@{
                Status = 'Unknown'
                Signals = @()
                Details = 'Domain membership could not be determined.'
            }
        }

        $signals = @()
        if ([bool]$computerSystem.PartOfDomain) {
            $signals += 'Active Directory domain membership'
        }
        $managedPolicyPaths = [ordered]@{
            'Group Policy firewall policy' = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
            'MDM firewall policy' = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall'
        }
        foreach ($signal in $managedPolicyPaths.Keys) {
            if (Test-Path -LiteralPath $managedPolicyPaths[$signal] -PathType Container -ErrorAction Stop) {
                $signals += $signal
            }
        }

        $omadmPath = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
        if (Test-Path -LiteralPath $omadmPath -PathType Container -ErrorAction Stop) {
            $managementAccounts = @(Get-ChildItem -LiteralPath $omadmPath -ErrorAction Stop)
            if ($managementAccounts.Count) {
                $signals += 'Active MDM enrollment'
            }
        }

        if ($signals.Count) {
            return [PSCustomObject]@{
                Status = 'Managed'
                Signals = @($signals)
                Details = "Firewall ownership is organization-managed: $($signals -join ', ')."
            }
        }
        [PSCustomObject]@{
            Status = 'Unmanaged'
            Signals = @()
            Details = 'No domain membership, firewall policy registry keys, or active MDM enrollment were detected.'
        }
    }
    catch {
        [PSCustomObject]@{
            Status = 'Unknown'
            Signals = @()
            Details = "Firewall management ownership could not be determined safely: $($_.Exception.Message)"
        }
    }
}

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
            ManagementCheck = 'Refuse domain, Group Policy, MDM, or unknown ownership.'
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
            ManagementCheck = 'Not applicable to resolver cache contents.'
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
    $managementState = Get-ArchesFirewallManagementState
    if ($managementState.Status -ne 'Unmanaged') {
        throw "Firewall remediation refused. $($managementState.Details) No firewall settings were changed."
    }
    $before = @(Get-ArchesFirewallProfileState -Profile Domain, Private, Public)
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
            Set-ArchesFirewallProfileState -Profile $change.Target -Enabled $true
        }
        foreach ($change in $changes) {
            $profile = Get-ArchesFirewallProfileState -Profile $change.Target
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

Export-ModuleMember -Function Get-ArchesFirewallManagementState, Get-ArchesRemediationCatalog, Invoke-ArchesRemediation
