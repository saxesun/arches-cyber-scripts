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
            'Microsoft Entra organization join' = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
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

        $rmmPatterns = @(
            'ScreenConnect*', 'ConnectWise*', 'NinjaRMMAgent', 'NinjaRMMAgentPatcher',
            'AteraAgent', 'Kaseya*', 'Datto*', 'SplashtopRemoteService',
            'TacticalRMM*', 'Syncro*', 'HuntressAgent'
        )
        $services = @(Get-Service -ErrorAction Stop)
        foreach ($service in $services) {
            foreach ($pattern in $rmmPatterns) {
                if ($service.Name -like $pattern -or $service.DisplayName -like $pattern) {
                    $signals += "Approved RMM service pattern: $pattern"
                    break
                }
            }
        }

        $securityProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' `
            -ClassName AntiVirusProduct -ErrorAction Stop)
        foreach ($product in $securityProducts) {
            if ($product.displayName -and $product.displayName -notmatch 'Microsoft Defender|Windows Defender') {
                $signals += "Third-party security ownership: $($product.displayName)"
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
            Status = 'SupportedSignalsClear'
            Signals = @()
            Details = 'No supported domain, Group Policy, MDM, approved RMM, or third-party security ownership signal was detected. Unsupported management products cannot be excluded.'
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
            Privileges = 'Administrator'
            Disruption = 'Firewall policy is re-evaluated for the selected profiles; existing permitted sessions should remain active.'
            Duration = 'Usually under 10 seconds'
            Verification = 'Re-read every selected firewall profile and require Enabled=True.'
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
            Privileges = 'Standard user where Windows permits; elevation may be required by policy.'
            Disruption = 'Cached DNS answers are discarded and subsequent name lookups must query DNS again.'
            Duration = 'Usually under 5 seconds'
            Verification = 'Command completion is verified; previous cache contents cannot be reconstructed.'
        }
    )
}

function Get-ArchesPlanDigest {
    param([Parameter(Mandatory)][object]$Plan)
    $payload = [PSCustomObject][ordered]@{
        PlanVersion = $Plan.PlanVersion
        Id = $Plan.Id
        Risk = $Plan.Risk
        RequiresAdmin = $Plan.RequiresAdmin
        Privileges = $Plan.Privileges
        Disruption = $Plan.Disruption
        Duration = $Plan.Duration
        ProtectionTier = $Plan.ProtectionTier
        Reversible = $Plan.Reversible
        Verification = $Plan.Verification
        OwnershipStatus = $Plan.OwnershipStatus
        OwnershipSignals = @($Plan.OwnershipSignals)
        ManagementOwnershipAttested = $Plan.ManagementOwnershipAttested
        CanExecute = $Plan.CanExecute
        BlockReason = $Plan.BlockReason
        Baseline = @($Plan.Baseline)
        Changes = @($Plan.Changes)
    } | ConvertTo-Json -Depth 8 -Compress
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString(
            $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload))
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function New-ArchesRemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('FIX-FW-001', 'FIX-DNS-001')][string]$Id,
        [switch]$ManagementOwnershipAttested
    )
    $catalogItem = Get-ArchesRemediationCatalog | Where-Object Id -eq $Id
    if ($null -eq $catalogItem) {
        throw "Unknown remediation '$Id'."
    }

    $baseline = @()
    $changes = @()
    $ownershipStatus = 'NotApplicable'
    $ownershipSignals = @()
    $canExecute = $true
    $blockReason = $null
    if ($Id -eq 'FIX-FW-001') {
        $managementState = Get-ArchesFirewallManagementState
        $ownershipStatus = $managementState.Status
        $ownershipSignals = @($managementState.Signals)
        if ($managementState.Status -eq 'SupportedSignalsClear' -and -not $ManagementOwnershipAttested) {
            $canExecute = $false
            $blockReason = 'Supported management signals are clear, but unsupported ownership cannot be excluded. Explicit technician attestation is required.'
        }
        elseif ($managementState.Status -ne 'SupportedSignalsClear') {
            $canExecute = $false
            $blockReason = $managementState.Details
        }
        $profiles = @(Get-ArchesFirewallProfileState -Profile Domain, Private, Public)
        if ($profiles.Count -ne 3) {
            $canExecute = $false
            $blockReason = 'All Domain, Private, and Public firewall profiles could not be read safely.'
        }
        $baseline = @($profiles | ForEach-Object {
            [PSCustomObject][ordered]@{
                TargetType = 'FirewallProfile'
                Target = [string]$_.Name
                Property = 'Enabled'
                Value = [bool]$_.Enabled
            }
        })
        $changes = @($baseline | Where-Object { -not $_.Value } | ForEach-Object {
            [PSCustomObject][ordered]@{
                TargetType = $_.TargetType
                Target = $_.Target
                Property = $_.Property
                Before = [bool]$_.Value
                After = $true
            }
        })
    }
    else {
        $changes = @(
            [PSCustomObject][ordered]@{
                TargetType = 'DnsResolverCache'
                Target = 'LocalComputer'
                Property = 'CachedAnswers'
                Before = 'Current cache contents'
                After = 'Empty cache'
            }
        )
    }

    $plan = [PSCustomObject][ordered]@{
        PlanVersion = 1
        Id = $catalogItem.Id
        Title = $catalogItem.Title
        Risk = $catalogItem.Risk
        RequiresAdmin = $catalogItem.RequiresAdmin
        Privileges = $catalogItem.Privileges
        Disruption = $catalogItem.Disruption
        Duration = $catalogItem.Duration
        ProtectionTier = $catalogItem.ProtectionTier
        Reversible = $catalogItem.Reversible
        Verification = $catalogItem.Verification
        OwnershipStatus = $ownershipStatus
        OwnershipSignals = @($ownershipSignals)
        ManagementOwnershipAttested = [bool]$ManagementOwnershipAttested
        CanExecute = $canExecute
        BlockReason = $blockReason
        Baseline = @($baseline)
        Changes = @($changes)
        Digest = $null
    }
    $plan.Digest = Get-ArchesPlanDigest -Plan $plan
    $plan
}

function Show-ArchesRemediationPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan)
    Write-Host "Remediation plan: $($Plan.Id) - $($Plan.Title)"
    Write-Host "Risk: $($Plan.Risk)"
    Write-Host "Privileges: $($Plan.Privileges)"
    Write-Host "Disruption: $($Plan.Disruption)"
    Write-Host "Duration: $($Plan.Duration)"
    Write-Host "Protection tier: $($Plan.ProtectionTier)"
    Write-Host "Reversible: $($Plan.Reversible)"
    Write-Host "Verification: $($Plan.Verification)"
    Write-Host "Ownership status: $($Plan.OwnershipStatus)"
    if ($Plan.BlockReason) {
        Write-Host "Blocked: $($Plan.BlockReason)"
    }
    Write-Host 'Exact planned changes:'
    $Plan.Changes | Format-Table TargetType, Target, Property, Before, After -AutoSize
}

function Assert-ArchesRemediationPlan {
    param([Parameter(Mandatory)][object]$Plan)
    $expected = @(
        'PlanVersion', 'Id', 'Title', 'Risk', 'RequiresAdmin', 'Privileges',
        'Disruption', 'Duration', 'ProtectionTier', 'Reversible', 'Verification',
        'OwnershipStatus', 'OwnershipSignals', 'CanExecute', 'BlockReason',
        'ManagementOwnershipAttested', 'Baseline', 'Changes', 'Digest'
    )
    $actual = @($Plan.PSObject.Properties.Name)
    if (@($expected | Where-Object { $_ -notin $actual }).Count -or
        @($actual | Where-Object { $_ -notin $expected }).Count) {
        throw 'Remediation plan has missing or unknown fields.'
    }
    if ($Plan.PlanVersion -notin @([int]1, [long]1) -or
        $Plan.Id -notin @('FIX-FW-001', 'FIX-DNS-001')) {
        throw 'Remediation plan version or identifier is unsupported.'
    }
    $expectedDigest = Get-ArchesPlanDigest -Plan $Plan
    if ($Plan.Digest -isnot [string] -or $Plan.Digest -cne $expectedDigest) {
        throw 'Remediation plan integrity validation failed.'
    }
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
        [Parameter(Mandatory)][string]$RollbackDirectory,
        [Parameter(Mandatory)][object]$Plan
    )
    if (-not (Test-ArchesAdministrator)) {
        throw 'Administrator privileges are required to change firewall profiles.'
    }
    if (-not $Plan.CanExecute) {
        throw "Firewall remediation refused. $($Plan.BlockReason) No firewall settings were changed."
    }
    $managementState = Get-ArchesFirewallManagementState
    if ($managementState.Status -ne $Plan.OwnershipStatus -or
        (@($managementState.Signals) -join '|') -cne (@($Plan.OwnershipSignals) -join '|')) {
        throw 'Firewall ownership state changed after planning. No firewall settings were changed.'
    }
    $current = @(Get-ArchesFirewallProfileState -Profile Domain, Private, Public)
    foreach ($baseline in @($Plan.Baseline)) {
        $profile = @($current | Where-Object Name -eq $baseline.Target)
        if ($profile.Count -ne 1 -or [bool]$profile[0].Enabled -ne [bool]$baseline.Value) {
            throw "Firewall profile '$($baseline.Target)' changed after planning. No firewall settings were changed."
        }
    }
    if (-not @($Plan.Changes).Count) {
        return [PSCustomObject]@{
            Id = 'FIX-FW-001'
            Changed = $false
            Message = 'All firewall profiles were already enabled.'
            RollbackPath = $null
        }
    }

    $changes = @($Plan.Changes)
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
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$RollbackDirectory,
        [switch]$Approved,
        [switch]$ExternalProtectionConfirmed
    )
    Assert-ArchesRemediationPlan -Plan $Plan
    $Id = $Plan.Id
    $catalogItem = Get-ArchesRemediationCatalog | Where-Object Id -eq $Id
    if ($null -eq $catalogItem) {
        throw "Unknown remediation '$Id'."
    }

    if (-not $PSCmdlet.ShouldProcess($catalogItem.Title, "Run remediation $Id")) {
        return [PSCustomObject]@{ Id=$Id; WhatIf=$true; Plan=$Plan; Changed=$false }
    }
    if (-not $Approved) {
        throw "Remediation $Id requires explicit approval after reviewing the displayed plan. Rerun with -Approved."
    }
    Initialize-ArchesRemediationProtection -CatalogItem $catalogItem `
        -ExternalProtectionConfirmed:$ExternalProtectionConfirmed | Out-Null

    switch ($Id) {
        'FIX-FW-001' {
            Invoke-ArchesFirewallRemediation -RollbackDirectory $RollbackDirectory -Plan $Plan
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

Export-ModuleMember -Function Get-ArchesFirewallManagementState, Get-ArchesRemediationCatalog, `
    New-ArchesRemediationPlan, Show-ArchesRemediationPlan, Invoke-ArchesRemediation
