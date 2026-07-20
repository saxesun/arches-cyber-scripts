$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force
Import-Module (Join-Path $root 'Modules\Remediation.psm1') -Force

Describe 'Tiered remediation protection' {
    BeforeAll {
        if (-not (Get-Command Test-ArchesAdministrator -ErrorAction SilentlyContinue)) {
            function global:Test-ArchesAdministrator { $true }
        }
        if (-not (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue)) {
            function global:Clear-DnsClientCache {
                param([string]$ErrorAction)
            }
        }
        if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
            function global:Get-CimInstance {
                param([string]$ClassName, [string]$ErrorAction)
            }
        }
    }

    BeforeEach {
        Mock Get-ArchesRollbackIntegrityKey -ModuleName Rollback {
            [byte[]](1..32)
        }
        Get-ChildItem -LiteralPath $TestDrive -Filter 'Rollback_*.json' -File -ErrorAction SilentlyContinue |
            Remove-Item -Force
        $script:firewallState = @{
            Domain = $false
            Private = $true
            Public = $false
        }
        $script:sawPendingBeforeChange = $false
        Mock Test-ArchesAdministrator -ModuleName Remediation { $true }
        Mock Get-ArchesFirewallManagementState -ModuleName Remediation {
            [PSCustomObject]@{ Status = 'Unmanaged'; Signals = @(); Details = 'Unmanaged test system.' }
        }
        Mock Get-ArchesFirewallProfileState -ModuleName Remediation {
            if ($Profile) {
                return @($Profile | ForEach-Object {
                    [PSCustomObject]@{ Name = $_; Enabled = [bool]$script:firewallState[$_] }
                })
            }
            @(
                [PSCustomObject]@{ Name = 'Domain'; Enabled = [bool]$script:firewallState.Domain }
                [PSCustomObject]@{ Name = 'Private'; Enabled = [bool]$script:firewallState.Private }
                [PSCustomObject]@{ Name = 'Public'; Enabled = [bool]$script:firewallState.Public }
            )
        }
        Mock Set-ArchesFirewallProfileState -ModuleName Remediation {
            $rollbackFile = Get-ChildItem -LiteralPath $TestDrive -Filter 'Rollback_*.json' -File |
                Select-Object -First 1
            if ($rollbackFile) {
                $pending = Get-Content -LiteralPath $rollbackFile.FullName -Raw | ConvertFrom-Json
                if ($pending.Status -eq 'Pending') { $script:sawPendingBeforeChange = $true }
            }
            $script:firewallState[$Profile] = [bool]$Enabled
        }
        Mock Clear-DnsClientCache -ModuleName Remediation {}
    }

    It 'declares protection tiers and does not claim DNS cache rollback' {
        $catalog = @(Get-ArchesRemediationCatalog)
        ($catalog | Where-Object Id -eq 'FIX-FW-001').ProtectionTier | Should -Be 'ConfigOnly'
        ($catalog | Where-Object Id -eq 'FIX-FW-001').Reversible | Should -BeTrue
        ($catalog | Where-Object Id -eq 'FIX-DNS-001').ProtectionTier | Should -Be 'ConfigOnly'
        ($catalog | Where-Object Id -eq 'FIX-DNS-001').Reversible | Should -BeFalse
    }

    It 'creates Pending firewall data before changing and marks Applied after verification' {
        $result = Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
            -Approved -Confirm:$false
        $script:sawPendingBeforeChange | Should -BeTrue
        $result.Changed | Should -BeTrue
        $record = Get-ArchesRollbackRecord -Path $result.RollbackPath
        $record.Status | Should -Be 'Applied'
        @($record.Changes).Count | Should -Be 2
        @($record.Changes.Target) | Should -Contain 'Domain'
        @($record.Changes.Target) | Should -Contain 'Public'
        @($record.Changes.Target) | Should -Not -Contain 'Private'
    }

    It 'does not create a rollback record for DNS cache flush' {
        $result = Invoke-ArchesRemediation -Id FIX-DNS-001 -RollbackDirectory $TestDrive `
            -Approved -Confirm:$false
        $result.RollbackPath | Should -BeNullOrEmpty
        $result.Message | Should -Match 'cannot be restored'
        @(Get-ChildItem -LiteralPath $TestDrive -Filter 'Rollback_*.json' -File).Count | Should -Be 0
    }

    It 'requires approval before remediation' {
        { Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive -Confirm:$false } |
            Should -Throw '*explicit approval*'
    }

    It 'detects an unmanaged firewall ownership state' {
        Mock Get-CimInstance -ModuleName Remediation {
            [PSCustomObject]@{ PartOfDomain = $false }
        }
        Mock Test-Path -ModuleName Remediation { $false }

        $state = Get-ArchesFirewallManagementState

        $state.Status | Should -Be 'Unmanaged'
    }

    It 'detects managed firewall ownership' {
        Mock Get-CimInstance -ModuleName Remediation {
            [PSCustomObject]@{ PartOfDomain = $true }
        }
        Mock Test-Path -ModuleName Remediation { $false }

        $state = Get-ArchesFirewallManagementState

        $state.Status | Should -Be 'Managed'
        $state.Signals | Should -Contain 'Active Directory domain membership'
    }

    It 'returns Unknown when ownership data is inconclusive' {
        Mock Get-CimInstance -ModuleName Remediation { $null }
        Mock Test-Path -ModuleName Remediation { $false }

        (Get-ArchesFirewallManagementState).Status | Should -Be 'Unknown'
    }

    It 'returns Unknown when management detection fails' {
        Mock Get-CimInstance -ModuleName Remediation { throw 'CIM unavailable' }

        $state = Get-ArchesFirewallManagementState

        $state.Status | Should -Be 'Unknown'
        $state.Details | Should -Match 'CIM unavailable'
    }

    It 'refuses managed or unknown firewall ownership before reading or changing profiles' -TestCases @(
        @{ State = 'Managed'; Details = 'Group Policy firewall policy detected.' }
        @{ State = 'Unknown'; Details = 'Ownership detection failed.' }
    ) {
        param($State, $Details)
        Mock Get-ArchesFirewallManagementState -ModuleName Remediation {
            [PSCustomObject]@{ Status = $State; Signals = @(); Details = $Details }
        }

        {
            Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
                -Approved -Confirm:$false
        } | Should -Throw '*refused*No firewall settings were changed*'
        Assert-MockCalled Get-ArchesFirewallProfileState -ModuleName Remediation -Times 0
        Assert-MockCalled Set-ArchesFirewallProfileState -ModuleName Remediation -Times 0
    }

    It 'reports the application failure after targeted rollback succeeds' {
        Mock Set-ArchesFirewallProfileState -ModuleName Remediation { throw 'application exploded' }
        Mock Restore-ArchesRollback -ModuleName Remediation {}
        { Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
                -Approved -Confirm:$false } |
            Should -Throw '*application exploded*Targeted rollback succeeded*'
    }

    It 'reports both application and targeted rollback failures' {
        Mock Set-ArchesFirewallProfileState -ModuleName Remediation { throw 'application exploded' }
        Mock Restore-ArchesRollback -ModuleName Remediation { throw 'rollback exploded' }
        { Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
                -Approved -Confirm:$false } |
            Should -Throw '*application exploded*Targeted rollback also failed*rollback exploded*'
    }
}
