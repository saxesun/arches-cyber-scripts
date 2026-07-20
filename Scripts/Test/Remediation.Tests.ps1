$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force
Import-Module (Join-Path $root 'Modules\Remediation.psm1') -Force

Describe 'Tiered remediation protection' {
    BeforeAll {
        if (-not (Get-Command Test-ArchesAdministrator -ErrorAction SilentlyContinue)) {
            function global:Test-ArchesAdministrator { $true }
        }
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            function global:Get-NetFirewallProfile {
                param([string[]]$Profile, [string]$ErrorAction)
            }
        }
        if (-not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            function global:Set-NetFirewallProfile {
                param([string]$Profile, [bool]$Enabled, [string]$ErrorAction)
            }
        }
        if (-not (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue)) {
            function global:Clear-DnsClientCache {
                param([string]$ErrorAction)
            }
        }
    }

    BeforeEach {
        Get-ChildItem -LiteralPath $TestDrive -Filter 'Rollback_*.json' -File -ErrorAction SilentlyContinue |
            Remove-Item -Force
        $script:firewallState = @{
            Domain = $false
            Private = $true
            Public = $false
        }
        $script:sawPendingBeforeChange = $false
        Mock Test-ArchesAdministrator -ModuleName Remediation { $true }
        Mock Get-NetFirewallProfile -ModuleName Remediation {
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
        Mock Set-NetFirewallProfile -ModuleName Remediation {
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

    It 'reports the application failure after targeted rollback succeeds' {
        Mock Set-NetFirewallProfile -ModuleName Remediation { throw 'application exploded' }
        Mock Restore-ArchesRollback -ModuleName Remediation {}
        { Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
                -Approved -Confirm:$false } |
            Should -Throw '*application exploded*Targeted rollback succeeded*'
        Assert-MockCalled Restore-ArchesRollback -ModuleName Remediation -Times 1 `
            -ParameterFilter { $Approved -and $Recovery }
    }

    It 'reports both application and targeted rollback failures' {
        Mock Set-NetFirewallProfile -ModuleName Remediation { throw 'application exploded' }
        Mock Restore-ArchesRollback -ModuleName Remediation { throw 'rollback exploded' }
        { Invoke-ArchesRemediation -Id FIX-FW-001 -RollbackDirectory $TestDrive `
                -Approved -Confirm:$false } |
            Should -Throw '*application exploded*Targeted rollback also failed*rollback exploded*'
    }
}
