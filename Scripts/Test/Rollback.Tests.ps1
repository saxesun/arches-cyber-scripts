$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force

Describe 'Structured rollback records' {
    BeforeAll {
        $testRoot = Split-Path -Parent $PSScriptRoot
        function New-TestChange {
            param(
                [string]$Target = 'Public',
                [bool]$Before = $false,
                [bool]$After = $true
            )
            [PSCustomObject][ordered]@{
                TargetType = 'FirewallProfile'
                Target = $Target
                Property = 'Enabled'
                Before = $Before
                After = $After
            }
        }

        function New-TestRecord {
            param([object[]]$Changes = @((New-TestChange)))
            New-ArchesRollbackRecord -Directory $TestDrive -RemediationId FIX-FW-001 `
                -ProtectionTier ConfigOnly -Changes $Changes
        }

        function Set-TestRecordField {
            param([string]$Path, [string]$Name, [object]$Value)
            $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            $record.$Name = $Value
            $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    }

    BeforeEach {
        Mock Get-ArchesRollbackIntegrityKey -ModuleName Rollback {
            [byte[]](1..32)
        }
        $script:firewallState = @{
            Domain = $true
            Private = $true
            Public = $true
        }
        Mock Set-ArchesFirewallProfileState -ModuleName Rollback {
            $script:firewallState[$Profile] = [bool]$Enabled
        }
        Mock Get-ArchesFirewallProfileState -ModuleName Rollback {
            [PSCustomObject]@{ Name = $Profile; Enabled = [bool]$script:firewallState[$Profile] }
        }
    }

    It 'creates a version 3 Pending data-only record with integrity metadata' {
        $path = New-TestRecord
        $record = Get-ArchesRollbackRecord -Path $path
        $record.SchemaVersion | Should -Be 3
        $record.Status | Should -Be 'Pending'
        $record.ProtectionTier | Should -Be 'ConfigOnly'
        $record.Integrity.Algorithm | Should -Be 'HMAC-SHA256'
        $record.Integrity.Value | Should -Not -BeNullOrEmpty
        @($record.Changes).Count | Should -Be 1
    }

    It 'does not persist executable command fields' {
        $path = New-TestRecord
        $json = Get-Content -LiteralPath $path -Raw
        $json | Should -Not -Match 'RestoreCommand|Command|ScriptBlock'
        $json | Should -Match '"Before":\s*false'
        $json | Should -Match '"After":\s*true'
    }

    It 'rejects an unknown remediation id' {
        $path = New-TestRecord
        Set-TestRecordField -Path $path -Name RemediationId -Value 'FIX-UNKNOWN-999'
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw '*unknown RemediationId*'
    }

    It 'rejects malformed integrity metadata' {
        $path = New-TestRecord
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $record.Integrity.Value = 'not-base64-or-a-valid-signature'
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw '*integrity validation failed*'
    }

    It 'rejects schema-valid tampering before a firewall handler executes' {
        $path = New-TestRecord
        Set-ArchesRollbackApplied -Path $path | Out-Null
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $record.Changes[0].Before = $true
        $record.Changes[0].After = $false
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8

        { Restore-ArchesRollback -Path $path -Approved -Confirm:$false } |
            Should -Throw '*integrity validation failed*'
        Assert-MockCalled Set-ArchesFirewallProfileState -ModuleName Rollback -Times 0
    }

    It 'rejects tampering with every security-relevant root field' -TestCases @(
        @{ Field = 'ComputerName'; Value = 'OTHER-PC' }
        @{ Field = 'RemediationId'; Value = 'FIX-FW-001' }
        @{ Field = 'ProtectionTier'; Value = 'ConfigOnly' }
        @{ Field = 'RecordId'; Value = '00000000-0000-0000-0000-000000000001' }
        @{ Field = 'Status'; Value = 'Applied' }
        @{ Field = 'AppliedAt'; Value = '2026-01-01T00:00:00.0000000Z' }
    ) {
        param($Field, $Value)
        $path = New-TestRecord
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($Field -eq 'RemediationId') {
            $record.RecordId = '00000000-0000-0000-0000-000000000002'
        }
        elseif ($Field -eq 'ProtectionTier') {
            $record.CreatedAt = '2026-01-01T00:00:00.0000000Z'
        }
        else {
            $record.$Field = $Value
        }
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw
    }

    It 'rejects an unknown target type' {
        $path = New-TestRecord
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $record.Changes[0].TargetType = 'Command'
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw '*unknown TargetType*'
    }

    It 'rejects an unknown firewall profile' {
        $path = New-TestRecord
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $record.Changes[0].Target = 'All'
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw '*unknown firewall profile*'
    }

    It 'rejects duplicate changes for the same profile and property' {
        {
            New-TestRecord -Changes @(
                (New-TestChange -Target Public -Before $false -After $true),
                (New-TestChange -Target Public -Before $true -After $false)
            )
        } | Should -Throw '*duplicate change target*'
    }

    It 'rejects a record from another computer' {
        $path = New-TestRecord
        Set-TestRecordField -Path $path -Name ComputerName -Value 'A-DIFFERENT-COMPUTER'
        { Get-ArchesRollbackRecord -Path $path } | Should -Throw '*belongs to computer*'
    }

    It 'transitions Pending to Applied only through verification' {
        $path = New-TestRecord
        $record = Set-ArchesRollbackApplied -Path $path
        $record.Status | Should -Be 'Applied'
        $record.AppliedAt | Should -Not -BeNullOrEmpty
        $record.Verification.Succeeded | Should -BeTrue
        { Set-ArchesRollbackApplied -Path $path } | Should -Throw '*must be Pending*'
    }

    It 'restores multiple profiles to different exact previous states' {
        $path = New-TestRecord -Changes @(
            (New-TestChange -Target Domain -Before $false -After $true),
            (New-TestChange -Target Private -Before $true -After $false)
        )
        Set-ArchesRollbackApplied -Path $path | Out-Null
        $script:firewallState.Domain = $true
        $script:firewallState.Private = $false

        $record = Restore-ArchesRollback -Path $path -Approved -Confirm:$false

        $record.Status | Should -Be 'RolledBack'
        $script:firewallState.Domain | Should -BeFalse
        $script:firewallState.Private | Should -BeTrue
    }

    It 'marks RollbackFailed when restored state cannot be verified' {
        $path = New-TestRecord
        Set-ArchesRollbackApplied -Path $path | Out-Null
        Mock Get-ArchesFirewallProfileState -ModuleName Rollback {
            [PSCustomObject]@{ Name = $Profile; Enabled = $true }
        }

        { Restore-ArchesRollback -Path $path -Approved -Confirm:$false } |
            Should -Throw '*marked RollbackFailed*'
        $record = Get-ArchesRollbackRecord -Path $path
        $record.Status | Should -Be 'RollbackFailed'
        $record.Verification.Succeeded | Should -BeFalse
        $record.Verification.Error | Should -Match 'did not return'
    }

    It 'rejects inappropriate Pending RolledBack and RollbackFailed states' {
        $pendingPath = New-TestRecord
        { Restore-ArchesRollback -Path $pendingPath -Approved -Confirm:$false } |
            Should -Throw "*expected 'Applied'*"

        $rolledBackPath = New-TestRecord
        Set-ArchesRollbackApplied -Path $rolledBackPath | Out-Null
        Restore-ArchesRollback -Path $rolledBackPath -Approved -Confirm:$false | Out-Null
        { Restore-ArchesRollback -Path $rolledBackPath -Approved -Confirm:$false } |
            Should -Throw '*not appropriate*'

        $failedPath = New-TestRecord
        Set-ArchesRollbackApplied -Path $failedPath | Out-Null
        Mock Get-ArchesFirewallProfileState -ModuleName Rollback {
            [PSCustomObject]@{ Name = $Profile; Enabled = $true }
        }
        { Restore-ArchesRollback -Path $failedPath -Approved -Confirm:$false } | Should -Throw
        { Restore-ArchesRollback -Path $failedPath -Approved -Confirm:$false } |
            Should -Throw '*not appropriate*'
    }

    It 'requires approval and leaves Applied records unchanged under WhatIf' {
        $path = New-TestRecord
        Set-ArchesRollbackApplied -Path $path | Out-Null
        { Restore-ArchesRollback -Path $path -Confirm:$false } |
            Should -Throw '*explicit approval*'
        Restore-ArchesRollback -Path $path -WhatIf -Confirm:$false | Out-Null
        (Get-ArchesRollbackRecord -Path $path).Status | Should -Be 'Applied'
    }

    It 'supports the trusted undo entry script in WhatIf mode' {
        $path = New-TestRecord
        Set-ArchesRollbackApplied -Path $path | Out-Null
        & (Join-Path $testRoot 'Invoke-ArchesUndo.ps1') -Path $path -WhatIf | Out-Null
        (Get-ArchesRollbackRecord -Path $path).Status | Should -Be 'Applied'
    }

    It 'contains no dynamic command execution in rollback or remediation code' {
        $source = @(
            Get-Content -LiteralPath (Join-Path $testRoot 'Modules\Rollback.psm1') -Raw
            Get-Content -LiteralPath (Join-Path $testRoot 'Modules\Remediation.psm1') -Raw
        ) -join "`n"
        $source | Should -Not -Match 'Invoke-Expression'
        $source | Should -Not -Match 'ScriptBlock\s*::\s*Create'
        $source | Should -Not -Match 'RestoreCommand'
    }
}
