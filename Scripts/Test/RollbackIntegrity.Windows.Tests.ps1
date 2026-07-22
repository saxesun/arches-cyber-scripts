$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force
$runningOnWindows = $env:OS -eq 'Windows_NT'

Describe 'Windows DPAPI rollback integrity integration' -Skip:(-not $runningOnWindows) {
    BeforeAll {
        $testRoot = Split-Path -Parent $PSScriptRoot
    }

    BeforeEach {
        $integrityPath = Join-Path $TestDrive 'ArchesCyber\rollback-integrity-key.json'
        if (Test-Path -LiteralPath $integrityPath) {
            Remove-Item -LiteralPath $integrityPath -Force
        }
        Mock Get-ArchesRollbackIntegrityKeyPath -ModuleName Rollback {
            $integrityPath
        }
    }

    It 'creates and reloads the same DPAPI-protected CurrentUser key' {
        $first = InModuleScope Rollback { Get-ArchesRollbackIntegrityKey }
        $second = InModuleScope Rollback { Get-ArchesRollbackIntegrityKey }
        [Convert]::ToBase64String($first) | Should -Be ([Convert]::ToBase64String($second))
        $envelope = Get-Content -LiteralPath $integrityPath -Raw | ConvertFrom-Json
        $envelope.ProtectionScope | Should -Be 'CurrentUser'
        $envelope.ProtectedKey | Should -Not -Be ([Convert]::ToBase64String($first))
    }

    It 'fails closed for a corrupted key envelope' {
        InModuleScope Rollback { Get-ArchesRollbackIntegrityKey } | Out-Null
        Set-Content -LiteralPath $integrityPath -Value '{corrupted' -Encoding UTF8
        { InModuleScope Rollback { Get-ArchesRollbackIntegrityKey } } |
            Should -Throw '*could not be loaded safely*'
    }

    It 'fails closed when the key cannot be read' {
        InModuleScope Rollback { Get-ArchesRollbackIntegrityKey } | Out-Null
        Mock Get-Content -ModuleName Rollback {
            throw [System.UnauthorizedAccessException]::new('access denied')
        }
        { InModuleScope Rollback { Get-ArchesRollbackIntegrityKey } } |
            Should -Throw '*could not be loaded safely*access denied*'
    }

    It 'uses the current Windows user DPAPI context after reload' {
        $key = InModuleScope Rollback { Get-ArchesRollbackIntegrityKey }
        Remove-Module Rollback -Force
        Import-Module (Join-Path $testRoot 'Modules\Rollback.psm1') -Force
        Mock Get-ArchesRollbackIntegrityKeyPath -ModuleName Rollback {
            $integrityPath
        }
        $reloaded = InModuleScope Rollback { Get-ArchesRollbackIntegrityKey }
        [Convert]::ToBase64String($reloaded) | Should -Be ([Convert]::ToBase64String($key))
    }

    It 'serializes concurrent key creation safely for the current user' {
        $modulePath = Join-Path $testRoot 'Modules\Rollback.psm1'
        $localAppData = Join-Path $TestDrive 'ConcurrentLocalAppData'
        $recordRoot = Join-Path $TestDrive 'ConcurrentRecords'
        $jobs = @(1..2 | ForEach-Object {
            Start-Job -ArgumentList $modulePath, $localAppData, $recordRoot, $_ -ScriptBlock {
                param($ModulePath, $LocalAppData, $RecordRoot, $Index)
                $env:LOCALAPPDATA = $LocalAppData
                Import-Module $ModulePath -Force
                $change = [PSCustomObject]@{
                    TargetType='FirewallProfile'; Target='Public'; Property='Enabled'
                    Before=$false; After=$true
                }
                New-ArchesRollbackRecord -Directory (Join-Path $RecordRoot $Index) `
                    -RemediationId FIX-FW-001 -ProtectionTier ConfigOnly -Changes @($change)
            }
        })
        try {
            $jobs | Wait-Job | Out-Null
            $errors = @($jobs | ForEach-Object { @($_.ChildJobs[0].Error) })
            $errors.Count | Should -Be 0
            @($jobs | Receive-Job).Count | Should -Be 2
            Test-Path (Join-Path $localAppData 'ArchesCyber\rollback-integrity-key.json') |
                Should -BeTrue
        }
        finally {
            $jobs | Remove-Job -Force
        }
    }
}
