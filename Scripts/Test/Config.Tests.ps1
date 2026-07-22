$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Config.psm1') -Force

Describe 'Phase 1 configuration' {
    BeforeAll {
        function New-TestConfiguration {
            [PSCustomObject]@{
                SchemaVersion = 1
                ReportRetentionDays = 30
                RollbackRetentionDays = 30
                Thresholds = [PSCustomObject]@{
                    DiskFreeWarningPercent = 20
                    DiskFreeCriticalPercent = 10
                    MemoryAvailableWarningPercent = 20
                    MemoryAvailableCriticalPercent = 10
                    CpuWarningPercent = 90
                    RestartAgeWarningDays = 30
                    AntivirusSignatureWarningDays = 3
                    LatencyWarningMs = 100
                    PacketLossWarningPercent = 2
                }
                Safety = [PSCustomObject]@{
                    RequireExplicitFixApproval = $true
                    CreateRollbackBeforeChange = $true
                    AllowNetworkReset = $false
                    AllowStaticToDhcpChange = $false
                }
            }
        }

        function Save-TestConfiguration {
            param([object]$Configuration, [string]$Path)
            $Configuration | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    }

    It 'loads a valid configuration' {
        $path = Join-Path $TestDrive 'valid.json'
        Save-TestConfiguration -Configuration (New-TestConfiguration) -Path $path
        $configuration = Get-ArchesConfiguration -Path $path
        $configuration.SchemaVersion | Should -Be 1
        $configuration.Thresholds.CpuWarningPercent | Should -Be 90
    }

    It 'reports a missing configuration file' {
        { Get-ArchesConfiguration -Path (Join-Path $TestDrive 'missing.json') } |
            Should -Throw '*configuration file not found*'
    }

    It 'reports malformed JSON' {
        $path = Join-Path $TestDrive 'malformed.json'
        Set-Content -LiteralPath $path -Value '{not-json' -Encoding UTF8
        { Get-ArchesConfiguration -Path $path } |
            Should -Throw '*malformed JSON*'
    }

    It 'reports a missing required section' {
        $path = Join-Path $TestDrive 'missing-section.json'
        $configuration = New-TestConfiguration
        $configuration.PSObject.Properties.Remove('Safety')
        Save-TestConfiguration -Configuration $configuration -Path $path
        { Get-ArchesConfiguration -Path $path } |
            Should -Throw "*required property 'root.Safety' is missing*"
    }

    It 'rejects threshold values outside their range' {
        $path = Join-Path $TestDrive 'invalid-range.json'
        $configuration = New-TestConfiguration
        $configuration.Thresholds.CpuWarningPercent = 101
        Save-TestConfiguration -Configuration $configuration -Path $path
        { Get-ArchesConfiguration -Path $path } |
            Should -Throw "*Thresholds.CpuWarningPercent*between 1 and 100*"
    }

    It 'rejects critical thresholds that are not below warning thresholds' {
        $path = Join-Path $TestDrive 'invalid-order.json'
        $configuration = New-TestConfiguration
        $configuration.Thresholds.DiskFreeCriticalPercent = 20
        Save-TestConfiguration -Configuration $configuration -Path $path
        { Get-ArchesConfiguration -Path $path } |
            Should -Throw '*DiskFreeCriticalPercent*less than*DiskFreeWarningPercent*'
    }
}
