$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Diagnostics.psm1') -Force

Describe 'Security Center-aware antivirus diagnosis' {
    BeforeEach {
        $script:products = @(
            [PSCustomObject]@{ Product='Microsoft Defender'; Active=$true; IsMicrosoft=$true }
        )
        $script:defender = [PSCustomObject]@{
            Available=$true
            AntivirusEnabled=$true
            RealTimeProtectionEnabled=$true
            RunningMode='Normal'
            Managed=$false
        }
        Mock Get-ArchesSecurityCenterAntivirusProducts -ModuleName Diagnostics {
            $script:products
        }
        Mock Get-ArchesDefenderDiagnosticState -ModuleName Diagnostics {
            $script:defender
        }
    }

    It 'passes active Defender with consistent Security Center registration' {
        (Get-ArchesAntivirusDiagnostic).Status | Should -Be 'Pass'
    }

    It 'passes approved active third-party antivirus while Defender is passive' {
        $script:products = @(
            [PSCustomObject]@{ Product='Approved AV'; Active=$true; IsMicrosoft=$false },
            [PSCustomObject]@{ Product='Microsoft Defender'; Active=$false; IsMicrosoft=$true }
        )
        $script:defender.AntivirusEnabled = $false
        $script:defender.RealTimeProtectionEnabled = $false
        $script:defender.RunningMode = 'Passive Mode'

        $result = Get-ArchesAntivirusDiagnostic

        $result.Status | Should -Be 'Pass'
        $result.Severity | Should -Not -Be 'Critical'
    }

    It 'returns Unknown when Security Center is unavailable' {
        Mock Get-ArchesSecurityCenterAntivirusProducts -ModuleName Diagnostics {
            throw 'Security Center unavailable'
        }
        (Get-ArchesAntivirusDiagnostic).Status | Should -Be 'Unknown'
    }

    It 'returns Unknown for managed inactive Defender without established active protection' {
        $script:products = @()
        $script:defender.AntivirusEnabled = $false
        $script:defender.RealTimeProtectionEnabled = $false
        $script:defender.Managed = $true
        (Get-ArchesAntivirusDiagnostic).Status | Should -Be 'Unknown'
    }

    It 'returns Unknown for conflicting Defender and Security Center signals' {
        $script:products[0].Active = $false
        (Get-ArchesAntivirusDiagnostic).Status | Should -Be 'Unknown'
    }

    It 'returns Unknown when Defender state is unavailable and no active product is established' {
        $script:products = @()
        Mock Get-ArchesDefenderDiagnosticState -ModuleName Diagnostics {
            throw 'Defender unavailable'
        }
        (Get-ArchesAntivirusDiagnostic).Status | Should -Be 'Unknown'
    }

    It 'fails at High rather than Critical only when no active protection is established' {
        $script:products = @()
        $script:defender.AntivirusEnabled = $false
        $script:defender.RealTimeProtectionEnabled = $false

        $result = Get-ArchesAntivirusDiagnostic

        $result.Status | Should -Be 'Fail'
        $result.Severity | Should -Be 'High'
    }
}
