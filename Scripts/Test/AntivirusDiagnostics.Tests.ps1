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

Describe 'Defender malware diagnostics' {
    BeforeEach {
        $script:malwareConfiguration = [PSCustomObject]@{
            Thresholds = [PSCustomObject]@{ AntivirusSignatureWarningDays = 3 }
        }
        $script:malwareDefender = [PSCustomObject]@{
            Available = $true
            AntivirusEnabled = $true
            RealTimeProtectionEnabled = $true
            RunningMode = 'Normal'
            Managed = $false
            SignatureAgeDays = 1
            SignatureLastUpdated = '2026-07-20T12:00:00-06:00'
            SignatureVersion = '1.2.3.4'
            QuickScanEndTime = '2026-07-20T13:00:00-06:00'
            FullScanEndTime = $null
            LastScanType = 'Quick'
            LastScanEndTime = '2026-07-20T13:00:00-06:00'
        }
        $script:threatState = [PSCustomObject]@{
            ThreatHistoryAvailable = $true
            DetectedThreatCount = 2
            DetectionEventCount = 3
            QuarantinedThreatCount = 2
            UnresolvedThreatCount = 0
            ResolvedThreatCount = 2
            LatestDetectionTime = '2026-07-19T12:00:00-06:00'
            ThreatStatusSummaries = @('Status=Quarantined; Count=2')
        }
        Mock Get-ArchesDefenderDiagnosticState -ModuleName Diagnostics { $script:malwareDefender }
        Mock Get-ArchesDefenderThreatState -ModuleName Diagnostics { $script:threatState }
    }

    It 'passes current signatures with completed scan history' {
        $result = Get-ArchesDefenderHealthDiagnostic -Configuration $script:malwareConfiguration
        $result.Status | Should -Be 'Pass'
        $result.Evidence.LastScanType | Should -Be 'Quick'
    }

    It 'warns when Defender signatures exceed the configured age' {
        $script:malwareDefender.SignatureAgeDays = 4
        (Get-ArchesDefenderHealthDiagnostic -Configuration $script:malwareConfiguration).Status |
            Should -Be 'Warning'
    }

    It 'warns when no completed scan time is reported' {
        $script:malwareDefender.QuickScanEndTime = $null
        $script:malwareDefender.LastScanType = $null
        $script:malwareDefender.LastScanEndTime = $null
        $result = Get-ArchesDefenderHealthDiagnostic -Configuration $script:malwareConfiguration
        $result.Status | Should -Be 'Warning'
        $result.Severity | Should -Be 'Low'
    }

    It 'treats passive Defender details as non-authoritative rather than failed' {
        $script:malwareDefender.RunningMode = 'Passive Mode'
        (Get-ArchesDefenderHealthDiagnostic -Configuration $script:malwareConfiguration).Status |
            Should -Be 'Unknown'
    }

    It 'fails when Defender reports an unresolved threat' {
        $script:threatState.UnresolvedThreatCount = 1
        $script:threatState.ResolvedThreatCount = 1
        $result = Get-ArchesDefenderThreatDiagnostic
        $result.Status | Should -Be 'Fail'
        $result.Severity | Should -Be 'High'
    }

    It 'passes resolved and quarantined historical threats with no unresolved record' {
        $result = Get-ArchesDefenderThreatDiagnostic
        $result.Status | Should -Be 'Pass'
        $result.Evidence.QuarantinedThreatCount | Should -Be 2
        $result.Evidence.UnresolvedThreatCount | Should -Be 0
    }
}
