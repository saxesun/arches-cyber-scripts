$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Scoring.psm1') -Force

Describe 'Arches scorecard' {
    BeforeAll {
        function New-ScoringResult {
            param(
                [string]$Status = 'Pass',
                [string]$Severity = 'Info',
                [string]$Id = ([guid]::NewGuid().ToString())
            )
            New-ArchesResult -Id $Id -Category Security -Title $Id -Status $Status -Severity $Severity
        }
    }

    It 'rates a passing category Great' {
        $results = @(New-ArchesResult -Id P -Category Security -Title Pass -Status Pass)
        (Get-ArchesCategoryScore -Results $results -Category Security).Rating | Should -Be 'Great'
    }
    It 'applies larger penalties to critical failures' {
        $critical = @(New-ArchesResult -Id C -Category Security -Title Critical -Status Fail -Severity Critical)
        $low = @(New-ArchesResult -Id L -Category Security -Title Low -Status Fail -Severity Low)
        (Get-ArchesCategoryScore -Results $critical -Category Security).Score | Should -BeLessThan (Get-ArchesCategoryScore -Results $low -Category Security).Score
    }
    It 'marks missing categories as Not Scanned' {
        $results = @(New-ArchesResult -Id P -Category Security -Title Pass -Status Pass)
        (Get-ArchesCategoryScore -Results $results -Category Network).Rating | Should -Be 'Not Scanned'
    }

    It 'does not score Error or Unknown as confirmed failures' -TestCases @(
        @{ Status = 'Error' }
        @{ Status = 'Unknown' }
    ) {
        param($Status)
        $results = @(New-ScoringResult -Status $Status -Severity Critical)
        $score = Get-ArchesCategoryScore -Results $results -Category Security
        $score.Score | Should -BeNullOrEmpty
        $score.Rating | Should -Be 'Not Scanned'
        $score.ProblemCount | Should -Be 0
        $score.UncertainCount | Should -Be 1
    }

    It 'does not let unavailable or managed Unknown checks alter confirmed scoring' {
        $results = @(
            (New-ScoringResult -Status Pass),
            (New-ScoringResult -Status Unknown -Severity Critical -Id Unavailable),
            (New-ScoringResult -Status Unknown -Severity Critical -Id Managed)
        )
        $score = Get-ArchesCategoryScore -Results $results -Category Security
        $score.Score | Should -Be 100
        $score.Rating | Should -Be 'Great'
        $score.UncertainCount | Should -Be 2
    }

    It 'scores only confirmed statuses deterministically' {
        (Get-ArchesCategoryScore -Results @((New-ScoringResult -Status Pass -Severity Critical)) -Category Security).Score |
            Should -Be 100
        (Get-ArchesCategoryScore -Results @((New-ScoringResult -Status Warning -Severity High)) -Category Security).Score |
            Should -Be 87
        (Get-ArchesCategoryScore -Results @((New-ScoringResult -Status Fail -Severity High)) -Category Security).Score |
            Should -Be 75
    }

    It 'covers every rating boundary' -TestCases @(
        @{ Expected = 'Great'; Results = @(@{ Status='Fail'; Severity='Low' }, @{ Status='Fail'; Severity='Low' }) }
        @{ Expected = 'Good'; Results = @(@{ Status='Fail'; Severity='High' }) }
        @{ Expected = 'Not Good'; Results = @(@{ Status='Fail'; Severity='High' }, @{ Status='Fail'; Severity='High' }) }
        @{ Expected = 'Bad'; Results = @(@{ Status='Fail'; Severity='High' }, @{ Status='Fail'; Severity='High' }, @{ Status='Fail'; Severity='Low' }) }
    ) {
        param($Expected, $Results)
        $findings = @($Results | ForEach-Object {
            New-ScoringResult -Status $_.Status -Severity $_.Severity
        })
        (Get-ArchesCategoryScore -Results $findings -Category Security).Rating |
            Should -Be $Expected
    }

    It 'uses the upper edge below each rating boundary' -TestCases @(
        @{ Expected = 'Good'; Results = @(@{ Status='Fail'; Severity='Low' }, @{ Status='Warning'; Severity='Medium' }) }
        @{ Expected = 'Not Good'; Results = @(@{ Status='Warning'; Severity='High' }, @{ Status='Warning'; Severity='High' }) }
        @{ Expected = 'Bad'; Results = @(@{ Status='Fail'; Severity='Critical' }, @{ Status='Fail'; Severity='Low' }, @{ Status='Fail'; Severity='Low' }, @{ Status='Warning'; Severity='Medium' }) }
    ) {
        param($Expected, $Results)
        $findings = @($Results | ForEach-Object {
            New-ScoringResult -Status $_.Status -Severity $_.Severity
        })
        (Get-ArchesCategoryScore -Results $findings -Category Security).Rating |
            Should -Be $Expected
    }
}
