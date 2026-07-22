$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force

Describe 'Arches result model' {
    It 'creates a normalized result' {
        $result = New-ArchesResult -Id T1 -Category Security -Title Firewall -Status Fail -Severity High
        $result.Id | Should -Be 'T1'
        $result.Status | Should -Be 'Fail'
        $result.BusinessImpact | Should -Not -BeNullOrEmpty
    }
    It 'allows a reviewed finding-specific business impact' {
        $result = New-ArchesResult -Id CUSTOM -Category Security -Title Custom -Status Warning `
            -BusinessImpact 'A reviewed impact statement.'
        $result.BusinessImpact | Should -Be 'A reviewed impact statement.'
    }
    It 'does not turn an uncertain check into a confirmed condition through impact text' {
        $result = New-ArchesResult -Id SEC-FW-001 -Category Security -Title Firewall -Status Error
        $result.BusinessImpact | Should -Match 'could not be confirmed'
        $result.BusinessImpact | Should -Not -Match 'disabled firewall'
    }
    It 'sorts highest severity first' {
        $low = New-ArchesResult -Id L -Category Test -Title Low -Status Warning -Severity Low
        $critical = New-ArchesResult -Id C -Category Test -Title Critical -Status Fail -Severity Critical
        $sorted = @($low,$critical) | Sort-ArchesResults
        $sorted[0].Id | Should -Be 'C'
    }
    It 'filters passing checks from problems' {
        $pass = New-ArchesResult -Id P -Category Test -Title Pass -Status Pass
        $fail = New-ArchesResult -Id F -Category Test -Title Fail -Status Fail -Severity High
        $unknown = New-ArchesResult -Id U -Category Test -Title Unknown -Status Unknown
        $error = New-ArchesResult -Id E -Category Test -Title Error -Status Error
        $problems = @($pass,$fail,$unknown,$error) | Get-ArchesProblems
        @($problems).Count | Should -Be 1
        $problems.Id | Should -Be 'F'
    }
}
