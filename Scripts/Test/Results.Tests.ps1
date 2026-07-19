$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force

Describe 'Arches result model' {
    It 'creates a normalized result' {
        $result = New-ArchesResult -Id T1 -Category Security -Title Firewall -Status Fail -Severity High
        $result.Id | Should -Be 'T1'
        $result.Status | Should -Be 'Fail'
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
        $problems = @($pass,$fail) | Get-ArchesProblems
        @($problems).Count | Should -Be 1
        $problems.Id | Should -Be 'F'
    }
}
