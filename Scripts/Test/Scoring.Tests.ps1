$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Scoring.psm1') -Force

Describe 'Arches scorecard' {
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
}
