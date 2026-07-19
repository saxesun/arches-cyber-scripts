$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Scoring.psm1') -Force
Import-Module (Join-Path $root 'Modules\Reports.psm1') -Force

Describe 'Arches report export' {
    It 'creates HTML JSON and CSV outputs' {
        $target = Join-Path $TestDrive 'reports'
        $result = New-ArchesResult -Id T1 -Category Test -Title Sample -Status Pass -Summary 'OK'
        $report = Export-ArchesReport -Results @($result) -Directory $target -ComputerName TESTPC
        Test-Path $report.Html | Should -BeTrue
        Test-Path $report.Json | Should -BeTrue
        Test-Path $report.Csv | Should -BeTrue
    }
}
