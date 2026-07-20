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

    It 'separates confirmed Unknown and Error counts in every report format' {
        $target = Join-Path $TestDrive 'classified'
        $results = @(
            (New-ArchesResult -Id PASS -Category Security -Title Pass -Status Pass),
            (New-ArchesResult -Id WARN -Category Security -Title Warning -Status Warning -Severity Low),
            (New-ArchesResult -Id FAIL -Category Security -Title Fail -Status Fail -Severity High),
            (New-ArchesResult -Id UNK -Category Security -Title Unknown -Status Unknown),
            (New-ArchesResult -Id ERR -Category Security -Title Error -Status Error)
        )
        $report = Export-ArchesReport -Results $results -Directory $target -ComputerName TESTPC
        $json = Get-Content -LiteralPath $report.Json -Raw | ConvertFrom-Json
        $csv = @(Import-Csv -LiteralPath $report.Csv)
        $html = Get-Content -LiteralPath $report.Html -Raw

        $report.ConfirmedFindingCount | Should -Be 2
        $report.UnknownCount | Should -Be 1
        $report.ErrorCount | Should -Be 1
        $json.Summary.ConfirmedFindingCount | Should -Be 2
        $json.Summary.UnknownCount | Should -Be 1
        $json.Summary.ErrorCount | Should -Be 1
        @($csv | Where-Object Classification -eq 'ConfirmedFinding').Count | Should -Be 2
        @($csv | Where-Object Classification -eq 'Unknown').Count | Should -Be 1
        @($csv | Where-Object Classification -eq 'Error').Count | Should -Be 1
        $html | Should -Match '2 confirmed findings'
        $html | Should -Match 'Unknown checks:</strong> 1'
        $html | Should -Match 'Diagnostic errors:</strong> 1'
        $html | Should -Match 'Client Summary'
        $html | Should -Match 'Technical Details'
        $html | Should -Match 'Inventory overview'
        $html | Should -Match 'Change and rollback history'
    }

    It 'creates a unique directory with report metadata' {
        $target = Join-Path $TestDrive 'unique'
        $result = New-ArchesResult -Id T1 -Category Test -Title Sample -Status Pass
        $report = Export-ArchesReport -Results @($result) -Directory $target `
            -ComputerName TESTPC -ScanType Network -ScriptVersion 0.2.0-dev -Elevated $true
        Split-Path -Parent $report.Html | Should -Be $report.Directory
        $json = Get-Content -LiteralPath $report.Json -Raw | ConvertFrom-Json
        $json.Metadata.ScanType | Should -Be 'Network'
        $json.Metadata.ScriptVersion | Should -Be '0.2.0-dev'
        $json.Metadata.Elevated | Should -BeTrue
    }
}
