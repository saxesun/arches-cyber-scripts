$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Scoring.psm1') -Force
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force
Import-Module (Join-Path $root 'Modules\Reports.psm1') -Force

Describe 'Arches report export' {
    BeforeEach {
        Mock Get-ArchesRollbackIntegrityKey -ModuleName Rollback {
            [byte[]](1..32)
        }
        $script:reportFirewallState = @{ Public = $true }
        Mock Set-ArchesFirewallProfileState -ModuleName Rollback {
            $script:reportFirewallState[$Profile] = [bool]$Enabled
        }
        Mock Get-ArchesFirewallProfileState -ModuleName Rollback {
            [PSCustomObject]@{ Name = $Profile; Enabled = [bool]$script:reportFirewallState[$Profile] }
        }
    }

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
        $html | Should -Match 'Complete validated change and rollback history'
        $html | Should -Match 'What this means'
        $html | Should -Match 'Why it matters'
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

    It 'exports business impact to HTML JSON and CSV' {
        $target = Join-Path $TestDrive 'impact'
        $result = New-ArchesResult -Id SEC-FW-001 -Category Security -Title Firewall `
            -Status Fail -Severity High -Summary 'The public firewall profile is disabled.'
        $report = Export-ArchesReport -Results @($result) -Directory $target -ComputerName TESTPC
        $json = Get-Content -LiteralPath $report.Json -Raw | ConvertFrom-Json
        $csv = Import-Csv -LiteralPath $report.Csv
        $html = Get-Content -LiteralPath $report.Html -Raw

        $json.Results[0].BusinessImpact | Should -Match 'unwanted inbound network traffic'
        $csv.BusinessImpact | Should -Match 'unwanted inbound network traffic'
        $html | Should -Match 'unwanted inbound network traffic'
    }

    It 'renders approved evidence as readable fields and lists instead of compressed JSON' {
        $target = Join-Path $TestDrive 'evidence'
        $result = New-ArchesResult -Id DEV-ARP-001 -Category 'Connected Devices' `
            -Title 'Neighbor table visibility' -Status Pass `
            -Evidence ([PSCustomObject]@{
                NeighborCount = 1
                Neighbors = @('IPv4=192.0.2.10; MAC=00-11-22-33-44-55; Interface=Ethernet; State=Reachable')
                Truncated = $false
            })
        $report = Export-ArchesReport -Results @($result) -Directory $target -ComputerName TESTPC
        $html = Get-Content -LiteralPath $report.Html -Raw

        $html | Should -Match 'Approved evidence \(3 field\(s\)\)'
        $html | Should -Match '<dl class="evidence-grid">'
        $html | Should -Match 'Neighbor Count'
        $html | Should -Match '<li><code>IPv4=192\.0\.2\.10; MAC=00-11-22-33-44-55'
        $html | Should -Not -Match '&quot;NeighborCount&quot;'
    }

    It 'shows malware status signature scan and threat counts in both report views' {
        $target = Join-Path $TestDrive 'malware-report'
        $results = @(
            (New-ArchesResult -Id SEC-AV-001 -Category Security -Title 'Antivirus protection' -Status Pass `
                -Summary 'Microsoft Defender is active.' -Evidence ([PSCustomObject]@{
                    SecurityCenterAvailable=$true; RegisteredProducts=@('Microsoft Defender'); ActiveThirdPartyProducts=@()
                    DefenderAvailable=$true; DefenderEnabled=$true; DefenderRealTimeEnabled=$true; DefenderMode='Normal'
                    Managed=$false; ConflictingSignals=$false
                })),
            (New-ArchesResult -Id SEC-MAL-STATUS-001 -Category Security -Title 'Malware protection status and scan history' -Status Pass `
                -Evidence ([PSCustomObject]@{
                    DefenderAvailable=$true; DefenderMode='Normal'; AntivirusEnabled=$true; RealTimeProtectionEnabled=$true
                    SignatureAgeDays=1; SignatureLastUpdated='2026-07-20T12:00:00-06:00'; SignatureVersion='1.2.3.4'
                    QuickScanEndTime='2026-07-20T13:00:00-06:00'; FullScanEndTime=$null
                    LastScanType='Quick'; LastScanEndTime='2026-07-20T13:00:00-06:00'
                })),
            (New-ArchesResult -Id SEC-MAL-THREAT-001 -Category Security -Title 'Malware detections and remediation status' -Status Pass `
                -Evidence ([PSCustomObject]@{
                    ThreatHistoryAvailable=$true; DetectedThreatCount=2; DetectionEventCount=2
                    QuarantinedThreatCount=2; UnresolvedThreatCount=0; ResolvedThreatCount=2
                    LatestDetectionTime='2026-07-19T12:00:00-06:00'; ThreatStatusSummaries=@('Status=Quarantined; Count=2')
                }))
        )
        $report = Export-ArchesReport -Results $results -Directory $target -ComputerName TESTPC
        $html = Get-Content -LiteralPath $report.Html -Raw

        ([regex]::Matches($html, '<h2>Malware (protection|diagnostics)</h2>')).Count | Should -Be 2
        $html | Should -Match 'Age: 1 day\(s\)'
        $html | Should -Match 'Quick - 2026-07-20'
        $html | Should -Match 'Detected: 2; quarantined: 2; unresolved: 0'
        $html | Should -Match 'Run an approved Defender scan'
        $html | Should -Match 'count-only'
    }

    It 'shows today applied and rolled-back changes in the client view and the full lifecycle in technical details' {
        $target = Join-Path $TestDrive 'history-reports'
        $rollbackDirectory = Join-Path $TestDrive 'rollback'
        $change = [PSCustomObject][ordered]@{
            TargetType = 'FirewallProfile'
            Target = 'Public'
            Property = 'Enabled'
            Before = $false
            After = $true
        }
        $rollbackPath = New-ArchesRollbackRecord -Directory $rollbackDirectory `
            -RemediationId FIX-FW-001 -ProtectionTier ConfigOnly -Changes @($change)
        Set-ArchesRollbackApplied -Path $rollbackPath `
            -VerificationDetails 'The Public firewall profile was verified enabled.' | Out-Null
        Restore-ArchesRollback -Path $rollbackPath -Approved -Confirm:$false | Out-Null

        $result = New-ArchesResult -Id SEC-FW-001 -Category Security -Title Firewall -Status Pass
        $report = Export-ArchesReport -Results @($result) -Directory $target `
            -ComputerName TESTPC -RollbackDirectory $rollbackDirectory
        $json = Get-Content -LiteralPath $report.Json -Raw | ConvertFrom-Json
        $html = Get-Content -LiteralPath $report.Html -Raw

        $report.TodayChangeEventCount | Should -Be 2
        $json.Summary.TodayChangeEventCount | Should -Be 2
        $json.ChangeHistory[0].Status | Should -Be 'RolledBack'
        $json.ChangeHistory[0].AppliedAt | Should -Not -BeNullOrEmpty
        $json.ChangeHistory[0].RolledBackAt | Should -Not -BeNullOrEmpty
        $json.ChangeHistory[0].VerificationSucceeded | Should -BeTrue
        $html | Should -Match '2 validated change event\(s\) were recorded today'
        $html | Should -Match 'Public firewall profile'
        $html | Should -Match '>Applied<'
        $html | Should -Match '>Rolled back<'
        $html | Should -Match '<strong>Created</strong>'
        $html | Should -Match '<strong>Applied</strong>'
        $html | Should -Match 'Rolled back / attempted'
        $html | Should -Match 'Every firewall profile matched its recorded previous Enabled value'
    }

    It 'does not represent a pending rollback record as a completed client change' {
        $target = Join-Path $TestDrive 'pending-reports'
        $rollbackDirectory = Join-Path $TestDrive 'pending-rollback'
        $change = [PSCustomObject][ordered]@{
            TargetType = 'FirewallProfile'
            Target = 'Public'
            Property = 'Enabled'
            Before = $false
            After = $true
        }
        New-ArchesRollbackRecord -Directory $rollbackDirectory -RemediationId FIX-FW-001 `
            -ProtectionTier ConfigOnly -Changes @($change) | Out-Null
        $result = New-ArchesResult -Id SEC-FW-001 -Category Security -Title Firewall -Status Pass
        $report = Export-ArchesReport -Results @($result) -Directory $target `
            -ComputerName TESTPC -RollbackDirectory $rollbackDirectory
        $html = Get-Content -LiteralPath $report.Html -Raw

        $report.TodayChangeEventCount | Should -Be 0
        $html | Should -Match 'No configuration changes were recorded today'
        $html | Should -Match 'No apply or rollback verification is recorded'
    }
}
