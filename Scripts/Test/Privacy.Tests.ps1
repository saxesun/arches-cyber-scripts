$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Privacy.psm1') -Force
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Scoring.psm1') -Force
Import-Module (Join-Path $root 'Modules\Reports.psm1') -Force

Describe 'Phase 1 evidence and report privacy' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $seededSecrets = @(
            'Seeded-Recovery-Password-111111',
            'Seeded-Bearer-Token-222222',
            'Seeded-Credential-Command-333333',
            'Seeded-Browser-Message-444444',
            'Seeded-Unnecessary-User-555555'
        )
    }

    It 'retains only allowlisted BitLocker evidence fields' {
        $evidence = [PSCustomObject]@{
            MountPoint = 'C:'
            ProtectionStatus = 'On'
            RecoveryPassword = $seededSecrets[0]
            Token = $seededSecrets[1]
            CommandLine = $seededSecrets[2]
            BrowserMessage = $seededSecrets[3]
            UserName = $seededSecrets[4]
        }
        $safe = ConvertTo-ArchesSafeEvidence -Id SEC-BL-001 -Evidence $evidence
        @($safe.PSObject.Properties.Name) | Should -Be @('MountPoint', 'ProtectionStatus')
        ($safe | ConvertTo-Json -Compress) | Should -Not -Match 'Seeded-'
    }

    It 'drops evidence for unknown finding ids' {
        $evidence = [PSCustomObject]@{ Password = $seededSecrets[0]; Harmless = 'value' }
        ConvertTo-ArchesSafeEvidence -Id UNKNOWN-001 -Evidence $evidence |
            Should -BeNullOrEmpty
    }

    It 'exports only approved technical inventory fields' {
        $safe = ConvertTo-ArchesSafeEvidence -Id DEV-ARP-001 -Evidence ([PSCustomObject]@{
            NeighborCount = 1
            Neighbors = @('IPv4=192.0.2.10; MAC=00-11-22-33-44-55; Interface=Ethernet; State=Reachable')
            Truncated = $false
            HostName = $seededSecrets[4]
            UserName = $seededSecrets[4]
        })
        @($safe.PSObject.Properties.Name) | Should -Be @('NeighborCount', 'Neighbors', 'Truncated')
        ($safe | ConvertTo-Json -Compress) | Should -Not -Match 'Seeded-'
    }

    It 'keeps local account inventory count-only' {
        $safe = ConvertTo-ArchesSafeEvidence -Id SEC-USERS-001 -Evidence ([PSCustomObject]@{
            LocalUserCount = 3
            EnabledUserCount = 2
            DisabledUserCount = 1
            PasswordRequiredCount = 2
            Names = @($seededSecrets[4])
        })
        @($safe.PSObject.Properties.Name) | Should -Not -Contain 'Names'
        ($safe | ConvertTo-Json -Compress) | Should -Not -Match 'Seeded-'
    }

    It 'keeps Defender threat reporting count-only and drops affected paths' {
        $safe = ConvertTo-ArchesSafeEvidence -Id SEC-MAL-THREAT-001 -Evidence ([PSCustomObject]@{
            ThreatHistoryAvailable = $true
            DetectedThreatCount = 2
            DetectionEventCount = 2
            QuarantinedThreatCount = 1
            UnresolvedThreatCount = 1
            ResolvedThreatCount = 1
            LatestDetectionTime = '2026-07-20T12:00:00Z'
            ThreatStatusSummaries = @('Status=Active; Count=1', 'Status=Quarantined; Count=1')
            Resources = @($seededSecrets[0])
            ProcessName = $seededSecrets[2]
            DomainUser = $seededSecrets[4]
        })
        @($safe.PSObject.Properties.Name) | Should -Not -Contain 'Resources'
        @($safe.PSObject.Properties.Name) | Should -Not -Contain 'ProcessName'
        @($safe.PSObject.Properties.Name) | Should -Not -Contain 'DomainUser'
        ($safe | ConvertTo-Json -Compress) | Should -Not -Match 'Seeded-'
    }

    It 'sanitizes seeded sensitive values again during report export' {
        $target = Join-Path $TestDrive 'reports'
        $unsafeResult = [PSCustomObject]@{
            Id = 'SEC-BL-001'
            Category = 'Security'
            Title = 'BitLocker'
            Status = 'Pass'
            Severity = 'Info'
            Summary = 'Protection status checked.'
            Evidence = [PSCustomObject]@{
                MountPoint = 'C:'
                ProtectionStatus = 'On'
                RecoveryKey = $seededSecrets[0]
                AccessToken = $seededSecrets[1]
                CommandLine = $seededSecrets[2]
                BrowserMessage = $seededSecrets[3]
                UserName = $seededSecrets[4]
            }
            Recommendation = $null
            RemediationId = $null
            RequiresAdmin = $false
            CheckedAt = '2026-07-20T00:00:00Z'
        }
        $report = Export-ArchesReport -Results @($unsafeResult) -Directory $target `
            -ComputerName '<script>seeded-computer</script>'
        $json = Get-Content -LiteralPath $report.Json -Raw
        $html = Get-Content -LiteralPath $report.Html -Raw
        $csv = Get-Content -LiteralPath $report.Csv -Raw
        foreach ($secret in $seededSecrets) {
            $json | Should -Not -Match ([regex]::Escape($secret))
            $html | Should -Not -Match ([regex]::Escape($secret))
            $csv | Should -Not -Match ([regex]::Escape($secret))
        }
        $html | Should -Not -Match '<script>seeded-computer</script>'
        $html | Should -Match '&lt;script&gt;seeded-computer&lt;/script&gt;'
    }

    It 'does not expose contents from an invalid rollback record' {
        $target = Join-Path $TestDrive 'invalid-history-report'
        $rollbackDirectory = Join-Path $TestDrive 'invalid-history'
        New-Item -ItemType Directory -Path $rollbackDirectory -Force | Out-Null
        $invalidPath = Join-Path $rollbackDirectory 'Rollback_seeded_invalid.json'
        '{"RecordId":"Seeded-Recovery-Password-111111","Changes":["Seeded-Bearer-Token-222222"]}' |
            Set-Content -LiteralPath $invalidPath -Encoding UTF8
        $result = New-ArchesResult -Id PASS -Category Security -Title Pass -Status Pass
        $report = Export-ArchesReport -Results @($result) -Directory $target `
            -ComputerName TESTPC -RollbackDirectory $rollbackDirectory
        $jsonText = Get-Content -LiteralPath $report.Json -Raw
        $html = Get-Content -LiteralPath $report.Html -Raw
        $json = $jsonText | ConvertFrom-Json

        $json.ChangeHistory[0].Trusted | Should -BeFalse
        @($json.ChangeHistory[0].Changes).Count | Should -Be 0
        $jsonText | Should -Not -Match 'Seeded-'
        $html | Should -Not -Match 'Seeded-'
        $html | Should -Match 'failed validation and no contents were trusted'
    }

    It 'does not collect the legacy DNS resolver cache' {
        $repositoryRoot = Split-Path -Parent $root
        $legacySource = @(
            Get-Content -LiteralPath (Join-Path $root 'Client-PC-Audit.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $repositoryRoot 'Auditor\Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1') -Raw
        ) -join "`n"
        $legacySource | Should -Not -Match '(?i)displaydns|DNS Cache Sample'
        $legacySource | Should -Not -Match 'CsUserName|AdminNames'
        $legacySource | Should -Not -Match 'Select-Object Name, Command, Location, User'
        $legacySource | Should -Not -Match 'Select-Object LocalPath, RemotePath, Status, UserName'
        $legacySource | Should -Not -Match 'Select-Object StatusCode, StatusDescription, Headers, Content'
        $legacySource | Should -Not -Match 'FullPath\s*='
        $legacySource | Should -Not -Match 'Get-SmbShare\s*\|\s*Select-Object.*Path'
        $legacySource | Should -Not -Match 'Get-SmbMapping\s*\|\s*Select-Object.*RemotePath'
        $legacySource | Should -Not -Match 'Get-Printer\s*\|\s*Select-Object.*Name'
    }

    It 'blocks both legacy audit scripts before any report artifact is created' {
        $repositoryRoot = Split-Path -Parent $root
        $legacyScripts = @(
            (Join-Path $root 'Client-PC-Audit.ps1'),
            (Join-Path $repositoryRoot 'Auditor\Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1')
        )
        $artifactCountBefore = @(Get-ChildItem -LiteralPath $TestDrive -Recurse -File).Count
        foreach ($scriptPath in $legacyScripts) {
            { & $scriptPath } | Should -Throw '*Legacy audit disabled for Phase 1*'
        }
        @(Get-ChildItem -LiteralPath $TestDrive -Recurse -File).Count |
            Should -Be $artifactCountBefore
    }
}
