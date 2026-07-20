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
