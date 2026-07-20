Describe 'Legacy and alternate entry-point safety' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
    }

    It 'keeps the legacy client audit diagnostic path read-only' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Client-PC-Audit.ps1') -Raw
        $source | Should -Not -Match '(?im)^\s*(ipconfig\s+/flushdns|Restart-Service|sfc\s+/scannow|DISM\b)'
    }

    It 'marks legacy scripts as disabled Phase 1 entry points before collection starts' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Client-PC-Audit.ps1') -Raw
        $throwPosition = $source.IndexOf("throw 'Legacy audit disabled for Phase 1")
        $outputPosition = $source.IndexOf('New-Item -ItemType Directory')
        $throwPosition | Should -BeGreaterOrEqual 0
        $throwPosition | Should -BeLessThan $outputPosition
    }

    It 'directs legacy DNS repair requests to the trusted remediation entry point' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Client-PC-Audit.ps1') -Raw
        $source | Should -Match 'Invoke-ArchesFix\.ps1'
    }

    It 'contains no alternate firewall or network-reset mutation command' {
        $entryPoints = @(
            (Join-Path $root 'Client-PC-Audit.ps1'),
            (Join-Path (Split-Path -Parent $root) 'Auditor\Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1')
        )
        $source = @($entryPoints | ForEach-Object {
            Get-Content -LiteralPath $_ -Raw
        }) -join "`n"
        $source | Should -Not -Match '(?i)Set-NetFirewallProfile|netsh\s+(advfirewall|winsock|interface)\s+reset'
        $source | Should -Not -Match '(?i)Set-NetIPInterface|New-NetIPAddress|Set-DnsClientServerAddress'
    }
}
