$root = Split-Path -Parent $PSScriptRoot

Describe 'Technical inventory safety and scope' {
    BeforeAll {
        $diagnosticsSource = Get-Content -LiteralPath (Join-Path $root 'Modules\Diagnostics.psm1') -Raw
        $privacySource = Get-Content -LiteralPath (Join-Path $root 'Modules\Privacy.psm1') -Raw
    }

    It 'collects the requested read-only technician inventory' {
        $diagnosticsSource | Should -Match "SEC-FW-RULES-001"
        $diagnosticsSource | Should -Match "SEC-USERS-001"
        $diagnosticsSource | Should -Match "NET-IF-001"
        $diagnosticsSource | Should -Match "DEV-ARP-001"
        $diagnosticsSource | Should -Match 'Get-NetFirewallRule'
        $diagnosticsSource | Should -Match 'Get-NetIPConfiguration'
        $diagnosticsSource | Should -Match 'Get-LocalUser'
        $diagnosticsSource | Should -Match 'Get-NetNeighbor'
    }

    It 'does not export account names or firewall application paths' {
        $privacySource | Should -Not -Match "SEC-USERS-001'.*Name"
        $privacySource | Should -Not -Match "SEC-FW-RULES-001'.*(Program|Application|Service)"
    }

    It 'bounds potentially large firewall and neighbor inventories' {
        $diagnosticsSource | Should -Match '\$ruleLimit = 500'
        $diagnosticsSource | Should -Match '\$neighborLimit = 250'
        $diagnosticsSource | Should -Match 'Truncated = \$enabledRules.Count -gt \$ruleLimit'
        $diagnosticsSource | Should -Match 'Truncated = \$neighbors.Count -gt \$neighborLimit'
    }
}
