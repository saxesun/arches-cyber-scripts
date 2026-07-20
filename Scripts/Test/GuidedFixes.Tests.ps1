$root = Split-Path -Parent $PSScriptRoot

Describe 'Guided Fixes safety boundary' {
    It 'requires a displayed current plan and explicit post-plan approval controls' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Start-ArchesGuidedFixes.ps1') -Raw
        $source | Should -Match 'Build Read-Only Plan'
        $source | Should -Match 'I reviewed and approve this exact displayed change'
        $source | Should -Match 'Final approval'
        $source | Should -Match 'Run Approved Change'
    }

    It 'uses only the trusted remediation module and contains no dynamic command execution' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Start-ArchesGuidedFixes.ps1') -Raw
        $source | Should -Match 'Invoke-ArchesRemediation'
        $source | Should -Not -Match 'Invoke-Expression'
        $source | Should -Not -Match 'ScriptBlock\.Create'
        $source | Should -Not -Match 'Start-Process'
    }

    It 'requires terminal approval after the CLI plan is displayed' {
        $source = Get-Content -LiteralPath (Join-Path $root 'Invoke-ArchesFix.ps1') -Raw
        $showPosition = $source.IndexOf('Show-ArchesRemediationPlan')
        $approvalPosition = $source.IndexOf('Type APPROVE')
        $invokePosition = $source.IndexOf('Invoke-ArchesRemediation')
        $showPosition | Should -BeGreaterThan -1
        $approvalPosition | Should -BeGreaterThan $showPosition
        $invokePosition | Should -BeGreaterThan $approvalPosition
    }
}
