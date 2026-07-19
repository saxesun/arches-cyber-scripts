$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Rollback.psm1') -Force

Describe 'Rollback records' {
    It 'persists the pre-change state' {
        $path = New-ArchesRollbackRecord -Directory $TestDrive -RemediationId TEST -BeforeState @{ Enabled=$false } -RestoreCommand 'Write-Output restore'
        Test-Path $path | Should -BeTrue
        $record = Get-Content $path -Raw | ConvertFrom-Json
        $record.RemediationId | Should -Be 'TEST'
        $record.Applied | Should -BeFalse
    }
    It 'marks a record as applied' {
        $path = New-ArchesRollbackRecord -Directory $TestDrive -RemediationId TEST2 -BeforeState @{} -RestoreCommand 'Write-Output restore'
        Set-ArchesRollbackApplied -Path $path
        (Get-Content $path -Raw | ConvertFrom-Json).Applied | Should -BeTrue
    }
}
