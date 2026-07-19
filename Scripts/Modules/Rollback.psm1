Set-StrictMode -Version 2.0

function New-ArchesRollbackRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$RemediationId,
        [Parameter(Mandatory)][object]$BeforeState,
        [Parameter(Mandatory)][string]$RestoreCommand,
        [string]$Description
    )
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $record = [PSCustomObject][ordered]@{
        SchemaVersion = 1
        Id = [guid]::NewGuid().ToString()
        RemediationId = $RemediationId
        ComputerName = $env:COMPUTERNAME
        CreatedAt = (Get-Date).ToString('o')
        Description = $Description
        BeforeState = $BeforeState
        RestoreCommand = $RestoreCommand
        Applied = $false
        AppliedAt = $null
    }
    $path = Join-Path $Directory ("Rollback_{0}_{1}.json" -f $RemediationId, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    $path
}

function Set-ArchesRollbackApplied {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $record.Applied = $true
    $record.AppliedAt = (Get-Date).ToString('o')
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Remove-ArchesExpiredRollback {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Directory, [ValidateRange(1,365)][int]$RetentionDays = 30)
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath $Directory -Filter 'Rollback_*.json' -File |
        Where-Object LastWriteTime -lt $cutoff |
        ForEach-Object { if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete expired rollback record')) { Remove-Item -LiteralPath $_.FullName -Force } }
}

Export-ModuleMember -Function New-ArchesRollbackRecord, Set-ArchesRollbackApplied, Remove-ArchesExpiredRollback
