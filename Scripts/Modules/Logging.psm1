Set-StrictMode -Version 2.0

function New-ArchesLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }
    Join-Path $Directory ("ArchesCyber_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

function Write-ArchesLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Add-Content -LiteralPath $Path -Value $line -Encoding UTF8
    if ($Level -eq 'ERROR') { Write-Warning $Message }
}

Export-ModuleMember -Function New-ArchesLog, Write-ArchesLog
