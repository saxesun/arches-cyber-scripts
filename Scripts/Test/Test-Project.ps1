[CmdletBinding()]
param([switch]$RunPester)

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$errorsFound = @()
$powerShellFiles = Get-ChildItem -LiteralPath $projectRoot -Recurse -File | Where-Object {
    $_.Extension -in @('.ps1', '.psm1')
}

$powerShellFiles | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
    foreach ($parseError in $parseErrors) {
        $errorsFound += [PSCustomObject]@{ File=$_.FullName; Line=$parseError.Extent.StartLineNumber; Message=$parseError.Message }
    }
}

if ($errorsFound.Count) {
    $errorsFound | Format-Table -AutoSize
    throw "$($errorsFound.Count) PowerShell parse error(s) found."
}
Write-Host 'PowerShell parsing passed.' -ForegroundColor Green

$configPath = Join-Path $projectRoot 'Scripts\Config\Phase1.json'
Import-Module (Join-Path $projectRoot 'Scripts\Modules\Config.psm1') -Force
Get-ArchesConfiguration -Path $configPath | Out-Null
Write-Host 'Configuration JSON passed.' -ForegroundColor Green

if ($RunPester) {
    if (-not (Get-Command Invoke-Pester -ErrorAction SilentlyContinue)) { throw 'Pester is not installed.' }
    $result = Invoke-Pester -Path $PSScriptRoot -PassThru
    if ($result.FailedCount -gt 0) { throw "$($result.FailedCount) Pester test(s) failed." }
}
