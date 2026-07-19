[CmdletBinding()]
param([switch]$RunPester)

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$errorsFound = @()
Get-ChildItem -LiteralPath $projectRoot -Recurse -Include '*.ps1','*.psm1' -File | ForEach-Object {
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
Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json | Out-Null
Write-Host 'Configuration JSON passed.' -ForegroundColor Green

if ($RunPester) {
    if (-not (Get-Command Invoke-Pester -ErrorAction SilentlyContinue)) { throw 'Pester is not installed.' }
    $result = Invoke-Pester -Path $PSScriptRoot -PassThru
    if ($result.FailedCount -gt 0) { throw "$($result.FailedCount) Pester test(s) failed." }
}
