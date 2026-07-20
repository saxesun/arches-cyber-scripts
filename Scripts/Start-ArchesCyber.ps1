[CmdletBinding()]
param(
    [ValidateSet('Full','Security','Network','System','Devices','Performance')][string]$Scan = 'Full',
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE 'Desktop\ArchesCyberAudit'),
    [switch]$ProblemsOnly,
    [switch]$NoOpenReport
)

$ErrorActionPreference = 'Stop'
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
@('Config.psm1','Logging.psm1','Privacy.psm1','Results.psm1','Diagnostics.psm1','Scoring.psm1','Reports.psm1') | ForEach-Object {
    Import-Module (Join-Path $moduleRoot $_) -Force -ErrorAction Stop
}
$configuration = Get-ArchesConfiguration

$logDirectory = Join-Path $PSScriptRoot 'Logs'
$logPath = New-ArchesLog -Directory $logDirectory
Write-ArchesLog -Path $logPath -Message "Starting $Scan scan."

try {
    $results = switch ($Scan) {
        'Security' { @(Get-ArchesSecurityDiagnostics -Configuration $configuration) }
        'Network'  { @(Get-ArchesNetworkDiagnostics -Configuration $configuration) }
        'System'   { @(Get-ArchesSystemDiagnostics -Configuration $configuration) }
        'Devices'  { @(Get-ArchesConnectedDeviceDiagnostics -Configuration $configuration) }
        'Performance' { @(Get-ArchesPerformanceDiagnostics -Configuration $configuration) }
        default    { @(Invoke-ArchesFullScan -Configuration $configuration) }
    }
    $confirmedFindings = @($results | Where-Object Status -in @('Warning', 'Fail') | Sort-ArchesResults)
    $unknownResults = @($results | Where-Object Status -eq 'Unknown' | Sort-ArchesResults)
    $errorResults = @($results | Where-Object Status -eq 'Error' | Sort-ArchesResults)
    if ($ProblemsOnly) {
        Write-Host "`nConfirmed findings: $($confirmedFindings.Count)"
        $confirmedFindings | Format-Table Severity, Category, Status, Title, Summary -AutoSize
        Write-Host "`nUnknown checks: $($unknownResults.Count)"
        $unknownResults | Format-Table Category, Status, Title, Summary -AutoSize
        Write-Host "`nCheck errors: $($errorResults.Count)"
        $errorResults | Format-Table Category, Status, Title, Summary -AutoSize
    }
    else {
        $results | Sort-ArchesResults | Format-Table Severity, Category, Status, Title, Summary -AutoSize
        Write-Host "`nConfirmed findings: $($confirmedFindings.Count); Unknown: $($unknownResults.Count); Errors: $($errorResults.Count)"
    }
    $report = Export-ArchesReport -Results $results -Directory $OutputDirectory
    Write-ArchesLog -Path $logPath -Message "Scan completed: ConfirmedFindings=$($report.ConfirmedFindingCount); Unknown=$($report.UnknownCount); Errors=$($report.ErrorCount)."
    Write-Host "`nReport: $($report.Html)" -ForegroundColor Cyan
    if (-not $NoOpenReport) { Start-Process $report.Html }
}
catch {
    Write-ArchesLog -Path $logPath -Level ERROR -Message $_.Exception.Message
    throw
}
