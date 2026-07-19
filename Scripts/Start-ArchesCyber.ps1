[CmdletBinding()]
param(
    [ValidateSet('Full','Security','Network','System')][string]$Scan = 'Full',
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE 'Desktop\ArchesCyberAudit'),
    [switch]$ProblemsOnly,
    [switch]$NoOpenReport
)

$ErrorActionPreference = 'Stop'
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
@('Logging.psm1','Results.psm1','Diagnostics.psm1','Reports.psm1') | ForEach-Object {
    Import-Module (Join-Path $moduleRoot $_) -Force -ErrorAction Stop
}

$logDirectory = Join-Path $PSScriptRoot 'Logs'
$logPath = New-ArchesLog -Directory $logDirectory
Write-ArchesLog -Path $logPath -Message "Starting $Scan scan."

try {
    $results = switch ($Scan) {
        'Security' { @(Get-ArchesSecurityDiagnostics) }
        'Network'  { @(Get-ArchesNetworkDiagnostics) }
        'System'   { @(Get-ArchesSystemDiagnostics) }
        default    { @(Invoke-ArchesFullScan) }
    }
    if ($ProblemsOnly) { $displayResults = @($results | Get-ArchesProblems) } else { $displayResults = @($results | Sort-ArchesResults) }
    $displayResults | Format-Table Severity, Category, Status, Title, Summary -AutoSize
    $report = Export-ArchesReport -Results $results -Directory $OutputDirectory
    Write-ArchesLog -Path $logPath -Message "Scan completed with $($report.ProblemCount) problem(s)."
    Write-Host "`nReport: $($report.Html)" -ForegroundColor Cyan
    if (-not $NoOpenReport) { Start-Process $report.Html }
}
catch {
    Write-ArchesLog -Path $logPath -Level ERROR -Message $_.Exception.Message
    throw
}
