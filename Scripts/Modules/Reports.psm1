Set-StrictMode -Version 2.0

function Export-ArchesReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$Directory,
        [string]$ComputerName = $env:COMPUTERNAME
    )
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $json = Join-Path $Directory "ArchesCyber_${ComputerName}_${stamp}.json"
    $csv = Join-Path $Directory "ArchesCyber_${ComputerName}_${stamp}.csv"
    $html = Join-Path $Directory "ArchesCyber_${ComputerName}_${stamp}.html"
    $Results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $json -Encoding UTF8
    $Results | Select-Object Id,Category,Title,Status,Severity,Summary,Recommendation,CheckedAt | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $problems = @($Results | Get-ArchesProblems)
    $scorecard = @(Get-ArchesScorecard -Results $Results)
    $scoreRows = foreach ($score in $scorecard) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f $score.Category,$score.Score,$score.Rating,$score.ProblemCount
    }
    $rows = foreach ($result in $Results) {
        $class = if ($result.Status -eq 'Pass') { 'pass' } elseif ($result.Status -eq 'Warning') { 'warn' } else { 'fail' }
        '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f $class,
            [Net.WebUtility]::HtmlEncode([string]$result.Severity), [Net.WebUtility]::HtmlEncode([string]$result.Category),
            [Net.WebUtility]::HtmlEncode([string]$result.Title), [Net.WebUtility]::HtmlEncode([string]$result.Status),
            [Net.WebUtility]::HtmlEncode([string]$result.Summary)
    }
    $document = @"
<!doctype html><html><head><meta charset="utf-8"><title>Arches Cyber Report</title>
<style>body{font-family:Segoe UI,Arial;margin:32px;color:#172033}table{border-collapse:collapse;width:100%}th,td{padding:9px;border:1px solid #d8dee9;text-align:left}.pass{background:#eaf8ef}.warn{background:#fff6d8}.fail{background:#fdeaea}.summary{padding:14px;background:#eef3f8;margin-bottom:20px}</style></head>
<body><h1>Arches Cyber Diagnostic Report</h1><div class="summary"><strong>Computer:</strong> $ComputerName<br><strong>Checks:</strong> $($Results.Count)<br><strong>Problems:</strong> $($problems.Count)<br><strong>Generated:</strong> $(Get-Date)</div>
<h2>Health scorecard</h2><table><thead><tr><th>Category</th><th>Score</th><th>Rating</th><th>Problems</th></tr></thead><tbody>$($scoreRows -join "`n")</tbody></table>
<h2>Diagnostic findings</h2>
<table><thead><tr><th>Severity</th><th>Category</th><th>Check</th><th>Status</th><th>Summary</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></body></html>
"@
    Set-Content -LiteralPath $html -Value $document -Encoding UTF8
    [PSCustomObject]@{ Html = $html; Json = $json; Csv = $csv; ProblemCount = $problems.Count; Scorecard = $scorecard }
}

Export-ModuleMember -Function Export-ArchesReport
