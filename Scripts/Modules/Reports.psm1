Set-StrictMode -Version 2.0

if (-not (Get-Command ConvertTo-ArchesSafeEvidence -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'Privacy.psm1') -ErrorAction Stop
}

function Export-ArchesReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$Directory,
        [string]$ComputerName = $env:COMPUTERNAME
    )
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeFileComputerName = ([string]$ComputerName -replace '[^A-Za-z0-9._-]', '_').Trim('._')
    if ([string]::IsNullOrWhiteSpace($safeFileComputerName)) {
        $safeFileComputerName = 'UnknownComputer'
    }
    $json = Join-Path $Directory "ArchesCyber_${safeFileComputerName}_${stamp}.json"
    $csv = Join-Path $Directory "ArchesCyber_${safeFileComputerName}_${stamp}.csv"
    $html = Join-Path $Directory "ArchesCyber_${safeFileComputerName}_${stamp}.html"
    $safeResults = @($Results | ForEach-Object {
        $classification = switch ($_.Status) {
            'Warning' { 'ConfirmedFinding' }
            'Fail' { 'ConfirmedFinding' }
            'Unknown' { 'Unknown' }
            'Error' { 'Error' }
            default { 'Pass' }
        }
        [PSCustomObject][ordered]@{
            Id = $_.Id
            Category = $_.Category
            Title = $_.Title
            Status = $_.Status
            Classification = $classification
            Severity = $_.Severity
            Summary = $_.Summary
            Evidence = ConvertTo-ArchesSafeEvidence -Id $_.Id -Evidence $_.Evidence -DiagnosticError:($_.Status -eq 'Error')
            Recommendation = $_.Recommendation
            RemediationId = $_.RemediationId
            RequiresAdmin = $_.RequiresAdmin
            CheckedAt = $_.CheckedAt
        }
    })
    $confirmed = @($safeResults | Where-Object Classification -eq 'ConfirmedFinding')
    $unknown = @($safeResults | Where-Object Classification -eq 'Unknown')
    $errors = @($safeResults | Where-Object Classification -eq 'Error')
    $jsonDocument = [PSCustomObject][ordered]@{
        Summary = [PSCustomObject][ordered]@{
            CheckCount = $safeResults.Count
            ConfirmedFindingCount = $confirmed.Count
            UnknownCount = $unknown.Count
            ErrorCount = $errors.Count
        }
        Results = $safeResults
    }
    $jsonDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $json -Encoding UTF8
    $safeResults | Select-Object Id,Category,Title,Status,Classification,Severity,Summary,Recommendation,CheckedAt | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
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
    $safeComputerName = [Net.WebUtility]::HtmlEncode([string]$ComputerName)
    $document = @"
<!doctype html><html><head><meta charset="utf-8"><title>Arches Cyber Report</title>
<style>body{font-family:Segoe UI,Arial;margin:32px;color:#172033}table{border-collapse:collapse;width:100%}th,td{padding:9px;border:1px solid #d8dee9;text-align:left}.pass{background:#eaf8ef}.warn{background:#fff6d8}.fail{background:#fdeaea}.summary{padding:14px;background:#eef3f8;margin-bottom:20px}</style></head>
<body><h1>Arches Cyber Diagnostic Report</h1><div class="summary"><strong>Computer:</strong> $safeComputerName<br><strong>Checks:</strong> $($Results.Count)<br><strong>Confirmed findings:</strong> $($confirmed.Count)<br><strong>Unknown:</strong> $($unknown.Count)<br><strong>Errors:</strong> $($errors.Count)<br><strong>Generated:</strong> $(Get-Date)</div>
<h2>Health scorecard</h2><table><thead><tr><th>Category</th><th>Score</th><th>Rating</th><th>Problems</th></tr></thead><tbody>$($scoreRows -join "`n")</tbody></table>
<h2>Diagnostic findings</h2>
<table><thead><tr><th>Severity</th><th>Category</th><th>Check</th><th>Status</th><th>Summary</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></body></html>
"@
    Set-Content -LiteralPath $html -Value $document -Encoding UTF8
    [PSCustomObject]@{
        Html = $html
        Json = $json
        Csv = $csv
        ProblemCount = $confirmed.Count
        ConfirmedFindingCount = $confirmed.Count
        UnknownCount = $unknown.Count
        ErrorCount = $errors.Count
        Scorecard = $scorecard
    }
}

Export-ModuleMember -Function Export-ArchesReport
