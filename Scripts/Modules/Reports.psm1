Set-StrictMode -Version 2.0

if (-not (Get-Command ConvertTo-ArchesSafeEvidence -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'Privacy.psm1') -ErrorAction Stop
}

function ConvertTo-ArchesHtml {
    param([object]$Value)
    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ArchesReportChangeHistory {
    [CmdletBinding()]
    param([string]$RollbackDirectory)
    if ([string]::IsNullOrWhiteSpace($RollbackDirectory) -or
        -not (Test-Path -LiteralPath $RollbackDirectory -PathType Container)) {
        return @()
    }
    if (-not (Get-Command Get-ArchesRollbackRecord -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path $PSScriptRoot 'Rollback.psm1') -Force -ErrorAction Stop
    }
    $history = @()
    Get-ChildItem -LiteralPath $RollbackDirectory -Filter 'Rollback_*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | ForEach-Object {
            try {
                $record = Get-ArchesRollbackRecord -Path $_.FullName
                $history += [PSCustomObject][ordered]@{
                    RecordId = $record.RecordId
                    RemediationId = $record.RemediationId
                    CreatedAt = $record.CreatedAt
                    Status = $record.Status
                    ProtectionTier = $record.ProtectionTier
                    Changes = @($record.Changes)
                    RollbackAvailable = $record.Status -eq 'Applied'
                }
            }
            catch {
                $history += [PSCustomObject][ordered]@{
                    RecordId = $_.BaseName
                    RemediationId = 'UntrustedRecord'
                    CreatedAt = $_.LastWriteTime.ToString('o')
                    Status = 'Invalid'
                    ProtectionTier = 'Unknown'
                    Changes = @()
                    RollbackAvailable = $false
                }
            }
        }
    @($history)
}

function Export-ArchesReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$Directory,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$ScanType = 'Full',
        [string]$ScriptVersion = '0.1.0-dev',
        [bool]$Elevated = $false,
        [string]$RollbackDirectory
    )
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeFileComputerName = ([string]$ComputerName -replace '[^A-Za-z0-9._-]', '_').Trim('._')
    if ([string]::IsNullOrWhiteSpace($safeFileComputerName)) {
        $safeFileComputerName = 'UnknownComputer'
    }
    $runDirectory = Join-Path $Directory "ArchesCyber_${safeFileComputerName}_${stamp}"
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $json = Join-Path $runDirectory 'ArchesCyber-Data.json'
    $csv = Join-Path $runDirectory 'ArchesCyber-Results.csv'
    $html = Join-Path $runDirectory 'ArchesCyber-Report.html'
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
    $changeHistory = @(Get-ArchesReportChangeHistory -RollbackDirectory $RollbackDirectory)
    $jsonDocument = [PSCustomObject][ordered]@{
        Metadata = [PSCustomObject][ordered]@{
            ComputerName = $ComputerName
            GeneratedAt = (Get-Date).ToString('o')
            ScanType = $ScanType
            ScriptVersion = $ScriptVersion
            Elevated = $Elevated
        }
        Summary = [PSCustomObject][ordered]@{
            CheckCount = $safeResults.Count
            ConfirmedFindingCount = $confirmed.Count
            UnknownCount = $unknown.Count
            ErrorCount = $errors.Count
        }
        Results = $safeResults
        ChangeHistory = $changeHistory
    }
    $jsonDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $json -Encoding UTF8
    $safeResults | Select-Object Id,Category,Title,Status,Classification,Severity,Summary,Recommendation,CheckedAt | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $scorecard = @(Get-ArchesScorecard -Results $Results)
    $scoreCards = foreach ($score in $scorecard) {
        '<div class="score"><span>{0}</span><strong>{1}</strong><span>{2} · {3} finding(s)</span></div>' -f `
            (ConvertTo-ArchesHtml $score.Category), $score.Score,
            (ConvertTo-ArchesHtml $score.Rating), $score.ProblemCount
    }
    $clientRows = foreach ($result in $confirmed) {
        $action = if ($result.RemediationId) { '<button class="fix" onclick="showFixNotice()">Review Fix</button>' } else { '<span class="muted">More information</span>' }
        '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f $result.Status.ToLowerInvariant(),
            (ConvertTo-ArchesHtml $result.Severity), (ConvertTo-ArchesHtml $result.Category),
            (ConvertTo-ArchesHtml $result.Title), (ConvertTo-ArchesHtml $result.Status),
            (ConvertTo-ArchesHtml $result.Summary), $action
    }
    $technicalRows = foreach ($result in $safeResults) {
        $evidenceText = if ($null -eq $result.Evidence) { 'No approved evidence exported.' } else {
            ConvertTo-ArchesHtml ($result.Evidence | ConvertTo-Json -Depth 8 -Compress)
        }
        '<tr class="{0}" data-status="{0}" data-category="{1}"><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td><details><summary>View evidence</summary><code>{7}</code></details></td><td>{8}</td></tr>' -f `
            $result.Status.ToLowerInvariant(), (ConvertTo-ArchesHtml $result.Category),
            (ConvertTo-ArchesHtml $result.Id), (ConvertTo-ArchesHtml $result.Severity),
            (ConvertTo-ArchesHtml $result.Category), (ConvertTo-ArchesHtml $result.Title),
            (ConvertTo-ArchesHtml $result.Status), $evidenceText,
            (ConvertTo-ArchesHtml $result.Recommendation)
    }
    $historyRows = foreach ($entry in $changeHistory) {
        $changes = if (@($entry.Changes).Count) {
            @($entry.Changes | ForEach-Object { "$($_.Target): $($_.Before) -> $($_.After)" }) -join '; '
        } else { 'No trusted change details available.' }
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
            (ConvertTo-ArchesHtml $entry.CreatedAt), (ConvertTo-ArchesHtml $entry.RemediationId),
            (ConvertTo-ArchesHtml $changes), (ConvertTo-ArchesHtml $entry.Status),
            (ConvertTo-ArchesHtml $entry.ProtectionTier),
            $(if ($entry.RollbackAvailable) { 'Yes' } else { 'No' })
    }
    $networkInventory = $safeResults | Where-Object Id -eq 'NET-IF-001' | Select-Object -First 1
    $neighborInventory = $safeResults | Where-Object Id -eq 'DEV-ARP-001' | Select-Object -First 1
    $firewallInventory = $safeResults | Where-Object Id -eq 'SEC-FW-RULES-001' | Select-Object -First 1
    $administratorInventory = $safeResults | Where-Object Id -eq 'SEC-ADM-001' | Select-Object -First 1
    $userInventory = $safeResults | Where-Object Id -eq 'SEC-USERS-001' | Select-Object -First 1
    $inventoryCards = @(
        [PSCustomObject]@{ Label='Active interfaces'; Value=if($networkInventory.Evidence){$networkInventory.Evidence.InterfaceCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Observed neighbors'; Value=if($neighborInventory.Evidence){$neighborInventory.Evidence.NeighborCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Firewall rules'; Value=if($firewallInventory.Evidence){$firewallInventory.Evidence.RuleCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Administrator principals'; Value=if($administratorInventory.Evidence){$administratorInventory.Evidence.PrincipalCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Local user accounts'; Value=if($userInventory.Evidence){$userInventory.Evidence.LocalUserCount}else{'Unavailable'} }
    ) | ForEach-Object {
        '<div class="score"><span>{0}</span><strong>{1}</strong></div>' -f `
            (ConvertTo-ArchesHtml $_.Label), (ConvertTo-ArchesHtml $_.Value)
    }
    $safeComputerName = [Net.WebUtility]::HtmlEncode([string]$ComputerName)
    $document = @"
<!doctype html><html><head><meta charset="utf-8"><title>Arches Cyber Report</title>
<style>
:root{--navy:#0b2f64;--blue:#1769d2;--line:#d8e0ea;--soft:#f3f7fb;--green:#17783d;--amber:#a45a00;--red:#b42318}*{box-sizing:border-box}body{font-family:Segoe UI,Arial;margin:0;color:#172033;background:#fff}.shell{max-width:1500px;margin:auto;padding:26px 34px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:16px}.tabs button{padding:12px 28px;border:1px solid var(--line);background:#fff;color:var(--navy);font-weight:650;cursor:pointer}.tabs button.active{background:var(--navy);color:#fff}.view{display:none}.view.active{display:block}.meta,.card{border:1px solid var(--line);border-radius:10px;padding:18px;margin-top:18px}.meta{background:var(--soft);display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.scores{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.score{text-align:center;border:1px solid var(--line);border-radius:8px;padding:14px}.score strong{display:block;font-size:28px;color:var(--green)}table{border-collapse:collapse;width:100%;margin-top:10px}th,td{padding:10px;border:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--soft)}tr.pass{background:#edf9f1}tr.warning{background:#fff8df}tr.fail{background:#fff0f0}tr.unknown,tr.error{background:#f4f1ff}.fix{background:var(--blue);color:#fff;border:0;border-radius:6px;padding:8px 12px}.muted{color:#5b6675}.pill{display:inline-block;border-radius:999px;padding:4px 9px;background:var(--soft)}.split{display:grid;grid-template-columns:2fr 1fr;gap:18px}.notice{padding:14px;border-left:5px solid var(--blue);background:#eef5ff}.warning-note{border-left-color:var(--amber);background:#fff8e5}code{white-space:pre-wrap;word-break:break-word}input{padding:10px;width:330px;border:1px solid var(--line);border-radius:6px}.sensitive{color:var(--red);font-weight:700}@media(max-width:900px){.meta,.scores,.split{grid-template-columns:1fr}.shell{padding:16px}}
</style></head><body><div class="shell">
<div class="top"><div><h1>Arches Cyber Diagnostic Report</h1><span class="muted">Offline report</span></div><div class="tabs"><button id="clientTab" class="active" onclick="switchView('client')">Client Summary</button><button id="techTab" onclick="switchView('technical')">Technical Details</button></div></div>
<div class="meta"><div><strong>Computer</strong><br>$safeComputerName</div><div><strong>Scan</strong><br>$(ConvertTo-ArchesHtml $ScanType)</div><div><strong>Version</strong><br>$(ConvertTo-ArchesHtml $ScriptVersion)</div><div><strong>Administrator</strong><br>$Elevated</div><div><strong>Generated</strong><br>$(ConvertTo-ArchesHtml (Get-Date))</div></div>
<section id="client" class="view active"><div class="card"><h2>Health scorecard</h2><div class="scores">$($scoreCards -join "`n")</div></div>
<div class="split"><div class="card"><h2>$($confirmed.Count) confirmed findings</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Status</th><th>Impact</th><th>Action</th></tr></thead><tbody>$($clientRows -join "`n")</tbody></table></div><div><div class="card"><h2>Changes made today</h2><p>$(if (@($changeHistory | Where-Object { ([datetime]$_.CreatedAt).Date -eq (Get-Date).Date }).Count) { 'See the verified entries in Technical Details.' } else { 'No configuration changes were recorded today. This diagnostic scan was read-only.' })</p></div><div class="card"><strong>Unknown checks:</strong> $($unknown.Count)<br><strong>Diagnostic errors:</strong> $($errors.Count)</div></div></div>
<div class="card"><h2>Uncertain and incomplete checks</h2><p>Unknown and Error results are not counted as confirmed problems. Open Technical Details to see each affected check and its safe error category.</p></div></section>
<section id="technical" class="view"><div class="card"><h2>Inventory overview</h2><div class="scores">$($inventoryCards -join "`n")</div><p class="muted">Open the evidence rows below for IP configuration, observed IPv4/MAC neighbors, enabled firewall-rule details, and account totals.</p></div><div class="card"><div class="split"><div><h2>Technical results</h2><p class="sensitive">Sensitive technical report — authorized technicians only.</p></div><div><input id="search" oninput="filterRows()" placeholder="Search checks, categories, IDs..."></div></div><table id="technicalTable"><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Check</th><th>Status</th><th>Approved evidence</th><th>Recommendation</th></tr></thead><tbody>$($technicalRows -join "`n")</tbody></table></div>
<div class="card"><h2>Change and rollback history</h2><div class="notice">Records are validated before display. Invalid or modified records are marked untrusted and never dispatched.</div><table><thead><tr><th>Time</th><th>Remediation</th><th>Exact changes</th><th>Status</th><th>Protection</th><th>Undo available</th></tr></thead><tbody>$($historyRows -join "`n")</tbody></table></div>
<div class="card"><h2>Machine-readable exports</h2><p>JSON and CSV are stored beside this HTML report for authorized import and troubleshooting.</p></div></section>
</div><script>
function switchView(name){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));document.getElementById(name).classList.add('active');document.getElementById(name==='client'?'clientTab':'techTab').classList.add('active')}
function filterRows(){const q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('#technicalTable tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}
function showFixNotice(){alert('Open Start-ArchesGuidedFixes.ps1 from the trusted Arches Cyber folder to build and approve an exact remediation plan. This offline report cannot execute commands.')}
</script></body></html>
"@
    Set-Content -LiteralPath $html -Value $document -Encoding UTF8
    [PSCustomObject]@{
        Html = $html
        Json = $json
        Csv = $csv
        Directory = $runDirectory
        ProblemCount = $confirmed.Count
        ConfirmedFindingCount = $confirmed.Count
        UnknownCount = $unknown.Count
        ErrorCount = $errors.Count
        Scorecard = $scorecard
    }
}

Export-ModuleMember -Function Export-ArchesReport, Get-ArchesReportChangeHistory
