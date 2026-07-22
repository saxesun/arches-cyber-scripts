Set-StrictMode -Version 2.0

if (-not (Get-Command ConvertTo-ArchesSafeEvidence -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'Privacy.psm1') -ErrorAction Stop
}

function ConvertTo-ArchesHtml {
    param([object]$Value)
    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ArchesFriendlyLabel {
    param([Parameter(Mandatory)][string]$Name)
    (($Name -replace '_', ' ') -creplace '([a-z0-9])([A-Z])', '$1 $2').Trim()
}

function ConvertTo-ArchesDisplayValue {
    param([object]$Value)
    if ($null -eq $Value) { return 'Not reported' }
    if ($Value -is [bool]) {
        if ($Value) { return 'True' }
        return 'False'
    }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss zzz') }
    if ($Value -is [DateTimeOffset]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss zzz') }
    [string]$Value
}

function Get-ArchesEvidenceField {
    param(
        [object]$Result,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Result -or $null -eq $Result.Evidence -or
        $Name -notin @($Result.Evidence.PSObject.Properties.Name)) {
        return $null
    }
    $Result.Evidence.$Name
}

function ConvertTo-ArchesEvidenceHtml {
    param([object]$Evidence)
    if ($null -eq $Evidence) {
        return '<span class="muted">No approved evidence was exported for this check.</span>'
    }
    $properties = @($Evidence.PSObject.Properties)
    if (-not $properties.Count) {
        return '<code>{0}</code>' -f (ConvertTo-ArchesHtml (ConvertTo-ArchesDisplayValue $Evidence))
    }
    $rows = foreach ($property in $properties) {
        $label = ConvertTo-ArchesHtml (ConvertTo-ArchesFriendlyLabel $property.Name)
        $value = $property.Value
        if ($value -is [array]) {
            $items = @($value)
            if (-not $items.Count) {
                $display = '<span class="muted">None</span>'
            }
            else {
                $listItems = @($items | ForEach-Object {
                    '<li><code>{0}</code></li>' -f (ConvertTo-ArchesHtml (ConvertTo-ArchesDisplayValue $_))
                })
                $display = '<ul class="evidence-list">{0}</ul>' -f ($listItems -join '')
            }
        }
        else {
            $display = '<code>{0}</code>' -f (ConvertTo-ArchesHtml (ConvertTo-ArchesDisplayValue $value))
        }
        '<dt>{0}</dt><dd>{1}</dd>' -f $label, $display
    }
    '<dl class="evidence-grid">{0}</dl>' -f ($rows -join '')
}

function Get-ArchesSafeBusinessImpact {
    param([Parameter(Mandatory)][object]$Result)
    $propertyNames = @($Result.PSObject.Properties.Name)
    if ('BusinessImpact' -in $propertyNames -and
        -not [string]::IsNullOrWhiteSpace([string]$Result.BusinessImpact)) {
        return [string]$Result.BusinessImpact
    }
    if (Get-Command Get-ArchesBusinessImpact -ErrorAction SilentlyContinue) {
        return Get-ArchesBusinessImpact -Id $Result.Id -Status $Result.Status -Category $Result.Category
    }
    'The business impact was not provided for this result.'
}

function ConvertTo-ArchesTimestampDisplay {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return 'Not recorded' }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
    }
    [string]$Value
}

function Test-ArchesTimestampIsToday {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $false }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Value, [ref]$parsed)) { return $false }
    $parsed.ToLocalTime().Date -eq (Get-Date).Date
}

function ConvertTo-ArchesChangeSetting {
    param([Parameter(Mandatory)][object]$Change)
    if ($Change.TargetType -eq 'FirewallProfile') {
        return '{0} firewall profile - {1}' -f $Change.Target, $Change.Property
    }
    '{0} - {1} - {2}' -f $Change.TargetType, $Change.Target, $Change.Property
}

function ConvertTo-ArchesChangeState {
    param([object]$Value)
    if ($Value -is [bool]) {
        if ($Value) { return 'On' }
        return 'Off'
    }
    ConvertTo-ArchesDisplayValue $Value
}

function Get-ArchesReportChangeEvents {
    param([object[]]$History)
    $events = @()
    foreach ($entry in @($History | Where-Object Trusted)) {
        if ($entry.AppliedAt) {
            foreach ($change in @($entry.Changes)) {
                $events += [PSCustomObject][ordered]@{
                    Timestamp = $entry.AppliedAt
                    Operation = 'Applied'
                    RemediationId = $entry.RemediationId
                    RecordId = $entry.RecordId
                    Setting = ConvertTo-ArchesChangeSetting $change
                    Before = ConvertTo-ArchesChangeState $change.Before
                    After = ConvertTo-ArchesChangeState $change.After
                    Outcome = 'Verified'
                    Verification = if ($entry.Status -eq 'Applied') {
                        $entry.VerificationDetails
                    }
                    else {
                        'Application was validated before the later rollback lifecycle event.'
                    }
                }
            }
        }
        if ($entry.RolledBackAt) {
            foreach ($change in @($entry.Changes)) {
                $events += [PSCustomObject][ordered]@{
                    Timestamp = $entry.RolledBackAt
                    Operation = if ($entry.Status -eq 'RolledBack') { 'Rolled back' } else { 'Rollback failed' }
                    RemediationId = $entry.RemediationId
                    RecordId = $entry.RecordId
                    Setting = ConvertTo-ArchesChangeSetting $change
                    Before = ConvertTo-ArchesChangeState $change.After
                    After = if ($entry.Status -eq 'RolledBack') {
                        ConvertTo-ArchesChangeState $change.Before
                    }
                    else {
                        'State not verified'
                    }
                    Outcome = if ($entry.Status -eq 'RolledBack') { 'Verified' } else { 'Failed' }
                    Verification = if ($entry.Status -eq 'RolledBack') {
                        $entry.VerificationDetails
                    }
                    else {
                        $entry.VerificationError
                    }
                }
            }
        }
    }
    @($events | Sort-Object @{ Expression = { [DateTimeOffset]$_.Timestamp }; Descending = $true })
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
            $recordFile = $_
            try {
                $record = Get-ArchesRollbackRecord -Path $recordFile.FullName
                $history += [PSCustomObject][ordered]@{
                    RecordId = $record.RecordId
                    RemediationId = $record.RemediationId
                    CreatedAt = $record.CreatedAt
                    AppliedAt = $record.AppliedAt
                    RolledBackAt = $record.RolledBackAt
                    Status = $record.Status
                    ProtectionTier = $record.ProtectionTier
                    Changes = @($record.Changes)
                    VerificationSucceeded = if ($null -ne $record.Verification) { $record.Verification.Succeeded } else { $null }
                    VerificationCheckedAt = if ($null -ne $record.Verification) { $record.Verification.CheckedAt } else { $null }
                    VerificationDetails = if ($null -ne $record.Verification) { $record.Verification.Details } else { $null }
                    VerificationError = if ($null -ne $record.Verification) { $record.Verification.Error } else { $null }
                    RollbackAvailable = $record.Status -eq 'Applied'
                    Trusted = $true
                    LatestActivityAt = if ($record.RolledBackAt) { $record.RolledBackAt } elseif ($record.AppliedAt) { $record.AppliedAt } else { $record.CreatedAt }
                }
            }
            catch {
                $history += [PSCustomObject][ordered]@{
                    RecordId = $recordFile.BaseName
                    RemediationId = 'UntrustedRecord'
                    CreatedAt = $recordFile.LastWriteTime.ToString('o')
                    AppliedAt = $null
                    RolledBackAt = $null
                    Status = 'Invalid'
                    ProtectionTier = 'Unknown'
                    Changes = @()
                    VerificationSucceeded = $false
                    VerificationCheckedAt = $null
                    VerificationDetails = $null
                    VerificationError = 'The record failed integrity or schema validation and was not trusted.'
                    RollbackAvailable = $false
                    Trusted = $false
                    LatestActivityAt = $recordFile.LastWriteTime.ToString('o')
                }
            }
        }
    @($history | Sort-Object @{ Expression = { [DateTimeOffset]$_.LatestActivityAt }; Descending = $true })
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
            BusinessImpact = Get-ArchesSafeBusinessImpact -Result $_
            Evidence = ConvertTo-ArchesSafeEvidence -Id $_.Id -Evidence $_.Evidence -DiagnosticError:($_.Status -eq 'Error')
            Recommendation = $_.Recommendation
            RemediationAvailable = -not [string]::IsNullOrWhiteSpace([string]$_.RemediationId)
            RemediationId = $_.RemediationId
            RequiresAdmin = $_.RequiresAdmin
            CheckedAt = $_.CheckedAt
        }
    })
    $confirmed = @($safeResults | Where-Object Classification -eq 'ConfirmedFinding')
    $unknown = @($safeResults | Where-Object Classification -eq 'Unknown')
    $errors = @($safeResults | Where-Object Classification -eq 'Error')
    $changeHistory = @(Get-ArchesReportChangeHistory -RollbackDirectory $RollbackDirectory)
    $changeEvents = @(Get-ArchesReportChangeEvents -History $changeHistory)
    $todayChangeEvents = @($changeEvents | Where-Object { Test-ArchesTimestampIsToday $_.Timestamp })
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
            TodayChangeEventCount = $todayChangeEvents.Count
        }
        Results = $safeResults
        ChangeHistory = $changeHistory
    }
    $jsonDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $json -Encoding UTF8
    $safeResults | Select-Object Id,Category,Title,Status,Classification,Severity,Summary,BusinessImpact,Recommendation,RemediationAvailable,RemediationId,RequiresAdmin,CheckedAt |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $scorecard = @(Get-ArchesScorecard -Results $Results)
    $scoreCards = foreach ($score in $scorecard) {
        '<div class="score"><span>{0}</span><strong>{1}</strong><span>{2} - {3} finding(s)</span></div>' -f `
            (ConvertTo-ArchesHtml $score.Category), $score.Score,
            (ConvertTo-ArchesHtml $score.Rating), $score.ProblemCount
    }
    $clientRows = foreach ($result in $confirmed) {
        $action = if ($result.RemediationAvailable) {
            '<button class="fix" onclick="showFixNotice()">Review guided fix</button>'
        }
        else {
            '<span class="muted">Technician review</span>'
        }
        $recommendation = if ([string]::IsNullOrWhiteSpace([string]$result.Recommendation)) {
            'No additional action is currently recommended.'
        }
        else { $result.Recommendation }
        '<tr class="{0}"><td><span class="pill">{1}</span></td><td><strong>{2}</strong><br><span class="muted">{3}</span></td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f `
            $result.Status.ToLowerInvariant(), (ConvertTo-ArchesHtml $result.Severity),
            (ConvertTo-ArchesHtml $result.Title), (ConvertTo-ArchesHtml $result.Category),
            (ConvertTo-ArchesHtml $result.Summary), (ConvertTo-ArchesHtml $result.BusinessImpact),
            (ConvertTo-ArchesHtml $recommendation), $action
    }
    $technicalRows = foreach ($result in $safeResults) {
        $evidenceHtml = ConvertTo-ArchesEvidenceHtml $result.Evidence
        $evidenceCount = if ($null -eq $result.Evidence) { 0 } else { @($result.Evidence.PSObject.Properties).Count }
        $recommendation = if ([string]::IsNullOrWhiteSpace([string]$result.Recommendation)) { 'None' } else { $result.Recommendation }
        '<tr class="{0}" data-status="{0}" data-category="{1}"><td><code>{2}</code></td><td><span class="pill">{3}</span><br>{4}</td><td>{5}</td><td><strong>{6}</strong></td><td><strong>Meaning:</strong> {7}<br><br><strong>Business impact:</strong> {8}</td><td><details><summary>Approved evidence ({9} field(s))</summary>{10}</details></td><td>{11}</td></tr>' -f `
            $result.Status.ToLowerInvariant(), (ConvertTo-ArchesHtml $result.Category),
            (ConvertTo-ArchesHtml $result.Id), (ConvertTo-ArchesHtml $result.Severity),
            (ConvertTo-ArchesHtml $result.Status), (ConvertTo-ArchesHtml $result.Category),
            (ConvertTo-ArchesHtml $result.Title), (ConvertTo-ArchesHtml $result.Summary),
            (ConvertTo-ArchesHtml $result.BusinessImpact), $evidenceCount, $evidenceHtml,
            (ConvertTo-ArchesHtml $recommendation)
    }
    $todayChangeRows = foreach ($event in $todayChangeEvents) {
        $outcomeClass = if ($event.Outcome -eq 'Verified') { 'verified' } else { 'failed' }
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><code>{3}</code></td><td><code>{4}</code></td><td><span class="pill {5}">{6}</span><br><span class="muted">{7}</span></td></tr>' -f `
            (ConvertTo-ArchesHtml (ConvertTo-ArchesTimestampDisplay $event.Timestamp)),
            (ConvertTo-ArchesHtml $event.Operation), (ConvertTo-ArchesHtml $event.Setting),
            (ConvertTo-ArchesHtml $event.Before), (ConvertTo-ArchesHtml $event.After),
            $outcomeClass, (ConvertTo-ArchesHtml $event.Outcome),
            (ConvertTo-ArchesHtml $event.Verification)
    }
    $todayChangesContent = if ($todayChangeEvents.Count) {
        '<p>{0} validated change event(s) were recorded today.</p><div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Setting</th><th>Before</th><th>After</th><th>Verification</th></tr></thead><tbody>{1}</tbody></table></div>' -f `
            $todayChangeEvents.Count, ($todayChangeRows -join "`n")
    }
    else {
        '<p>No configuration changes were recorded today. This diagnostic scan was read-only.</p>'
    }
    $historyCards = foreach ($entry in $changeHistory) {
        $changeRows = if (@($entry.Changes).Count) {
            @($entry.Changes | ForEach-Object {
                '<tr><td>{0}</td><td><code>{1}</code></td><td><code>{2}</code></td></tr>' -f `
                    (ConvertTo-ArchesHtml (ConvertTo-ArchesChangeSetting $_)),
                    (ConvertTo-ArchesHtml (ConvertTo-ArchesChangeState $_.Before)),
                    (ConvertTo-ArchesHtml (ConvertTo-ArchesChangeState $_.After))
            }) -join "`n"
        }
        else {
            '<tr><td colspan="3" class="muted">No trusted change details are available.</td></tr>'
        }
        $verification = if (-not $entry.Trusted) {
            '<span class="pill failed">Untrusted</span> The record failed validation and no contents were trusted.'
        }
        elseif ($null -eq $entry.VerificationSucceeded) {
            '<span class="pill">Not performed</span> No apply or rollback verification is recorded.'
        }
        elseif ($entry.VerificationSucceeded) {
            '<span class="pill verified">Succeeded</span> {0}' -f (ConvertTo-ArchesHtml $entry.VerificationDetails)
        }
        else {
            '<span class="pill failed">Failed</span> {0}' -f (ConvertTo-ArchesHtml $entry.VerificationError)
        }
        '<article class="history-card"><div class="history-head"><div><h3>{0}</h3><code>{1}</code></div><div><span class="pill status-{2}">{3}</span></div></div><div class="timeline"><div><strong>Created</strong><br>{4}</div><div><strong>Applied</strong><br>{5}</div><div><strong>Rolled back / attempted</strong><br>{6}</div><div><strong>Protection</strong><br>{7}</div><div><strong>Undo available</strong><br>{8}</div></div><h4>Exact recorded changes</h4><div class="table-wrap"><table><thead><tr><th>Setting</th><th>Before</th><th>After</th></tr></thead><tbody>{9}</tbody></table></div><p><strong>Final verification:</strong> {10}</p><p class="muted">Verification checked: {11}</p></article>' -f `
            (ConvertTo-ArchesHtml $entry.RemediationId), (ConvertTo-ArchesHtml $entry.RecordId),
            ([string]$entry.Status).ToLowerInvariant(), (ConvertTo-ArchesHtml $entry.Status),
            (ConvertTo-ArchesHtml (ConvertTo-ArchesTimestampDisplay $entry.CreatedAt)),
            (ConvertTo-ArchesHtml (ConvertTo-ArchesTimestampDisplay $entry.AppliedAt)),
            (ConvertTo-ArchesHtml (ConvertTo-ArchesTimestampDisplay $entry.RolledBackAt)),
            (ConvertTo-ArchesHtml $entry.ProtectionTier),
            $(if ($entry.RollbackAvailable) { 'Yes' } else { 'No' }),
            $changeRows, $verification,
            (ConvertTo-ArchesHtml (ConvertTo-ArchesTimestampDisplay $entry.VerificationCheckedAt))
    }
    $historyContent = if ($changeHistory.Count) {
        $historyCards -join "`n"
    }
    else {
        '<p class="muted">No retained rollback or change records were found.</p>'
    }
    $antivirusProtection = $safeResults | Where-Object Id -eq 'SEC-AV-001' | Select-Object -First 1
    $malwareStatus = $safeResults | Where-Object Id -eq 'SEC-MAL-STATUS-001' | Select-Object -First 1
    $malwareThreat = $safeResults | Where-Object Id -eq 'SEC-MAL-THREAT-001' | Select-Object -First 1
    $malwareOverviewRows = @(
        [PSCustomObject]@{
            Label = 'Active protection'
            Result = $antivirusProtection
            Detail = if ($null -ne $antivirusProtection) { $antivirusProtection.Summary } else { 'Not included in this scan.' }
        }
        [PSCustomObject]@{
            Label = 'Security intelligence'
            Result = $malwareStatus
            Detail = if ($null -ne $malwareStatus -and $null -ne $malwareStatus.Evidence) {
                'Age: {0} day(s); updated: {1}' -f `
                    (ConvertTo-ArchesDisplayValue (Get-ArchesEvidenceField $malwareStatus 'SignatureAgeDays')),
                    (ConvertTo-ArchesTimestampDisplay (Get-ArchesEvidenceField $malwareStatus 'SignatureLastUpdated'))
            }
            else { 'Not included or unavailable.' }
        }
        [PSCustomObject]@{
            Label = 'Last completed scan'
            Result = $malwareStatus
            Detail = if ($null -ne $malwareStatus -and $null -ne $malwareStatus.Evidence) {
                '{0} - {1}' -f `
                    (ConvertTo-ArchesDisplayValue (Get-ArchesEvidenceField $malwareStatus 'LastScanType')),
                    (ConvertTo-ArchesTimestampDisplay (Get-ArchesEvidenceField $malwareStatus 'LastScanEndTime'))
            }
            else { 'Not included or unavailable.' }
        }
        [PSCustomObject]@{
            Label = 'Threat records'
            Result = $malwareThreat
            Detail = if ($null -ne $malwareThreat -and $null -ne $malwareThreat.Evidence) {
                'Detected: {0}; quarantined: {1}; unresolved: {2}' -f `
                    (ConvertTo-ArchesDisplayValue (Get-ArchesEvidenceField $malwareThreat 'DetectedThreatCount')),
                    (ConvertTo-ArchesDisplayValue (Get-ArchesEvidenceField $malwareThreat 'QuarantinedThreatCount')),
                    (ConvertTo-ArchesDisplayValue (Get-ArchesEvidenceField $malwareThreat 'UnresolvedThreatCount'))
            }
            else { 'Not included or unavailable.' }
        }
    ) | ForEach-Object {
        $status = if ($null -ne $_.Result) { [string]$_.Result.Status } else { 'Not Scanned' }
        '<div class="malware-item {0}"><span>{1}</span><strong>{2}</strong><small>{3}</small></div>' -f `
            ($status.ToLowerInvariant() -replace ' ', '-'), (ConvertTo-ArchesHtml $_.Label),
            (ConvertTo-ArchesHtml $status), (ConvertTo-ArchesHtml $_.Detail)
    }
    $malwareOverviewContent = '<div class="malware-grid">{0}</div><p class="muted">Threat reporting is count-only: file paths, usernames, process paths, and raw Defender records are not exported.</p><button class="fix" onclick="showMalwareScanNotice()">Run an approved Defender scan</button>' -f `
        ($malwareOverviewRows -join "`n")
    $networkInventory = $safeResults | Where-Object Id -eq 'NET-IF-001' | Select-Object -First 1
    $neighborInventory = $safeResults | Where-Object Id -eq 'DEV-ARP-001' | Select-Object -First 1
    $firewallInventory = $safeResults | Where-Object Id -eq 'SEC-FW-RULES-001' | Select-Object -First 1
    $administratorInventory = $safeResults | Where-Object Id -eq 'SEC-ADM-001' | Select-Object -First 1
    $userInventory = $safeResults | Where-Object Id -eq 'SEC-USERS-001' | Select-Object -First 1
    $inventoryCards = @(
        [PSCustomObject]@{ Label='Active interfaces'; Value=if($null -ne $networkInventory -and $null -ne $networkInventory.Evidence){$networkInventory.Evidence.InterfaceCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Observed neighbors'; Value=if($null -ne $neighborInventory -and $null -ne $neighborInventory.Evidence){$neighborInventory.Evidence.NeighborCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Firewall rules'; Value=if($null -ne $firewallInventory -and $null -ne $firewallInventory.Evidence){$firewallInventory.Evidence.RuleCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Administrator principals'; Value=if($null -ne $administratorInventory -and $null -ne $administratorInventory.Evidence){$administratorInventory.Evidence.PrincipalCount}else{'Unavailable'} }
        [PSCustomObject]@{ Label='Local user accounts'; Value=if($null -ne $userInventory -and $null -ne $userInventory.Evidence){$userInventory.Evidence.LocalUserCount}else{'Unavailable'} }
    ) | ForEach-Object {
        '<div class="score"><span>{0}</span><strong>{1}</strong></div>' -f `
            (ConvertTo-ArchesHtml $_.Label), (ConvertTo-ArchesHtml $_.Value)
    }
    $safeComputerName = [Net.WebUtility]::HtmlEncode([string]$ComputerName)
    $document = @"
<!doctype html><html><head><meta charset="utf-8"><title>Arches Cyber Report</title>
<style>
:root{--navy:#0b2f64;--blue:#1769d2;--line:#d8e0ea;--soft:#f3f7fb;--green:#17783d;--amber:#a45a00;--red:#b42318}*{box-sizing:border-box}body{font-family:Segoe UI,Arial;margin:0;color:#172033;background:#fff}.shell{max-width:1500px;margin:auto;padding:26px 34px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:16px}.tabs button{padding:12px 28px;border:1px solid var(--line);background:#fff;color:var(--navy);font-weight:650;cursor:pointer}.tabs button.active{background:var(--navy);color:#fff}.view{display:none}.view.active{display:block}.meta,.card{border:1px solid var(--line);border-radius:10px;padding:18px;margin-top:18px}.meta{background:var(--soft);display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.scores{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.score{text-align:center;border:1px solid var(--line);border-radius:8px;padding:14px}.score strong{display:block;font-size:28px;color:var(--green)}.malware-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.malware-item{border:1px solid var(--line);border-radius:8px;padding:13px}.malware-item span,.malware-item small{display:block}.malware-item strong{display:block;font-size:18px;margin:5px 0}.malware-item.pass{border-left:5px solid var(--green)}.malware-item.warning{border-left:5px solid var(--amber)}.malware-item.fail{border-left:5px solid var(--red)}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin-top:10px}th,td{padding:10px;border:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--soft)}tr.pass{background:#edf9f1}tr.warning{background:#fff8df}tr.fail{background:#fff0f0}tr.unknown,tr.error{background:#f4f1ff}.fix{background:var(--blue);color:#fff;border:0;border-radius:6px;padding:8px 12px;cursor:pointer}.muted{color:#5b6675}.pill{display:inline-block;border-radius:999px;padding:4px 9px;background:var(--soft)}.pill.verified,.status-applied,.status-rolledback{background:#dff4e7;color:var(--green)}.pill.failed,.status-invalid,.status-rollbackfailed{background:#ffe4e2;color:var(--red)}.split{display:grid;grid-template-columns:2fr 1fr;gap:18px}.notice{padding:14px;border-left:5px solid var(--blue);background:#eef5ff}.warning-note{border-left-color:var(--amber);background:#fff8e5}code{white-space:pre-wrap;word-break:break-word}details summary{cursor:pointer;color:var(--navy);font-weight:650}.evidence-grid{display:grid;grid-template-columns:minmax(135px,1fr) 3fr;margin:12px 0 0;border-top:1px solid var(--line);border-left:1px solid var(--line)}.evidence-grid dt,.evidence-grid dd{margin:0;padding:8px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.evidence-grid dt{font-weight:650;background:var(--soft)}.evidence-list{margin:0;padding-left:20px;max-height:340px;overflow:auto}.evidence-list li{margin-bottom:6px}.history-card{border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:16px}.history-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}.history-head h3{margin:0 0 6px}.timeline{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;background:var(--soft);padding:12px;border-radius:7px;margin-top:14px}.timeline>div{min-width:0}input{padding:10px;width:330px;border:1px solid var(--line);border-radius:6px}.sensitive{color:var(--red);font-weight:700}@media(max-width:900px){.meta,.scores,.split,.timeline,.malware-grid{grid-template-columns:1fr}.top,.history-head{display:block}.tabs{margin-top:12px}.shell{padding:16px}.evidence-grid{grid-template-columns:1fr}input{width:100%}}
</style></head><body><div class="shell">
<div class="top"><div><h1>Arches Cyber Diagnostic Report</h1><span class="muted">Offline report</span></div><div class="tabs"><button id="clientTab" class="active" onclick="switchView('client')">Client Summary</button><button id="techTab" onclick="switchView('technical')">Technical Details</button></div></div>
<div class="meta"><div><strong>Computer</strong><br>$safeComputerName</div><div><strong>Scan</strong><br>$(ConvertTo-ArchesHtml $ScanType)</div><div><strong>Version</strong><br>$(ConvertTo-ArchesHtml $ScriptVersion)</div><div><strong>Administrator</strong><br>$Elevated</div><div><strong>Generated</strong><br>$(ConvertTo-ArchesHtml (Get-Date))</div></div>
<section id="client" class="view active"><div class="card"><h2>Health scorecard</h2><div class="scores">$($scoreCards -join "`n")</div></div>
<div class="card"><h2>Malware protection</h2>$malwareOverviewContent</div>
<div class="card"><h2>$($confirmed.Count) confirmed findings</h2><p class="muted">Each finding separates what was observed from why it matters and what should happen next.</p><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>What this means</th><th>Why it matters</th><th>Recommended action</th><th>Next step</th></tr></thead><tbody>$($clientRows -join "`n")</tbody></table></div></div>
<div class="card"><h2>Changes made today</h2>$todayChangesContent</div>
<div class="card"><h2>Uncertain and incomplete checks</h2><p><strong>Unknown checks:</strong> $($unknown.Count) &nbsp; <strong>Diagnostic errors:</strong> $($errors.Count)</p><p>Unknown and Error results are not counted as confirmed problems. Open Technical Details to see each affected check and its safe error category.</p></div></section>
<section id="technical" class="view"><div class="card"><h2>Inventory overview</h2><div class="scores">$($inventoryCards -join "`n")</div><p class="muted">Expand the approved evidence for readable IP configuration, observed IPv4/MAC neighbors, enabled firewall-rule details, and account totals.</p></div><div class="card"><h2>Malware diagnostics</h2>$malwareOverviewContent<p>Complete approved Defender evidence is retained in the technical result rows below.</p></div><div class="card"><div class="split"><div><h2>Technical results</h2><p class="sensitive">Sensitive technical report - authorized technicians only.</p></div><div><input id="search" oninput="filterRows()" placeholder="Search checks, categories, IDs..."></div></div><div class="table-wrap"><table id="technicalTable"><thead><tr><th>ID</th><th>Severity / status</th><th>Category</th><th>Check</th><th>Meaning and impact</th><th>Approved evidence</th><th>Recommendation</th></tr></thead><tbody>$($technicalRows -join "`n")</tbody></table></div></div>
<div class="card"><h2>Complete validated change and rollback history</h2><div class="notice">Every trusted record passed schema, computer, and integrity validation before display. Invalid or modified records are labeled untrusted and never dispatched.</div>$historyContent</div>
<div class="card"><h2>Machine-readable exports</h2><p>JSON and CSV are stored beside this HTML report for authorized import and troubleshooting.</p></div></section>
</div><script>
function switchView(name){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));document.getElementById(name).classList.add('active');document.getElementById(name==='client'?'clientTab':'techTab').classList.add('active')}
function filterRows(){const q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('#technicalTable tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}
function showFixNotice(){alert('Open Start-ArchesGuidedFixes.ps1 from the trusted Arches Cyber folder to build and approve an exact remediation plan. This offline report cannot execute commands.')}
function showMalwareScanNotice(){alert('Run Run-ArchesMalwareScan.bat from the trusted Arches Cyber folder. The Malware Scan Center requires a fresh confirmation before every quick or full Defender scan. This offline report cannot execute commands.')}
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
        TodayChangeEventCount = $todayChangeEvents.Count
        Scorecard = $scorecard
    }
}

Export-ModuleMember -Function Export-ArchesReport, Get-ArchesReportChangeHistory, Get-ArchesReportChangeEvents
