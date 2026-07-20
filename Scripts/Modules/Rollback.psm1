Set-StrictMode -Version 2.0

function Get-ArchesComputerName {
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return $env:COMPUTERNAME
    }
    [Environment]::MachineName
}

function Assert-ArchesExactProperties {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Location
    )
    $actual = @($InputObject.PSObject.Properties.Name)
    $missing = @($Expected | Where-Object { $_ -notin $actual })
    $unknown = @($actual | Where-Object { $_ -notin $Expected })
    if ($missing.Count) {
        throw "Invalid rollback record: $Location is missing field(s): $($missing -join ', ')."
    }
    if ($unknown.Count) {
        throw "Invalid rollback record: $Location contains unknown field(s): $($unknown -join ', ')."
    }
}

function Assert-ArchesTimestamp {
    param(
        [object]$Value,
        [Parameter(Mandatory)][string]$Name,
        [switch]$AllowNull
    )
    if ($null -eq $Value) {
        if ($AllowNull) { return }
        throw "Invalid rollback record: '$Name' cannot be null."
    }
    if ($Value -is [datetime] -or $Value -is [DateTimeOffset]) {
        return
    }
    if ($Value -isnot [string]) {
        throw "Invalid rollback record: '$Name' must be an ISO 8601 string."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Value, [ref]$parsed)) {
        throw "Invalid rollback record: '$Name' must be an ISO 8601 timestamp."
    }
}

function Assert-ArchesVerification {
    param([object]$Verification)
    if ($null -eq $Verification) { return }
    Assert-ArchesExactProperties -InputObject $Verification `
        -Expected @('Succeeded', 'CheckedAt', 'Details', 'Error') -Location 'Verification'
    if ($Verification.Succeeded -isnot [bool]) {
        throw "Invalid rollback record: 'Verification.Succeeded' must be true or false."
    }
    Assert-ArchesTimestamp -Value $Verification.CheckedAt -Name 'Verification.CheckedAt'
    foreach ($name in @('Details', 'Error')) {
        $value = $Verification.$name
        if ($null -ne $value -and $value -isnot [string]) {
            throw "Invalid rollback record: 'Verification.$name' must be a string or null."
        }
    }
}

function Test-ArchesRollbackRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [switch]$SkipComputerCheck
    )

    Assert-ArchesExactProperties -InputObject $Record -Expected @(
        'SchemaVersion', 'RecordId', 'RemediationId', 'ProtectionTier',
        'ComputerName', 'CreatedAt', 'Status', 'Changes', 'AppliedAt',
        'RolledBackAt', 'Verification'
    ) -Location 'root'

    if ($Record.SchemaVersion -notin @([int]2, [long]2)) {
        throw "Invalid rollback record: unsupported SchemaVersion '$($Record.SchemaVersion)'."
    }
    $recordGuid = [guid]::Empty
    if ($Record.RecordId -isnot [string] -or -not [guid]::TryParse($Record.RecordId, [ref]$recordGuid)) {
        throw "Invalid rollback record: 'RecordId' must be a GUID string."
    }
    if ($Record.RemediationId -ne 'FIX-FW-001') {
        throw "Invalid rollback record: unknown RemediationId '$($Record.RemediationId)'."
    }
    if ($Record.ProtectionTier -ne 'ConfigOnly') {
        throw "Invalid rollback record: FIX-FW-001 requires ProtectionTier 'ConfigOnly'."
    }
    if ($Record.ComputerName -isnot [string] -or [string]::IsNullOrWhiteSpace($Record.ComputerName)) {
        throw "Invalid rollback record: 'ComputerName' must be a non-empty string."
    }
    if (-not $SkipComputerCheck -and $Record.ComputerName -ine (Get-ArchesComputerName)) {
        throw "Rollback record belongs to computer '$($Record.ComputerName)', not the current computer '$(Get-ArchesComputerName)'."
    }
    Assert-ArchesTimestamp -Value $Record.CreatedAt -Name 'CreatedAt'
    if ($Record.Status -notin @('Pending', 'Applied', 'RolledBack', 'RollbackFailed')) {
        throw "Invalid rollback record: unknown Status '$($Record.Status)'."
    }

    $changes = @($Record.Changes)
    if (-not $changes.Count) {
        throw "Invalid rollback record: 'Changes' must contain at least one change."
    }
    foreach ($change in $changes) {
        Assert-ArchesExactProperties -InputObject $change `
            -Expected @('TargetType', 'Target', 'Property', 'Before', 'After') -Location 'Changes[]'
        if ($change.TargetType -ne 'FirewallProfile') {
            throw "Invalid rollback record: unknown TargetType '$($change.TargetType)'."
        }
        if ($change.Target -notin @('Domain', 'Private', 'Public')) {
            throw "Invalid rollback record: unknown firewall profile '$($change.Target)'."
        }
        if ($change.Property -ne 'Enabled') {
            throw "Invalid rollback record: unsupported FirewallProfile property '$($change.Property)'."
        }
        if ($change.Before -isnot [bool] -or $change.After -isnot [bool]) {
            throw "Invalid rollback record: firewall Enabled values must be true or false."
        }
        if ($change.Before -eq $change.After) {
            throw "Invalid rollback record: Before and After must describe an actual change."
        }
    }

    Assert-ArchesTimestamp -Value $Record.AppliedAt -Name 'AppliedAt' -AllowNull
    Assert-ArchesTimestamp -Value $Record.RolledBackAt -Name 'RolledBackAt' -AllowNull
    Assert-ArchesVerification -Verification $Record.Verification

    if ($Record.Status -eq 'Pending' -and $null -ne $Record.AppliedAt) {
        throw "Invalid rollback record: Pending records cannot have AppliedAt."
    }
    if ($Record.Status -eq 'Applied' -and $null -eq $Record.AppliedAt) {
        throw "Invalid rollback record: Applied records require AppliedAt."
    }
    if ($Record.Status -eq 'RolledBack') {
        if ($null -eq $Record.RolledBackAt -or $null -eq $Record.Verification -or -not $Record.Verification.Succeeded) {
            throw "Invalid rollback record: RolledBack records require successful verification and RolledBackAt."
        }
    }
    if ($Record.Status -eq 'RollbackFailed') {
        if ($null -eq $Record.RolledBackAt -or $null -eq $Record.Verification -or $Record.Verification.Succeeded) {
            throw "Invalid rollback record: RollbackFailed records require failed verification and RolledBackAt."
        }
    }
    $true
}

function Save-ArchesRollbackRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Record
    )
    [void](Test-ArchesRollbackRecord -Record $Record)
    $temporaryPath = "$Path.tmp"
    try {
        $Record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ArchesRollbackRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Rollback record not found: $Path"
    }
    try {
        $record = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Rollback record is not valid JSON: $($_.Exception.Message)"
    }
    [void](Test-ArchesRollbackRecord -Record $record)
    $record
}

function New-ArchesRollbackRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidateSet('FIX-FW-001')][string]$RemediationId,
        [Parameter(Mandatory)][ValidateSet('ConfigOnly')][string]$ProtectionTier,
        [Parameter(Mandatory)][object[]]$Changes
    )
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }
    $record = [PSCustomObject][ordered]@{
        SchemaVersion = 2
        RecordId = [guid]::NewGuid().ToString()
        RemediationId = $RemediationId
        ProtectionTier = $ProtectionTier
        ComputerName = Get-ArchesComputerName
        CreatedAt = (Get-Date).ToString('o')
        Status = 'Pending'
        Changes = @($Changes)
        AppliedAt = $null
        RolledBackAt = $null
        Verification = $null
    }
    [void](Test-ArchesRollbackRecord -Record $record)
    $path = Join-Path $Directory ("Rollback_{0}_{1}_{2}.json" -f $RemediationId, (Get-Date -Format 'yyyyMMdd_HHmmss'), $record.RecordId)
    Save-ArchesRollbackRecord -Path $path -Record $record
    $path
}

function Set-ArchesRollbackApplied {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$VerificationDetails = 'The intended state was verified after remediation.'
    )
    $record = Get-ArchesRollbackRecord -Path $Path
    if ($record.Status -ne 'Pending') {
        throw "Rollback record must be Pending before it can be marked Applied; current status is '$($record.Status)'."
    }
    $record.Status = 'Applied'
    $record.AppliedAt = (Get-Date).ToString('o')
    $record.Verification = [PSCustomObject][ordered]@{
        Succeeded = $true
        CheckedAt = (Get-Date).ToString('o')
        Details = $VerificationDetails
        Error = $null
    }
    Save-ArchesRollbackRecord -Path $Path -Record $record
    $record
}

function Restore-ArchesFirewallChanges {
    param([Parameter(Mandatory)][object]$Record)
    foreach ($change in @($Record.Changes)) {
        Set-NetFirewallProfile -Profile $change.Target -Enabled ([bool]$change.Before) -ErrorAction Stop
    }
    foreach ($change in @($Record.Changes)) {
        $profile = Get-NetFirewallProfile -Profile $change.Target -ErrorAction Stop
        if ($null -eq $profile -or [bool]$profile.Enabled -ne [bool]$change.Before) {
            throw "Firewall profile '$($change.Target)' did not return to Enabled=$($change.Before)."
        }
    }
}

function Restore-ArchesRollback {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Approved,
        [switch]$Recovery
    )
    $record = Get-ArchesRollbackRecord -Path $Path
    $allowedStatus = if ($Recovery) { 'Pending' } else { 'Applied' }
    if ($record.Status -ne $allowedStatus) {
        throw "Rollback record status '$($record.Status)' is not appropriate for this operation; expected '$allowedStatus'."
    }
    if (-not $Approved -and -not $WhatIfPreference) {
        throw 'Rollback requires explicit approval. Rerun with -Approved after reviewing every change.'
    }
    if (-not $PSCmdlet.ShouldProcess($record.RecordId, "Restore $($record.RemediationId) settings")) {
        return [PSCustomObject]@{ Path = $Path; RecordId = $record.RecordId; Status = $record.Status; WhatIf = $true }
    }

    try {
        foreach ($change in @($record.Changes)) {
            if ($record.RemediationId -ne 'FIX-FW-001' -or $change.TargetType -ne 'FirewallProfile') {
                throw "No trusted rollback handler exists for '$($record.RemediationId)/$($change.TargetType)'."
            }
        }
        Restore-ArchesFirewallChanges -Record $record
        $record.Status = 'RolledBack'
        $record.RolledBackAt = (Get-Date).ToString('o')
        $record.Verification = [PSCustomObject][ordered]@{
            Succeeded = $true
            CheckedAt = (Get-Date).ToString('o')
            Details = 'Every firewall profile matched its recorded previous Enabled value.'
            Error = $null
        }
        Save-ArchesRollbackRecord -Path $Path -Record $record
        $record
    }
    catch {
        $rollbackError = $_.Exception.Message
        $record.Status = 'RollbackFailed'
        $record.RolledBackAt = (Get-Date).ToString('o')
        $record.Verification = [PSCustomObject][ordered]@{
            Succeeded = $false
            CheckedAt = (Get-Date).ToString('o')
            Details = $null
            Error = $rollbackError
        }
        try {
            Save-ArchesRollbackRecord -Path $Path -Record $record
        }
        catch {
            throw "Rollback failed: $rollbackError. The failure status could not be saved: $($_.Exception.Message)"
        }
        throw "Rollback failed and the record was marked RollbackFailed: $rollbackError"
    }
}

function Remove-ArchesExpiredRollback {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Directory, [ValidateRange(1,3650)][int]$RetentionDays = 30)
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath $Directory -Filter 'Rollback_*.json' -File |
        Where-Object LastWriteTime -lt $cutoff |
        ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete expired rollback record')) {
                Remove-Item -LiteralPath $_.FullName -Force
            }
        }
}

Export-ModuleMember -Function New-ArchesRollbackRecord, Get-ArchesRollbackRecord, `
    Test-ArchesRollbackRecord, Set-ArchesRollbackApplied, Restore-ArchesRollback, `
    Remove-ArchesExpiredRollback
