Set-StrictMode -Version 2.0

function Get-ArchesRollbackIntegrityKeyPath {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'Rollback integrity is unavailable because LOCALAPPDATA is not defined.'
    }
    Join-Path $env:LOCALAPPDATA 'ArchesCyber\rollback-integrity-key.json'
}

function New-ArchesRandomBytes {
    param([Parameter(Mandatory)][ValidateRange(16, 1024)][int]$Count)
    $bytes = New-Object byte[] $Count
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    $bytes
}

function Get-ArchesRollbackIntegrityKey {
    $path = Get-ArchesRollbackIntegrityKeyPath
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $envelope = Get-Content -LiteralPath $path -Raw -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            Assert-ArchesExactProperties -InputObject $envelope `
                -Expected @('SchemaVersion', 'ProtectionScope', 'ProtectedKey') `
                -Location 'integrity key envelope'
            if ($envelope.SchemaVersion -notin @([int]1, [long]1) -or
                $envelope.ProtectionScope -ne 'CurrentUser') {
                throw 'The integrity key envelope has an unsupported schema or protection scope.'
            }
            $protectedKey = [Convert]::FromBase64String([string]$envelope.ProtectedKey)
            $key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $protectedKey,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            if ($key.Length -ne 32) {
                throw 'The unprotected integrity key has an invalid length.'
            }
            return $key
        }
        catch {
            throw "Rollback integrity key could not be loaded safely: $($_.Exception.Message)"
        }
    }

    $mutex = New-Object Threading.Mutex($false, 'Local\ArchesCyberRollbackIntegrityKey')
    $lockTaken = $false
    try {
        $lockTaken = $mutex.WaitOne([TimeSpan]::FromSeconds(10))
        if (-not $lockTaken) {
            throw 'Timed out waiting for exclusive rollback integrity key creation.'
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            return Get-ArchesRollbackIntegrityKey
        }
        $directory = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
        }
        $key = New-ArchesRandomBytes -Count 32
        $temporaryPath = $null
        try {
            $protectedKey = [System.Security.Cryptography.ProtectedData]::Protect(
                $key,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            $envelope = [PSCustomObject][ordered]@{
                SchemaVersion = 1
                ProtectionScope = 'CurrentUser'
                ProtectedKey = [Convert]::ToBase64String($protectedKey)
            }
            $temporaryPath = "$path.$([guid]::NewGuid().ToString('N')).tmp"
            $envelope | ConvertTo-Json | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
            Move-Item -LiteralPath $temporaryPath -Destination $path -Force
        }
        finally {
            if ($null -ne $key) {
                [Array]::Clear($key, 0, $key.Length)
            }
            if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath)) {
                Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        throw "Rollback integrity key could not be created safely: $($_.Exception.Message)"
    }
    finally {
        if ($lockTaken) {
            [void]$mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
    Get-ArchesRollbackIntegrityKey
}

function Get-ArchesRollbackIntegrityKeyId {
    param([Parameter(Mandatory)][byte[]]$Key)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha256.ComputeHash($Key))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-ArchesCanonicalTimestamp {
    param([object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    $parsed = [DateTimeOffset]::MinValue
    if ($Value -is [datetime]) {
        $parsed = [DateTimeOffset]$Value
    }
    elseif ($Value -is [DateTimeOffset]) {
        $parsed = $Value
    }
    elseif (-not [DateTimeOffset]::TryParse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    )) {
        return [string]$Value
    }
    $parsed.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-ArchesRollbackIntegrityPayload {
    param([Parameter(Mandatory)][object]$Record)
    $changes = @($Record.Changes | ForEach-Object {
        [PSCustomObject][ordered]@{
            TargetType = $_.TargetType
            Target = $_.Target
            Property = $_.Property
            Before = $_.Before
            After = $_.After
        }
    })
    $verification = if ($null -eq $Record.Verification) {
        $null
    }
    else {
        [PSCustomObject][ordered]@{
            Succeeded = $Record.Verification.Succeeded
            CheckedAt = ConvertTo-ArchesCanonicalTimestamp $Record.Verification.CheckedAt
            Details = $Record.Verification.Details
            Error = $Record.Verification.Error
        }
    }
    [PSCustomObject][ordered]@{
        SchemaVersion = $Record.SchemaVersion
        RecordId = $Record.RecordId
        RemediationId = $Record.RemediationId
        ProtectionTier = $Record.ProtectionTier
        ComputerName = $Record.ComputerName
        CreatedAt = ConvertTo-ArchesCanonicalTimestamp $Record.CreatedAt
        Status = $Record.Status
        Changes = $changes
        AppliedAt = ConvertTo-ArchesCanonicalTimestamp $Record.AppliedAt
        RolledBackAt = ConvertTo-ArchesCanonicalTimestamp $Record.RolledBackAt
        Verification = $verification
    } | ConvertTo-Json -Depth 10 -Compress
}

function Get-ArchesRollbackIntegrityValue {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][byte[]]$Key
    )
    $payload = ConvertTo-ArchesRollbackIntegrityPayload -Record $Record
    $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$Key)
    try {
        [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-ArchesFixedTimeString {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )
    $leftBytes = [Text.Encoding]::UTF8.GetBytes($Left)
    $rightBytes = [Text.Encoding]::UTF8.GetBytes($Right)
    $difference = $leftBytes.Length -bxor $rightBytes.Length
    $length = [math]::Max($leftBytes.Length, $rightBytes.Length)
    for ($index = 0; $index -lt $length; $index++) {
        $leftByte = if ($index -lt $leftBytes.Length) { $leftBytes[$index] } else { 0 }
        $rightByte = if ($index -lt $rightBytes.Length) { $rightBytes[$index] } else { 0 }
        $difference = $difference -bor ($leftByte -bxor $rightByte)
    }
    $difference -eq 0
}

function Set-ArchesRollbackIntegrity {
    param([Parameter(Mandatory)][object]$Record)
    $key = Get-ArchesRollbackIntegrityKey
    try {
        $Record.Integrity = [PSCustomObject][ordered]@{
            Algorithm = 'HMAC-SHA256'
            KeyId = Get-ArchesRollbackIntegrityKeyId -Key $key
            Value = Get-ArchesRollbackIntegrityValue -Record $Record -Key $key
        }
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Assert-ArchesRollbackIntegrity {
    param([Parameter(Mandatory)][object]$Record)
    Assert-ArchesExactProperties -InputObject $Record.Integrity `
        -Expected @('Algorithm', 'KeyId', 'Value') -Location 'Integrity'
    if ($Record.Integrity.Algorithm -ne 'HMAC-SHA256') {
        throw "Invalid rollback record: unsupported integrity algorithm '$($Record.Integrity.Algorithm)'."
    }
    if ($Record.Integrity.KeyId -isnot [string] -or
        $Record.Integrity.KeyId -notmatch '^[a-f0-9]{64}$' -or
        $Record.Integrity.Value -isnot [string]) {
        throw 'Invalid rollback record: malformed integrity metadata.'
    }
    $key = Get-ArchesRollbackIntegrityKey
    try {
        $keyId = Get-ArchesRollbackIntegrityKeyId -Key $key
        $expected = Get-ArchesRollbackIntegrityValue -Record $Record -Key $key
        if (-not (Test-ArchesFixedTimeString -Left $Record.Integrity.KeyId -Right $keyId) -or
            -not (Test-ArchesFixedTimeString -Left $Record.Integrity.Value -Right $expected)) {
            throw 'Rollback record integrity validation failed. The record may have been modified or belongs to a different integrity key.'
        }
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
    }
}

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
        'RolledBackAt', 'Verification', 'Integrity'
    ) -Location 'root'

    if ($Record.SchemaVersion -notin @([int]3, [long]3)) {
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
    $changeKeys = @{}
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
        $changeKey = '{0}|{1}|{2}' -f $change.TargetType, $change.Target, $change.Property
        if ($changeKeys.ContainsKey($changeKey)) {
            throw "Invalid rollback record: duplicate change target '$changeKey'."
        }
        $changeKeys[$changeKey] = $true
    }

    Assert-ArchesTimestamp -Value $Record.AppliedAt -Name 'AppliedAt' -AllowNull
    Assert-ArchesTimestamp -Value $Record.RolledBackAt -Name 'RolledBackAt' -AllowNull
    Assert-ArchesVerification -Verification $Record.Verification

    if ($Record.Status -eq 'Pending' -and
        ($null -ne $Record.AppliedAt -or $null -ne $Record.RolledBackAt -or $null -ne $Record.Verification)) {
        throw 'Invalid rollback record: Pending records cannot contain application, rollback, or verification state.'
    }
    if ($Record.Status -eq 'Applied' -and
        ($null -eq $Record.AppliedAt -or $null -ne $Record.RolledBackAt -or
            $null -eq $Record.Verification -or -not $Record.Verification.Succeeded)) {
        throw 'Invalid rollback record: Applied records require successful application verification and cannot contain rollback state.'
    }
    if ($Record.Status -eq 'RolledBack') {
        if ($null -eq $Record.AppliedAt -or $null -eq $Record.RolledBackAt -or
            $null -eq $Record.Verification -or -not $Record.Verification.Succeeded) {
            throw 'Invalid rollback record: RolledBack records require AppliedAt, successful verification, and RolledBackAt.'
        }
    }
    if ($Record.Status -eq 'RollbackFailed') {
        if ($null -eq $Record.RolledBackAt -or $null -eq $Record.Verification -or
            $Record.Verification.Succeeded) {
            throw 'Invalid rollback record: RollbackFailed records require failed verification and RolledBackAt.'
        }
    }
    Assert-ArchesRollbackIntegrity -Record $Record
    $true
}

function Save-ArchesRollbackRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Record
    )
    Set-ArchesRollbackIntegrity -Record $Record
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
        SchemaVersion = 3
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
        Integrity = $null
    }
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

function Get-ArchesFirewallProfileState {
    param([Parameter(Mandatory)][string[]]$Profile)
    @(Get-NetFirewallProfile -Profile $Profile -ErrorAction Stop |
        Select-Object Name, Enabled)
}

function Set-ArchesFirewallProfileState {
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][bool]$Enabled
    )
    Set-NetFirewallProfile -Profile $Profile -Enabled $Enabled -ErrorAction Stop
}

function Restore-ArchesFirewallChanges {
    param([Parameter(Mandatory)][object]$Record)
    foreach ($change in @($Record.Changes)) {
        Set-ArchesFirewallProfileState -Profile $change.Target -Enabled ([bool]$change.Before)
    }
    foreach ($change in @($Record.Changes)) {
        $profile = Get-ArchesFirewallProfileState -Profile $change.Target
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
    Remove-ArchesExpiredRollback, Get-ArchesFirewallProfileState, `
    Set-ArchesFirewallProfileState
