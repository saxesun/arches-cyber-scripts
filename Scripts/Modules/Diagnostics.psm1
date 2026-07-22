Set-StrictMode -Version 2.0

function Test-ArchesAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ArchesDiagnostic {
    param([string]$Id, [string]$Category, [string]$Title, [scriptblock]$Action)
    try { & $Action }
    catch {
        New-ArchesResult -Id $Id -Category $Category -Title $Title -Status Error -Severity Medium `
            -Summary 'The check could not complete.' `
            -Evidence ([PSCustomObject]@{ ErrorType = $_.Exception.GetType().FullName }) `
            -Recommendation 'Review the log and rerun from an elevated Windows PowerShell session.'
    }
}

function Get-ArchesDefaultRoute {
    Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric |
        Select-Object -First 1
}

function Get-ArchesGatewayNeighbor {
    param([Parameter(Mandatory)][string]$IPAddress)
    Get-NetNeighbor -IPAddress $IPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object State -notin @('Unreachable', 'Incomplete') |
        Select-Object -First 1
}

function Invoke-ArchesIcmpSamples {
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateRange(1, 10)][int]$Attempts = 3,
        [ValidateRange(100, 10000)][int]$TimeoutMilliseconds = 1000
    )
    $results = @()
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $ping = New-Object Net.NetworkInformation.Ping
        try {
            $reply = $ping.Send($Target, $TimeoutMilliseconds)
            $results += [PSCustomObject]@{
                Attempt = $attempt
                Status = [string]$reply.Status
                RoundtripTimeMs = if ($reply.Status -eq 'Success') { [long]$reply.RoundtripTime } else { $null }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Attempt = $attempt
                Status = 'Error'
                RoundtripTimeMs = $null
            }
        }
        finally {
            $ping.Dispose()
        }
    }
    $results
}

function Test-ArchesTcpReachability {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [ValidateRange(100, 30000)][int]$TimeoutMilliseconds = 3000
    )
    $client = New-Object Net.Sockets.TcpClient
    $asyncResult = $null
    try {
        $asyncResult = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return [PSCustomObject]@{ Status='Timeout'; Target=$Target; Port=$Port }
        }
        $client.EndConnect($asyncResult)
        [PSCustomObject]@{ Status='Success'; Target=$Target; Port=$Port }
    }
    catch {
        [PSCustomObject]@{ Status='Error'; Target=$Target; Port=$Port }
    }
    finally {
        if ($null -ne $asyncResult -and $null -ne $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }
        $client.Close()
    }
}

function Resolve-ArchesDnsBounded {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateRange(100, 30000)][int]$TimeoutMilliseconds = 3000
    )
    $asyncResult = [Net.Dns]::BeginGetHostAddresses($Name, $null, $null)
    try {
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return [PSCustomObject]@{ Status='Timeout'; Name=$Name; Addresses=@() }
        }
        $addresses = @([Net.Dns]::EndGetHostAddresses($asyncResult) | ForEach-Object IPAddressToString)
        [PSCustomObject]@{ Status='Success'; Name=$Name; Addresses=$addresses }
    }
    catch {
        [PSCustomObject]@{ Status='Error'; Name=$Name; Addresses=@() }
    }
    finally {
        if ($null -ne $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }
    }
}

function Get-ArchesSecurityCenterAntivirusProducts {
    $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' `
        -ClassName AntiVirusProduct -ErrorAction Stop)
    @($products | ForEach-Object {
        $state = [int]$_.productState
        $stateByte = ($state -shr 8) -band 0xff
        [PSCustomObject]@{
            Product = [string]$_.displayName
            Active = $stateByte -in @(0x10, 0x11)
            IsMicrosoft = [string]$_.displayName -match 'Microsoft Defender|Windows Defender'
        }
    })
}

function Get-ArchesObjectPropertyValue {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject -or $Name -notin @($InputObject.PSObject.Properties.Name)) {
        return $null
    }
    $InputObject.$Name
}

function ConvertTo-ArchesDiagnosticTimestamp {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    try {
        $date = [datetime]$Value
        if ($date.Year -lt 2000) { return $null }
        ([DateTimeOffset]$date).ToString('o')
    }
    catch { $null }
}

function Get-ArchesDefenderDiagnosticState {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $managed = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' `
        -PathType Container -ErrorAction Stop
    $quickScanEndTime = ConvertTo-ArchesDiagnosticTimestamp `
        (Get-ArchesObjectPropertyValue -InputObject $status -Name 'QuickScanEndTime')
    $fullScanEndTime = ConvertTo-ArchesDiagnosticTimestamp `
        (Get-ArchesObjectPropertyValue -InputObject $status -Name 'FullScanEndTime')
    $lastScanType = $null
    $lastScanEndTime = $null
    if ($quickScanEndTime -and $fullScanEndTime) {
        if ([DateTimeOffset]$quickScanEndTime -ge [DateTimeOffset]$fullScanEndTime) {
            $lastScanType = 'Quick'
            $lastScanEndTime = $quickScanEndTime
        }
        else {
            $lastScanType = 'Full'
            $lastScanEndTime = $fullScanEndTime
        }
    }
    elseif ($quickScanEndTime) {
        $lastScanType = 'Quick'
        $lastScanEndTime = $quickScanEndTime
    }
    elseif ($fullScanEndTime) {
        $lastScanType = 'Full'
        $lastScanEndTime = $fullScanEndTime
    }
    $signatureAge = Get-ArchesObjectPropertyValue -InputObject $status -Name 'AntivirusSignatureAge'
    [PSCustomObject]@{
        Available = $true
        AntivirusEnabled = [bool]$status.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        RunningMode = [string]$status.AMRunningMode
        Managed = [bool]$managed
        SignatureAgeDays = if ($null -ne $signatureAge) { [int64]$signatureAge } else { $null }
        SignatureLastUpdated = ConvertTo-ArchesDiagnosticTimestamp `
            (Get-ArchesObjectPropertyValue -InputObject $status -Name 'AntivirusSignatureLastUpdated')
        SignatureVersion = [string](Get-ArchesObjectPropertyValue -InputObject $status -Name 'AntivirusSignatureVersion')
        QuickScanEndTime = $quickScanEndTime
        FullScanEndTime = $fullScanEndTime
        LastScanType = $lastScanType
        LastScanEndTime = $lastScanEndTime
    }
}

function Get-ArchesDefenderThreatState {
    $threats = @(Get-MpThreat -ErrorAction Stop)
    $detections = @(Get-MpThreatDetection -ErrorAction Stop)
    $statusValues = @()
    $unresolved = @()
    $quarantined = @()
    foreach ($threat in $threats) {
        $status = [string](Get-ArchesObjectPropertyValue -InputObject $threat -Name 'Status')
        $rollupStatus = [string](Get-ArchesObjectPropertyValue -InputObject $threat -Name 'RollupStatus')
        $statusText = (@($status, $rollupStatus) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' / '
        if ([string]::IsNullOrWhiteSpace($statusText)) { $statusText = 'Unspecified' }
        $statusText = (($statusText -replace '[\r\n;]', ' ').Trim())
        if ($statusText.Length -gt 80) { $statusText = $statusText.Substring(0, 80) }
        $statusValues += $statusText

        $isActive = [bool](Get-ArchesObjectPropertyValue -InputObject $threat -Name 'IsActive')
        if ($isActive -or $statusText -match '(^|[ /_-])(Active|Detected|Failed|Pending|ActionRequired|RemediationRequired)($|[ /_-])') {
            $unresolved += $threat
        }
        if ($statusText -match 'Quarantin') {
            $quarantined += $threat
        }
    }
    $statusSummaries = @($statusValues | Group-Object | Sort-Object Name | ForEach-Object {
        'Status={0}; Count={1}' -f $_.Name, $_.Count
    })
    $latestDetection = $null
    $detectionDates = @($detections | ForEach-Object {
        $value = Get-ArchesObjectPropertyValue -InputObject $_ -Name 'InitialDetectionTime'
        if ($null -ne $value) {
            try { [DateTimeOffset]([datetime]$value) } catch { }
        }
    })
    if ($detectionDates.Count) {
        $latestDetection = ($detectionDates | Sort-Object -Descending | Select-Object -First 1).ToString('o')
    }
    [PSCustomObject]@{
        ThreatHistoryAvailable = $true
        DetectedThreatCount = $threats.Count
        DetectionEventCount = $detections.Count
        QuarantinedThreatCount = $quarantined.Count
        UnresolvedThreatCount = $unresolved.Count
        ResolvedThreatCount = [math]::Max(0, $threats.Count - $unresolved.Count)
        LatestDetectionTime = $latestDetection
        ThreatStatusSummaries = $statusSummaries
    }
}

function Get-ArchesDefenderHealthDiagnostic {
    param([Parameter(Mandatory)][object]$Configuration)
    try {
        $defender = Get-ArchesDefenderDiagnosticState
    }
    catch {
        return New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
            -Title 'Malware protection status and scan history' -Status Unknown -Severity Info `
            -Summary 'Defender security intelligence and scan history are unavailable.' `
            -Evidence ([PSCustomObject]@{ DefenderAvailable=$false }) `
            -Recommendation 'Verify malware protection status in the active antivirus product or its management console.'
    }
    $evidence = [PSCustomObject]@{
        DefenderAvailable = $true
        DefenderMode = $defender.RunningMode
        AntivirusEnabled = [bool]$defender.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$defender.RealTimeProtectionEnabled
        SignatureAgeDays = $defender.SignatureAgeDays
        SignatureLastUpdated = $defender.SignatureLastUpdated
        SignatureVersion = $defender.SignatureVersion
        QuickScanEndTime = $defender.QuickScanEndTime
        FullScanEndTime = $defender.FullScanEndTime
        LastScanType = $defender.LastScanType
        LastScanEndTime = $defender.LastScanEndTime
    }
    $defenderActive = $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled -and
        $defender.RunningMode -notmatch 'Passive'
    if (-not $defenderActive) {
        return New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
            -Title 'Malware protection status and scan history' -Status Unknown -Severity Info `
            -Summary 'Defender is not active, so its signatures and scan history are not authoritative for the active antivirus product.' `
            -Evidence $evidence `
            -Recommendation 'Review scan and signature health in the registered third-party antivirus console.'
    }
    if ($null -eq $defender.SignatureAgeDays) {
        return New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
            -Title 'Malware protection status and scan history' -Status Unknown -Severity Info `
            -Summary 'Defender is active, but the security-intelligence age was not reported.' `
            -Evidence $evidence -Recommendation 'Update Defender security intelligence and rerun the diagnostic.'
    }
    if ([int64]$defender.SignatureAgeDays -gt [int]$Configuration.Thresholds.AntivirusSignatureWarningDays) {
        return New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
            -Title 'Malware protection status and scan history' -Status Warning -Severity Medium `
            -Summary "Defender security intelligence is $($defender.SignatureAgeDays) day(s) old; the warning threshold is $($Configuration.Thresholds.AntivirusSignatureWarningDays) day(s)." `
            -Evidence $evidence -Recommendation 'Update Defender security intelligence, then confirm the reported age returns to the expected range.'
    }
    if (-not $defender.LastScanEndTime) {
        return New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
            -Title 'Malware protection status and scan history' -Status Warning -Severity Low `
            -Summary 'Defender is active and security intelligence is current, but no completed quick or full scan time was reported.' `
            -Evidence $evidence -Recommendation 'Run an approved Defender quick scan and confirm its completion time appears.'
    }
    New-ArchesResult -Id 'SEC-MAL-STATUS-001' -Category Security `
        -Title 'Malware protection status and scan history' -Status Pass `
        -Summary "Defender is active, security intelligence is current, and the last completed scan was a $($defender.LastScanType.ToLowerInvariant()) scan." `
        -Evidence $evidence
}

function Get-ArchesDefenderThreatDiagnostic {
    try {
        $defender = Get-ArchesDefenderDiagnosticState
    }
    catch {
        return New-ArchesResult -Id 'SEC-MAL-THREAT-001' -Category Security `
            -Title 'Malware detections and remediation status' -Status Unknown -Severity Info `
            -Summary 'Defender threat history is unavailable.' `
            -Evidence ([PSCustomObject]@{ ThreatHistoryAvailable=$false }) `
            -Recommendation 'Review threat history in the active antivirus product or its management console.'
    }
    if (-not $defender.AntivirusEnabled -or $defender.RunningMode -match 'Passive') {
        return New-ArchesResult -Id 'SEC-MAL-THREAT-001' -Category Security `
            -Title 'Malware detections and remediation status' -Status Unknown -Severity Info `
            -Summary 'Defender is not the active antivirus engine, so its local threat history is not authoritative.' `
            -Evidence ([PSCustomObject]@{ ThreatHistoryAvailable=$false }) `
            -Recommendation 'Review detected, quarantined, and unresolved threats in the registered third-party antivirus console.'
    }
    try {
        $threatState = Get-ArchesDefenderThreatState
    }
    catch {
        return New-ArchesResult -Id 'SEC-MAL-THREAT-001' -Category Security `
            -Title 'Malware detections and remediation status' -Status Unknown -Severity Info `
            -Summary 'Defender is active, but its threat history could not be read.' `
            -Evidence ([PSCustomObject]@{ ThreatHistoryAvailable=$false }) `
            -Recommendation 'Review Windows Security protection history and rerun from an elevated session.'
    }
    if ($threatState.UnresolvedThreatCount -gt 0) {
        return New-ArchesResult -Id 'SEC-MAL-THREAT-001' -Category Security `
            -Title 'Malware detections and remediation status' -Status Fail -Severity High `
            -Summary "$($threatState.UnresolvedThreatCount) unresolved Defender threat record(s) require review." `
            -Evidence $threatState `
            -Recommendation 'Open Windows Security protection history, investigate the unresolved detections, and follow the approved incident-response process.'
    }
    $summary = if ($threatState.DetectedThreatCount) {
        "$($threatState.DetectedThreatCount) historical threat record(s) were found; none are currently classified as unresolved."
    }
    else { 'Defender reported no threat records and no unresolved detections.' }
    New-ArchesResult -Id 'SEC-MAL-THREAT-001' -Category Security `
        -Title 'Malware detections and remediation status' -Status Pass -Summary $summary `
        -Evidence $threatState
}

function Get-ArchesAntivirusDiagnostic {
    $securityCenterAvailable = $true
    $defenderAvailable = $true
    try {
        $products = @(Get-ArchesSecurityCenterAntivirusProducts)
    }
    catch {
        $securityCenterAvailable = $false
        $products = @()
    }
    try {
        $defender = Get-ArchesDefenderDiagnosticState
    }
    catch {
        $defenderAvailable = $false
        $defender = $null
    }

    $thirdPartyActive = @($products | Where-Object { $_.Active -and -not $_.IsMicrosoft })
    $registeredDefender = @($products | Where-Object IsMicrosoft)
    $defenderActive = $defenderAvailable -and $defender.AntivirusEnabled -and
        $defender.RealTimeProtectionEnabled
    $defenderPassive = $defenderAvailable -and $defender.RunningMode -match 'Passive'
    $conflicting = $false
    if ($defenderAvailable -and $registeredDefender.Count) {
        $registeredDefenderActive = @($registeredDefender | Where-Object Active).Count -gt 0
        $conflicting = $registeredDefenderActive -ne [bool]$defenderActive
    }
    $evidence = [PSCustomObject]@{
        SecurityCenterAvailable = $securityCenterAvailable
        RegisteredProducts = @($products | ForEach-Object Product)
        ActiveThirdPartyProducts = @($thirdPartyActive | ForEach-Object Product)
        DefenderAvailable = $defenderAvailable
        DefenderEnabled = if ($defenderAvailable) { [bool]$defender.AntivirusEnabled } else { $null }
        DefenderRealTimeEnabled = if ($defenderAvailable) { [bool]$defender.RealTimeProtectionEnabled } else { $null }
        DefenderMode = if ($defenderAvailable) { $defender.RunningMode } else { $null }
        Managed = if ($defenderAvailable) { [bool]$defender.Managed } else { $null }
        ConflictingSignals = $conflicting
    }

    if (-not $securityCenterAvailable) {
        return New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
            -Status Unknown -Severity Info -Summary 'Windows Security Center antivirus registration is unavailable, so protection ownership cannot be established safely.' `
            -Evidence $evidence -Recommendation 'Verify registered antivirus products and their active state manually.'
    }
    if ($conflicting) {
        return New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
            -Status Unknown -Severity Info -Summary 'Security Center and Defender report conflicting antivirus state.' `
            -Evidence $evidence -Recommendation 'Resolve the conflicting product state before judging protection health.'
    }
    if ($thirdPartyActive.Count -and ($defenderPassive -or -not $defenderActive)) {
        return New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
            -Status Pass -Summary 'An active third-party antivirus product is registered; Defender inactivity or passive mode is expected.' `
            -Evidence $evidence
    }
    if ($defenderActive) {
        return New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
            -Status Pass -Summary 'Microsoft Defender antivirus and real-time protection are active.' `
            -Evidence $evidence
    }
    if (-not $defenderAvailable -or ($null -ne $defender -and $defender.Managed)) {
        return New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
            -Status Unknown -Severity Info -Summary 'Antivirus state is unavailable or policy-managed and active protection could not be established safely.' `
            -Evidence $evidence -Recommendation 'Verify the managing security product and policy state.'
    }
    New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' `
        -Status Fail -Severity High -Summary 'No active registered antivirus protection was detected.' `
        -Evidence $evidence -Recommendation 'Confirm product health and enable an approved antivirus product.'
}

function Get-ArchesSecurityDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
    $results += Invoke-ArchesDiagnostic 'SEC-FW-001' 'Security' 'Windows Firewall' {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $disabled = @($profiles | Where-Object { -not $_.Enabled })
        if ($disabled.Count) {
            New-ArchesResult -Id 'SEC-FW-001' -Category Security -Title 'Windows Firewall' -Status Fail -Severity High `
                -Summary "$($disabled.Count) firewall profile(s) disabled." `
                -Evidence ([PSCustomObject]@{ DisabledProfiles = @($disabled.Name); ObservedProfiles = @($profiles.Name) }) `
                -Recommendation 'Enable all Windows Firewall profiles.' -RemediationId 'FIX-FW-001' -RequiresAdmin $true
        } else {
            New-ArchesResult -Id 'SEC-FW-001' -Category Security -Title 'Windows Firewall' -Status Pass -Summary 'All firewall profiles are enabled.' `
                -Evidence ([PSCustomObject]@{ DisabledProfiles = @(); ObservedProfiles = @($profiles.Name) })
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-AV-001' 'Security' 'Antivirus protection' {
        Get-ArchesAntivirusDiagnostic
    }
    $results += Invoke-ArchesDiagnostic 'SEC-MAL-STATUS-001' 'Security' 'Malware protection status and scan history' {
        Get-ArchesDefenderHealthDiagnostic -Configuration $Configuration
    }
    $results += Invoke-ArchesDiagnostic 'SEC-MAL-THREAT-001' 'Security' 'Malware detections and remediation status' {
        Get-ArchesDefenderThreatDiagnostic
    }
    $results += Invoke-ArchesDiagnostic 'SEC-RDP-001' 'Security' 'Remote Desktop' {
        $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        if ($rdp.fDenyTSConnections -eq 0) {
            New-ArchesResult -Id 'SEC-RDP-001' -Category Security -Title 'Remote Desktop' -Status Warning -Severity Medium -Summary 'Remote Desktop is enabled.' `
                -Evidence ([PSCustomObject]@{ RegistryValue = 0 }) -Recommendation 'Disable RDP unless required, and never expose it directly to the internet.'
        } else {
            New-ArchesResult -Id 'SEC-RDP-001' -Category Security -Title 'Remote Desktop' -Status Pass -Summary 'Remote Desktop is disabled.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-BL-001' 'Security' 'BitLocker protection' {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ([string]$volume.ProtectionStatus -eq 'On' -or [int]$volume.ProtectionStatus -eq 1) {
            New-ArchesResult -Id 'SEC-BL-001' -Category Security -Title 'BitLocker protection' -Status Pass -Summary 'System drive protection is enabled.' `
                -Evidence ([PSCustomObject]@{ MountPoint=[string]$volume.MountPoint; VolumeStatus=[string]$volume.VolumeStatus; ProtectionStatus=[string]$volume.ProtectionStatus; EncryptionPercentage=$volume.EncryptionPercentage })
        } else {
            New-ArchesResult -Id 'SEC-BL-001' -Category Security -Title 'BitLocker protection' -Status Fail -Severity High -Summary 'System drive protection is not enabled.' `
                -Evidence ([PSCustomObject]@{ MountPoint=[string]$volume.MountPoint; VolumeStatus=[string]$volume.VolumeStatus; ProtectionStatus=[string]$volume.ProtectionStatus; EncryptionPercentage=$volume.EncryptionPercentage }) `
                -Recommendation 'Back up the recovery key and enable BitLocker where licensing and hardware support it.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-SB-001' 'Security' 'Secure Boot' {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($enabled) {
            New-ArchesResult -Id 'SEC-SB-001' -Category Security -Title 'Secure Boot' -Status Pass -Summary 'Secure Boot is enabled.'
        } else {
            New-ArchesResult -Id 'SEC-SB-001' -Category Security -Title 'Secure Boot' -Status Warning -Severity Medium -Summary 'Secure Boot is disabled.' -Recommendation 'Verify firmware compatibility and enable Secure Boot.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-ADM-001' 'Security' 'Local administrators' {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        if ($admins.Count -gt 3) {
            New-ArchesResult -Id 'SEC-ADM-001' -Category Security -Title 'Local administrators' -Status Warning -Severity Medium -Summary "$($admins.Count) local administrator principals were found." `
                -Evidence ([PSCustomObject]@{ PrincipalCount = $admins.Count }) -Recommendation 'Review each administrator and remove access that is not required.'
        } else {
            New-ArchesResult -Id 'SEC-ADM-001' -Category Security -Title 'Local administrators' -Status Pass -Summary "$($admins.Count) local administrator principal(s) found." `
                -Evidence ([PSCustomObject]@{ PrincipalCount = $admins.Count })
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-USERS-001' 'Security' 'Local user account summary' {
        $users = @(Get-LocalUser -ErrorAction Stop)
        $enabled = @($users | Where-Object Enabled).Count
        $passwordRequired = @($users | Where-Object PasswordRequired).Count
        New-ArchesResult -Id 'SEC-USERS-001' -Category Security -Title 'Local user account summary' -Status Pass `
            -Summary "$($users.Count) local account(s) found; $enabled enabled." `
            -Evidence ([PSCustomObject]@{
                LocalUserCount = $users.Count
                EnabledUserCount = $enabled
                DisabledUserCount = $users.Count - $enabled
                PasswordRequiredCount = $passwordRequired
            })
    }
    $results += Invoke-ArchesDiagnostic 'SEC-FW-RULES-001' 'Security' 'Firewall rule inventory' {
        $allRules = @(Get-NetFirewallRule -ErrorAction Stop)
        $enabledRules = @($allRules | Where-Object Enabled -eq 'True')
        $ruleLimit = 500
        $safeRules = @($enabledRules | Sort-Object DisplayName | Select-Object -First $ruleLimit | ForEach-Object {
            'Name={0}; Direction={1}; Action={2}; Profile={3}; Enabled={4}' -f `
                ([string]$_.DisplayName -replace '[\r\n;]', ' '), $_.Direction, $_.Action, $_.Profile, $_.Enabled
        })
        New-ArchesResult -Id 'SEC-FW-RULES-001' -Category Security -Title 'Firewall rule inventory' -Status Pass `
            -Summary "$($allRules.Count) firewall rule(s) found; $($enabledRules.Count) enabled." `
            -Evidence ([PSCustomObject]@{
                RuleCount = $allRules.Count
                EnabledRuleCount = $enabledRules.Count
                AllowRuleCount = @($enabledRules | Where-Object Action -eq 'Allow').Count
                BlockRuleCount = @($enabledRules | Where-Object Action -eq 'Block').Count
                Rules = $safeRules
                Truncated = $enabledRules.Count -gt $ruleLimit
            })
    }
    $results
}

function Get-ArchesNetworkDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
    $results += Invoke-ArchesDiagnostic 'NET-IF-001' 'Network' 'IP configuration' {
        $configurations = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
            $_.NetAdapter.Status -eq 'Up'
        })
        $interfaces = @($configurations | ForEach-Object {
            $ipv4 = @($_.IPv4Address | ForEach-Object IPAddress) -join ', '
            $gateway = @($_.IPv4DefaultGateway | ForEach-Object NextHop) -join ', '
            $dns = @($_.DNSServer.ServerAddresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join ', '
            'Interface={0}; IPv4={1}; Gateway={2}; DNS={3}' -f `
                ([string]$_.InterfaceAlias -replace '[\r\n;]', ' '), $ipv4, $gateway, $dns
        })
        New-ArchesResult -Id 'NET-IF-001' -Category Network -Title 'IP configuration' -Status Pass `
            -Summary "$($configurations.Count) active network interface(s) found." `
            -Evidence ([PSCustomObject]@{ InterfaceCount=$configurations.Count; Interfaces=$interfaces })
    }
    $results += Invoke-ArchesDiagnostic 'NET-GW-001' 'Network' 'Default gateway' {
        $route = Get-ArchesDefaultRoute
        if ($null -eq $route) {
            New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Fail -Severity High `
                -Summary 'No IPv4 default route is configured.' `
                -Evidence ([PSCustomObject]@{ RoutePresent=$false; NeighborResolved=$false; IcmpSuccessCount=0; IcmpAttemptCount=0; TcpStatus='NotAttempted' }) `
                -Recommendation 'Check adapter addressing, DHCP/static configuration, and default-route policy.'
        }
        else {
            $neighbor = Get-ArchesGatewayNeighbor -IPAddress $route.NextHop
            $icmp = @(Invoke-ArchesIcmpSamples -Target $route.NextHop -Attempts 3 -TimeoutMilliseconds 1000)
            $icmpSuccessCount = @($icmp | Where-Object Status -eq 'Success').Count
            $tcp = Test-ArchesTcpReachability -Target 'www.microsoft.com' -Port 443 -TimeoutMilliseconds 3000
            $evidence = [PSCustomObject]@{
                RoutePresent = $true
                NextHop = $route.NextHop
                InterfaceAlias = $route.InterfaceAlias
                RouteMetric = $route.RouteMetric
                NeighborResolved = $null -ne $neighbor
                IcmpSuccessCount = $icmpSuccessCount
                IcmpAttemptCount = $icmp.Count
                TcpStatus = $tcp.Status
            }
            if ($icmpSuccessCount -gt 0 -and $tcp.Status -eq 'Success') {
                New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Pass `
                    -Summary 'The default route, gateway ICMP samples, and independent TCP reachability succeeded.' -Evidence $evidence
            }
            elseif ($icmpSuccessCount -eq 0 -and $tcp.Status -eq 'Success') {
                New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Warning -Severity Low `
                    -Summary 'The route and independent TCP reachability work, but the gateway did not answer bounded ICMP samples.' -Evidence $evidence `
                    -Recommendation 'ICMP may be blocked by policy; do not treat this alone as an outage.'
            }
            elseif ($null -eq $neighbor -and $icmpSuccessCount -eq 0 -and $tcp.Status -in @('Error', 'Timeout')) {
                New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Fail -Severity High `
                    -Summary 'Route, neighbor, ICMP, and independent TCP evidence indicate a local connectivity outage.' -Evidence $evidence `
                    -Recommendation 'Check the adapter, cable/Wi-Fi connection, addressing, gateway, and local network.'
            }
            else {
                New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Unknown -Severity Info `
                    -Summary 'Gateway evidence is partial or conflicting; connectivity could not be established safely.' -Evidence $evidence `
                    -Recommendation 'Review route, neighbor, ICMP, and TCP evidence before diagnosing an outage.'
            }
        }
    }
    $results += Invoke-ArchesDiagnostic 'NET-DNS-001' 'Network' 'DNS resolution' {
        $answer = Resolve-ArchesDnsBounded -Name 'www.microsoft.com' -TimeoutMilliseconds 3000
        if ($answer.Status -eq 'Success' -and @($answer.Addresses).Count) {
            New-ArchesResult -Id 'NET-DNS-001' -Category Network -Title 'DNS resolution' -Status Pass -Summary 'DNS resolution succeeded within the bounded timeout.' `
                -Evidence ([PSCustomObject]@{ Query='www.microsoft.com'; IPAddress=$answer.Addresses[0] })
        }
        else {
            New-ArchesResult -Id 'NET-DNS-001' -Category Network -Title 'DNS resolution' -Status Unknown -Severity Info `
                -Summary "DNS resolution did not complete successfully within the bounded check ($($answer.Status))." `
                -Evidence ([PSCustomObject]@{ Query='www.microsoft.com'; IPAddress=$null })
        }
    }
    $results += Invoke-ArchesDiagnostic 'NET-INT-001' 'Network' 'Internet reachability' {
        $reachable = Test-ArchesTcpReachability -Target 'www.microsoft.com' -Port 443 -TimeoutMilliseconds 3000
        if ($reachable.Status -eq 'Success') {
            New-ArchesResult -Id 'NET-INT-001' -Category Network -Title 'Internet reachability' -Status Pass -Summary 'Outbound TCP 443 connectivity succeeded.' `
                -Evidence ([PSCustomObject]@{ Target='www.microsoft.com:443'; Protocol='TCP' })
        } else {
            New-ArchesResult -Id 'NET-INT-001' -Category Network -Title 'Internet reachability' -Status Unknown -Severity Info `
                -Summary "The bounded outbound TCP check did not succeed ($($reachable.Status))." `
                -Evidence ([PSCustomObject]@{ Target='www.microsoft.com:443'; Protocol='TCP' }) -Recommendation 'Correlate with gateway and DNS evidence before diagnosing an outage.'
        }
    }
    $results
}

function Get-ArchesSystemDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
    $results += Invoke-ArchesDiagnostic 'SYS-DISK-001' 'Hardware' 'System drive free space' {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        $percent = if ($disk.Size) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) } else { 0 }
        if ($percent -le $Configuration.Thresholds.DiskFreeCriticalPercent) {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Fail -Severity High -Summary "Only $percent% free space remains." `
                -Evidence ([PSCustomObject]@{ DeviceId=$disk.DeviceID; SizeBytes=$disk.Size; FreeBytes=$disk.FreeSpace; PercentFree=$percent }) -Recommendation 'Free disk space before updates or normal operation begin failing.'
        } elseif ($percent -lt $Configuration.Thresholds.DiskFreeWarningPercent) {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Warning -Severity Medium -Summary "$percent% free space remains." `
                -Evidence ([PSCustomObject]@{ DeviceId=$disk.DeviceID; SizeBytes=$disk.Size; FreeBytes=$disk.FreeSpace; PercentFree=$percent }) -Recommendation 'Plan disk cleanup or storage expansion.'
        } else {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Pass -Summary "$percent% free space remains." `
                -Evidence ([PSCustomObject]@{ DeviceId=$disk.DeviceID; SizeBytes=$disk.Size; FreeBytes=$disk.FreeSpace; PercentFree=$percent })
        }
    }
    $results += Invoke-ArchesDiagnostic 'SYS-BOOT-001' 'Performance' 'Time since restart' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $days = [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalDays)
        if ($days -ge $Configuration.Thresholds.RestartAgeWarningDays) {
            New-ArchesResult -Id 'SYS-BOOT-001' -Category Performance -Title 'Time since restart' -Status Warning -Severity Low -Summary "The computer has not restarted for $days days." `
                -Evidence ([PSCustomObject]@{ LastBootUpTime=$os.LastBootUpTime; DaysSinceRestart=$days }) -Recommendation 'Schedule a restart after saving work and confirming maintenance availability.'
        } else {
            New-ArchesResult -Id 'SYS-BOOT-001' -Category Performance -Title 'Time since restart' -Status Pass -Summary "Last restart was $days day(s) ago." `
                -Evidence ([PSCustomObject]@{ LastBootUpTime=$os.LastBootUpTime; DaysSinceRestart=$days })
        }
    }
    $results += Invoke-ArchesDiagnostic 'SYS-UPD-001' 'Security' 'Windows Update service' {
        $service = Get-Service -Name wuauserv -ErrorAction Stop
        if ($service.StartType -eq 'Disabled') {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Fail -Severity High -Summary 'The Windows Update service is disabled.' `
                -Evidence ([PSCustomObject]@{ ServiceName='wuauserv'; Status=[string]$service.Status; StartType=[string]$service.StartType }) -Recommendation 'Review update management policy and enable Windows Update when it is not controlled by another approved tool.'
        } elseif ($service.Status -ne 'Running') {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Warning -Severity Low -Summary "The Windows Update service is $($service.Status)." `
                -Evidence ([PSCustomObject]@{ ServiceName='wuauserv'; Status=[string]$service.Status; StartType=[string]$service.StartType }) -Recommendation 'Confirm the service can start when Windows checks for updates.'
        } else {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Pass -Summary 'The Windows Update service is running.' `
                -Evidence ([PSCustomObject]@{ ServiceName='wuauserv'; Status=[string]$service.Status; StartType=[string]$service.StartType })
        }
    }
    $results += Invoke-ArchesDiagnostic 'SYS-W11-001' 'Hardware' 'Windows 11 readiness clues' {
        $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $systemDisk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        $tpm = try { Get-Tpm -ErrorAction Stop } catch { $null }
        $ramGb = [math]::Round($system.TotalPhysicalMemory / 1GB, 1)
        $diskGb = [math]::Round($systemDisk.Size / 1GB, 1)
        $basicReady = $cpu.NumberOfCores -ge 2 -and $ramGb -ge 4 -and $diskGb -ge 64 -and $os.OSArchitecture -match '64'
        $tpmReady = $tpm -and $tpm.TpmPresent -and $tpm.TpmReady
        $evidence = [PSCustomObject]@{ CPU=$cpu.Name; Cores=$cpu.NumberOfCores; RAM_GB=$ramGb; SystemDisk_GB=$diskGb; Architecture=$os.OSArchitecture; TPM_Present=if($tpm){$tpm.TpmPresent}else{$null}; TPM_Ready=if($tpm){$tpm.TpmReady}else{$null} }
        if ($basicReady -and $tpmReady) {
            New-ArchesResult -Id 'SYS-W11-001' -Category Hardware -Title 'Windows 11 readiness clues' -Status Pass -Summary 'Basic hardware and TPM readiness clues meet the minimums checked.' -Evidence $evidence
        } else {
            New-ArchesResult -Id 'SYS-W11-001' -Category Hardware -Title 'Windows 11 readiness clues' -Status Warning -Severity Medium -Summary 'One or more basic Windows 11 readiness clues did not meet the checked minimums.' -Evidence $evidence -Recommendation 'Use Microsoft PC Health Check for the authoritative CPU model and compatibility decision.'
        }
    }
    $results
}

function Get-ArchesConnectedDeviceDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
    $results += Invoke-ArchesDiagnostic 'DEV-ARP-001' 'Connected Devices' 'Neighbor table visibility' {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.State -notin @('Unreachable','Incomplete') -and $_.IPAddress -notmatch '^(224|239)\.'
        })
        $neighborLimit = 250
        $safeNeighbors = @($neighbors | Sort-Object InterfaceAlias,IPAddress | Select-Object -First $neighborLimit | ForEach-Object {
            'IPv4={0}; MAC={1}; Interface={2}; State={3}' -f $_.IPAddress, $_.LinkLayerAddress, `
                ([string]$_.InterfaceAlias -replace '[\r\n;]', ' '), $_.State
        })
        New-ArchesResult -Id 'DEV-ARP-001' -Category 'Connected Devices' -Title 'Neighbor table visibility' -Status Pass `
            -Summary "$($neighbors.Count) active or recently observed IPv4 neighbor(s) found." `
            -Evidence ([PSCustomObject]@{
                NeighborCount = $neighbors.Count
                Neighbors = $safeNeighbors
                Truncated = $neighbors.Count -gt $neighborLimit
            })
    }
    $results
}

function Get-ArchesPerformanceDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
    $results += Invoke-ArchesDiagnostic 'PERF-MEM-001' 'Performance' 'Available memory' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $percentAvailable = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
        if ($percentAvailable -le $Configuration.Thresholds.MemoryAvailableCriticalPercent) {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Fail -Severity High -Summary "Only $percentAvailable% memory is currently available." `
                -Evidence ([PSCustomObject]@{ PercentAvailable=$percentAvailable; FreePhysicalMemoryKB=$os.FreePhysicalMemory; TotalVisibleMemoryKB=$os.TotalVisibleMemorySize }) -Recommendation 'Identify memory-heavy processes and evaluate whether the system needs more RAM.'
        } elseif ($percentAvailable -lt $Configuration.Thresholds.MemoryAvailableWarningPercent) {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Warning -Severity Medium -Summary "$percentAvailable% memory is currently available." `
                -Evidence ([PSCustomObject]@{ PercentAvailable=$percentAvailable; FreePhysicalMemoryKB=$os.FreePhysicalMemory; TotalVisibleMemoryKB=$os.TotalVisibleMemorySize }) -Recommendation 'Review memory pressure and high-usage processes.'
        } else {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Pass -Summary "$percentAvailable% memory is currently available." `
                -Evidence ([PSCustomObject]@{ PercentAvailable=$percentAvailable; FreePhysicalMemoryKB=$os.FreePhysicalMemory; TotalVisibleMemoryKB=$os.TotalVisibleMemorySize })
        }
    }
    $results += Invoke-ArchesDiagnostic 'PERF-CPU-001' 'Performance' 'Processor utilization' {
        $samples = @(Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty LoadPercentage)
        $average = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Average).Average, 1) } else { 0 }
        if ($average -ge $Configuration.Thresholds.CpuWarningPercent) {
            New-ArchesResult -Id 'PERF-CPU-001' -Category Performance -Title 'Processor utilization' -Status Warning -Severity Medium -Summary "Processor load is currently $average%." `
                -Evidence ([PSCustomObject]@{ AverageLoadPercent=$average }) -Recommendation 'Review sustained CPU use in Task Manager before taking corrective action.'
        } else {
            New-ArchesResult -Id 'PERF-CPU-001' -Category Performance -Title 'Processor utilization' -Status Pass -Summary "Processor load is currently $average%." `
                -Evidence ([PSCustomObject]@{ AverageLoadPercent=$average })
        }
    }
    $results
}

function Invoke-ArchesFullScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)
    @(
        Get-ArchesSecurityDiagnostics -Configuration $Configuration
        Get-ArchesNetworkDiagnostics -Configuration $Configuration
        Get-ArchesSystemDiagnostics -Configuration $Configuration
        Get-ArchesConnectedDeviceDiagnostics -Configuration $Configuration
        Get-ArchesPerformanceDiagnostics -Configuration $Configuration
    ) | Sort-ArchesResults
}

Export-ModuleMember -Function Test-ArchesAdministrator, Get-ArchesSecurityDiagnostics, `
    Get-ArchesNetworkDiagnostics, Get-ArchesSystemDiagnostics, `
    Get-ArchesConnectedDeviceDiagnostics, Get-ArchesPerformanceDiagnostics, `
    Invoke-ArchesFullScan, Get-ArchesAntivirusDiagnostic, `
    Get-ArchesDefenderDiagnosticState, Get-ArchesDefenderThreatState, `
    Get-ArchesDefenderHealthDiagnostic, Get-ArchesDefenderThreatDiagnostic
