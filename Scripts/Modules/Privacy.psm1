Set-StrictMode -Version 2.0

function Get-ArchesEvidenceAllowlist {
    @{
        'SEC-FW-001' = @('DisabledProfiles', 'ObservedProfiles')
        'SEC-FW-RULES-001' = @('RuleCount', 'EnabledRuleCount', 'AllowRuleCount', 'BlockRuleCount', 'Rules', 'Truncated')
        'SEC-AV-001' = @('SecurityCenterAvailable', 'RegisteredProducts', 'ActiveThirdPartyProducts', 'DefenderAvailable', 'DefenderEnabled', 'DefenderRealTimeEnabled', 'DefenderMode', 'Managed', 'ConflictingSignals')
        'SEC-MAL-STATUS-001' = @('DefenderAvailable', 'DefenderMode', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'SignatureAgeDays', 'SignatureLastUpdated', 'SignatureVersion', 'QuickScanEndTime', 'FullScanEndTime', 'LastScanType', 'LastScanEndTime')
        'SEC-MAL-THREAT-001' = @('ThreatHistoryAvailable', 'DetectedThreatCount', 'DetectionEventCount', 'QuarantinedThreatCount', 'UnresolvedThreatCount', 'ResolvedThreatCount', 'LatestDetectionTime', 'ThreatStatusSummaries')
        'SEC-RDP-001' = @('RegistryValue')
        'SEC-BL-001' = @('MountPoint', 'VolumeStatus', 'ProtectionStatus', 'EncryptionPercentage')
        'SEC-ADM-001' = @('PrincipalCount')
        'SEC-USERS-001' = @('LocalUserCount', 'EnabledUserCount', 'DisabledUserCount', 'PasswordRequiredCount')
        'NET-IF-001' = @('InterfaceCount', 'Interfaces')
        'NET-GW-001' = @('RoutePresent', 'NextHop', 'InterfaceAlias', 'RouteMetric', 'NeighborResolved', 'IcmpSuccessCount', 'IcmpAttemptCount', 'TcpStatus')
        'NET-DNS-001' = @('Query', 'IPAddress')
        'NET-INT-001' = @('Target', 'Protocol')
        'SYS-DISK-001' = @('DeviceId', 'SizeBytes', 'FreeBytes', 'PercentFree')
        'SYS-BOOT-001' = @('LastBootUpTime', 'DaysSinceRestart')
        'SYS-UPD-001' = @('ServiceName', 'Status', 'StartType')
        'SYS-W11-001' = @('CPU', 'Cores', 'RAM_GB', 'SystemDisk_GB', 'Architecture', 'TPM_Present', 'TPM_Ready')
        'DEV-ARP-001' = @('NeighborCount', 'Neighbors', 'Truncated')
        'PERF-MEM-001' = @('PercentAvailable', 'FreePhysicalMemoryKB', 'TotalVisibleMemoryKB')
        'PERF-CPU-001' = @('AverageLoadPercent')
        'DIAGNOSTIC-ERROR' = @('ErrorType')
    }
}

function ConvertTo-ArchesSafeEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [object]$Evidence,
        [switch]$DiagnosticError
    )
    if ($null -eq $Evidence) {
        return $null
    }
    $allowlist = Get-ArchesEvidenceAllowlist
    $allowlistId = if ($DiagnosticError) { 'DIAGNOSTIC-ERROR' } else { $Id }
    if (-not $allowlist.ContainsKey($allowlistId)) {
        return $null
    }

    $safe = [ordered]@{}
    foreach ($name in $allowlist[$allowlistId]) {
        if ($name -notin @($Evidence.PSObject.Properties.Name)) {
            continue
        }
        $value = $Evidence.$name
        if ($null -eq $value -or $value -is [string] -or $value -is [bool] -or
            $value -is [byte] -or $value -is [int16] -or $value -is [int32] -or
            $value -is [int64] -or $value -is [single] -or $value -is [double] -or
            $value -is [decimal] -or $value -is [datetime] -or $value -is [DateTimeOffset]) {
            $safe[$name] = $value
        }
        elseif ($value -is [array]) {
            $safe[$name] = @($value | Where-Object {
                $null -eq $_ -or $_ -is [string] -or $_ -is [bool] -or $_ -is [ValueType]
            })
        }
    }
    if (-not $safe.Count) {
        return $null
    }
    [PSCustomObject]$safe
}

Export-ModuleMember -Function Get-ArchesEvidenceAllowlist, ConvertTo-ArchesSafeEvidence
