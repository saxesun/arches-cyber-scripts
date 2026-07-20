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

function Get-ArchesDefenderDiagnosticState {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $managed = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' `
        -PathType Container -ErrorAction Stop
    [PSCustomObject]@{
        Available = $true
        AntivirusEnabled = [bool]$status.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        RunningMode = [string]$status.AMRunningMode
        Managed = [bool]$managed
    }
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
    $results
}

function Get-ArchesNetworkDiagnostics {
    param([Parameter(Mandatory)][object]$Configuration)
    $results = @()
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
        New-ArchesResult -Id 'DEV-ARP-001' -Category 'Connected Devices' -Title 'Neighbor table visibility' -Status Pass `
            -Summary "$($neighbors.Count) active or recently observed IPv4 neighbor(s) found." `
            -Evidence ([PSCustomObject]@{ NeighborCount = $neighbors.Count })
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
    Invoke-ArchesFullScan, Get-ArchesAntivirusDiagnostic
