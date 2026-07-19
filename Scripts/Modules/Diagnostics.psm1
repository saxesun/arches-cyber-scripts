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
            -Summary 'The check could not complete.' -Evidence $_.Exception.Message `
            -Recommendation 'Review the log and rerun from an elevated Windows PowerShell session.'
    }
}

function Get-ArchesSecurityDiagnostics {
    $results = @()
    $results += Invoke-ArchesDiagnostic 'SEC-FW-001' 'Security' 'Windows Firewall' {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $disabled = @($profiles | Where-Object { -not $_.Enabled })
        if ($disabled.Count) {
            New-ArchesResult -Id 'SEC-FW-001' -Category Security -Title 'Windows Firewall' -Status Fail -Severity High `
                -Summary "$($disabled.Count) firewall profile(s) disabled." -Evidence ($disabled.Name -join ', ') `
                -Recommendation 'Enable all Windows Firewall profiles.' -RemediationId 'FIX-FW-001' -RequiresAdmin $true
        } else {
            New-ArchesResult -Id 'SEC-FW-001' -Category Security -Title 'Windows Firewall' -Status Pass -Summary 'All firewall profiles are enabled.' -Evidence ($profiles.Name -join ', ')
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-AV-001' 'Security' 'Antivirus protection' {
        $av = Get-MpComputerStatus -ErrorAction Stop
        if ($av.AntivirusEnabled -and $av.RealTimeProtectionEnabled) {
            New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' -Status Pass -Summary 'Microsoft Defender antivirus and real-time protection are enabled.' -Evidence $av
        } else {
            New-ArchesResult -Id 'SEC-AV-001' -Category Security -Title 'Antivirus protection' -Status Fail -Severity Critical -Summary 'Antivirus or real-time protection is disabled.' -Evidence $av -Recommendation 'Enable antivirus and real-time protection immediately.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-RDP-001' 'Security' 'Remote Desktop' {
        $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        if ($rdp.fDenyTSConnections -eq 0) {
            New-ArchesResult -Id 'SEC-RDP-001' -Category Security -Title 'Remote Desktop' -Status Warning -Severity Medium -Summary 'Remote Desktop is enabled.' -Evidence 'fDenyTSConnections=0' -Recommendation 'Disable RDP unless required, and never expose it directly to the internet.'
        } else {
            New-ArchesResult -Id 'SEC-RDP-001' -Category Security -Title 'Remote Desktop' -Status Pass -Summary 'Remote Desktop is disabled.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'SEC-BL-001' 'Security' 'BitLocker protection' {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ([string]$volume.ProtectionStatus -eq 'On' -or [int]$volume.ProtectionStatus -eq 1) {
            New-ArchesResult -Id 'SEC-BL-001' -Category Security -Title 'BitLocker protection' -Status Pass -Summary 'System drive protection is enabled.' -Evidence $volume
        } else {
            New-ArchesResult -Id 'SEC-BL-001' -Category Security -Title 'BitLocker protection' -Status Fail -Severity High -Summary 'System drive protection is not enabled.' -Evidence $volume -Recommendation 'Back up the recovery key and enable BitLocker where licensing and hardware support it.'
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
            New-ArchesResult -Id 'SEC-ADM-001' -Category Security -Title 'Local administrators' -Status Warning -Severity Medium -Summary "$($admins.Count) local administrator principals were found." -Evidence ($admins.Name -join ', ') -Recommendation 'Review each administrator and remove access that is not required.'
        } else {
            New-ArchesResult -Id 'SEC-ADM-001' -Category Security -Title 'Local administrators' -Status Pass -Summary "$($admins.Count) local administrator principal(s) found." -Evidence ($admins.Name -join ', ')
        }
    }
    $results
}

function Get-ArchesNetworkDiagnostics {
    $results = @()
    $results += Invoke-ArchesDiagnostic 'NET-GW-001' 'Network' 'Default gateway' {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
        if ($route -and (Test-Connection -ComputerName $route.NextHop -Count 1 -Quiet)) {
            New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Pass -Summary 'The default gateway responds.' -Evidence $route.NextHop
        } else {
            New-ArchesResult -Id 'NET-GW-001' -Category Network -Title 'Default gateway' -Status Fail -Severity High -Summary 'No responsive default gateway was found.' -Evidence $route -Recommendation 'Check the adapter, cable/Wi-Fi connection, DHCP lease, and router.'
        }
    }
    $results += Invoke-ArchesDiagnostic 'NET-DNS-001' 'Network' 'DNS resolution' {
        $answer = Resolve-DnsName -Name 'www.microsoft.com' -Type A -DnsOnly -ErrorAction Stop | Select-Object -First 1
        New-ArchesResult -Id 'NET-DNS-001' -Category Network -Title 'DNS resolution' -Status Pass -Summary 'DNS resolution succeeded.' -Evidence $answer.IPAddress
    }
    $results += Invoke-ArchesDiagnostic 'NET-INT-001' 'Network' 'Internet reachability' {
        $reachable = Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($reachable) {
            New-ArchesResult -Id 'NET-INT-001' -Category Network -Title 'Internet reachability' -Status Pass -Summary 'Outbound TCP 443 connectivity succeeded.' -Evidence '1.1.1.1:443'
        } else {
            New-ArchesResult -Id 'NET-INT-001' -Category Network -Title 'Internet reachability' -Status Fail -Severity High -Summary 'Outbound TCP 443 connectivity failed.' -Evidence '1.1.1.1:443' -Recommendation 'Check WAN status, firewall policy, captive portals, and upstream service availability.'
        }
    }
    $results
}

function Get-ArchesSystemDiagnostics {
    $results = @()
    $results += Invoke-ArchesDiagnostic 'SYS-DISK-001' 'Hardware' 'System drive free space' {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        $percent = if ($disk.Size) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) } else { 0 }
        if ($percent -lt 10) {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Fail -Severity High -Summary "Only $percent% free space remains." -Evidence $disk -Recommendation 'Free disk space before updates or normal operation begin failing.'
        } elseif ($percent -lt 20) {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Warning -Severity Medium -Summary "$percent% free space remains." -Evidence $disk -Recommendation 'Plan disk cleanup or storage expansion.'
        } else {
            New-ArchesResult -Id 'SYS-DISK-001' -Category Hardware -Title 'System drive free space' -Status Pass -Summary "$percent% free space remains." -Evidence $disk
        }
    }
    $results += Invoke-ArchesDiagnostic 'SYS-BOOT-001' 'Performance' 'Time since restart' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $days = [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalDays)
        if ($days -gt 30) {
            New-ArchesResult -Id 'SYS-BOOT-001' -Category Performance -Title 'Time since restart' -Status Warning -Severity Low -Summary "The computer has not restarted for $days days." -Evidence $os.LastBootUpTime -Recommendation 'Schedule a restart after saving work and confirming maintenance availability.'
        } else {
            New-ArchesResult -Id 'SYS-BOOT-001' -Category Performance -Title 'Time since restart' -Status Pass -Summary "Last restart was $days day(s) ago." -Evidence $os.LastBootUpTime
        }
    }
    $results += Invoke-ArchesDiagnostic 'SYS-UPD-001' 'Security' 'Windows Update service' {
        $service = Get-Service -Name wuauserv -ErrorAction Stop
        if ($service.StartType -eq 'Disabled') {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Fail -Severity High -Summary 'The Windows Update service is disabled.' -Evidence $service -Recommendation 'Review update management policy and enable Windows Update when it is not controlled by another approved tool.'
        } elseif ($service.Status -ne 'Running') {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Warning -Severity Low -Summary "The Windows Update service is $($service.Status)." -Evidence $service -Recommendation 'Confirm the service can start when Windows checks for updates.'
        } else {
            New-ArchesResult -Id 'SYS-UPD-001' -Category Security -Title 'Windows Update service' -Status Pass -Summary 'The Windows Update service is running.' -Evidence $service
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
    $results = @()
    $results += Invoke-ArchesDiagnostic 'DEV-ARP-001' 'Connected Devices' 'Neighbor table visibility' {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.State -notin @('Unreachable','Incomplete') -and $_.IPAddress -notmatch '^(224|239)\.'
        })
        New-ArchesResult -Id 'DEV-ARP-001' -Category 'Connected Devices' -Title 'Neighbor table visibility' -Status Pass `
            -Summary "$($neighbors.Count) active or recently observed IPv4 neighbor(s) found." `
            -Evidence @($neighbors | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State)
    }
    $results
}

function Get-ArchesPerformanceDiagnostics {
    $results = @()
    $results += Invoke-ArchesDiagnostic 'PERF-MEM-001' 'Performance' 'Available memory' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $percentAvailable = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
        if ($percentAvailable -lt 10) {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Fail -Severity High -Summary "Only $percentAvailable% memory is currently available." -Evidence $os -Recommendation 'Identify memory-heavy processes and evaluate whether the system needs more RAM.'
        } elseif ($percentAvailable -lt 20) {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Warning -Severity Medium -Summary "$percentAvailable% memory is currently available." -Evidence $os -Recommendation 'Review memory pressure and high-usage processes.'
        } else {
            New-ArchesResult -Id 'PERF-MEM-001' -Category Performance -Title 'Available memory' -Status Pass -Summary "$percentAvailable% memory is currently available." -Evidence $os
        }
    }
    $results += Invoke-ArchesDiagnostic 'PERF-CPU-001' 'Performance' 'Processor utilization' {
        $samples = @(Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty LoadPercentage)
        $average = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Average).Average, 1) } else { 0 }
        if ($average -ge 90) {
            New-ArchesResult -Id 'PERF-CPU-001' -Category Performance -Title 'Processor utilization' -Status Warning -Severity Medium -Summary "Processor load is currently $average%." -Evidence $samples -Recommendation 'Review sustained CPU use in Task Manager before taking corrective action.'
        } else {
            New-ArchesResult -Id 'PERF-CPU-001' -Category Performance -Title 'Processor utilization' -Status Pass -Summary "Processor load is currently $average%." -Evidence $samples
        }
    }
    $results
}

function Invoke-ArchesFullScan {
    [CmdletBinding()]
    param()
    @(
        Get-ArchesSecurityDiagnostics
        Get-ArchesNetworkDiagnostics
        Get-ArchesSystemDiagnostics
        Get-ArchesConnectedDeviceDiagnostics
        Get-ArchesPerformanceDiagnostics
    ) | Sort-ArchesResults
}

Export-ModuleMember -Function Test-ArchesAdministrator, Get-ArchesSecurityDiagnostics, Get-ArchesNetworkDiagnostics, Get-ArchesSystemDiagnostics, Get-ArchesConnectedDeviceDiagnostics, Get-ArchesPerformanceDiagnostics, Invoke-ArchesFullScan
