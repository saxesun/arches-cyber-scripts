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
    $results
}

function Invoke-ArchesFullScan {
    [CmdletBinding()]
    param()
    @(
        Get-ArchesSecurityDiagnostics
        Get-ArchesNetworkDiagnostics
        Get-ArchesSystemDiagnostics
    ) | Sort-ArchesResults
}

Export-ModuleMember -Function Test-ArchesAdministrator, Get-ArchesSecurityDiagnostics, Get-ArchesNetworkDiagnostics, Get-ArchesSystemDiagnostics, Invoke-ArchesFullScan
