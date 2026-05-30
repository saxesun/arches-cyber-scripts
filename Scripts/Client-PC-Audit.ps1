# Client-PC-Audit.ps1
# Read-only workstation assessment script
# Run as Administrator

$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
$ReportFolder = "$env:USERPROFILE\Desktop\ClientAudit_$ComputerName`_$TimeStamp"

New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null

function Save-Text {
    param (
        [string]$FileName,
        [scriptblock]$Command
    )

    $Path = Join-Path $ReportFolder $FileName
    try {
        & $Command | Out-File -FilePath $Path -Encoding UTF8
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $Path -Encoding UTF8
    }
}

function Save-Csv {
    param (
        [string]$FileName,
        [scriptblock]$Command
    )

    $Path = Join-Path $ReportFolder $FileName
    try {
        & $Command | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
    catch {
        [PSCustomObject]@{
            Error = $_.Exception.Message
        } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

# Basic computer info
Save-Csv "01_Computer_Info.csv" {
    Get-ComputerInfo | Select-Object `
        CsName,
        WindowsProductName,
        WindowsVersion,
        OsBuildNumber,
        OsArchitecture,
        CsManufacturer,
        CsModel,
        CsDomain,
        CsWorkgroup,
        CsUserName,
        BiosFirmwareType,
        SecureBootState,
        CsTotalPhysicalMemory,
        OsLastBootUpTime
}

# Serial number / BIOS
Save-Csv "02_BIOS_Serial.csv" {
    Get-CimInstance Win32_BIOS | Select-Object `
        Manufacturer,
        SMBIOSBIOSVersion,
        SerialNumber,
        ReleaseDate
}

# CPU
Save-Csv "03_CPU.csv" {
    Get-CimInstance Win32_Processor | Select-Object `
        Name,
        Manufacturer,
        NumberOfCores,
        NumberOfLogicalProcessors,
        MaxClockSpeed,
        SocketDesignation
}

# RAM
Save-Csv "04_RAM.csv" {
    Get-CimInstance Win32_PhysicalMemory | Select-Object `
        Manufacturer,
        PartNumber,
        Capacity,
        Speed,
        ConfiguredClockSpeed,
        DeviceLocator
}

# Storage disks
Save-Csv "05_Storage_Disks.csv" {
    Get-CimInstance Win32_DiskDrive | Select-Object `
        Model,
        SerialNumber,
        MediaType,
        InterfaceType,
        Size
}

# Volumes
Save-Csv "06_Storage_Volumes.csv" {
    Get-Volume | Select-Object `
        DriveLetter,
        FileSystemLabel,
        FileSystem,
        HealthStatus,
        Size,
        SizeRemaining
}

# Local users
Save-Csv "07_Local_Users.csv" {
    Get-LocalUser | Select-Object `
        Name,
        Enabled,
        LastLogon,
        PasswordRequired,
        PasswordLastSet,
        UserMayChangePassword,
        PasswordExpires,
        Description
}

# Local admins
Save-Text "08_Local_Admins.txt" {
    Get-LocalGroupMember Administrators
}

# BitLocker status
Save-Text "09_BitLocker_Status.txt" {
    manage-bde -status
}

# Defender status
Save-Csv "10_Defender_Status.csv" {
    Get-MpComputerStatus | Select-Object `
        AMServiceEnabled,
        AntivirusEnabled,
        RealTimeProtectionEnabled,
        BehaviorMonitorEnabled,
        IoavProtectionEnabled,
        NISEnabled,
        AntivirusSignatureLastUpdated,
        QuickScanEndTime,
        FullScanEndTime
}

# Firewall profiles
Save-Csv "11_Firewall_Profiles.csv" {
    Get-NetFirewallProfile | Select-Object `
        Name,
        Enabled,
        DefaultInboundAction,
        DefaultOutboundAction,
        AllowInboundRules,
        AllowLocalFirewallRules,
        NotifyOnListen
}

# RDP status
Save-Csv "12_RDP_Status.csv" {
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        RDP_Connections_Denied = $RDP.fDenyTSConnections
        RDP_Enabled = if ($RDP.fDenyTSConnections -eq 0) { "Yes" } else { "No" }
    }
}

# Installed software
Save-Csv "13_Installed_Software.csv" {
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName
}

# Network adapters
Save-Csv "14_Network_Adapters.csv" {
    Get-NetAdapter | Select-Object `
        Name,
        InterfaceDescription,
        Status,
        MacAddress,
        LinkSpeed,
        MediaType
}

# IP / DNS / Gateway
Save-Text "15_IP_DNS_Gateway.txt" {
    Get-NetIPConfiguration
}

# DNS client settings
Save-Csv "16_DNS_Settings.csv" {
    Get-DnsClientServerAddress | Select-Object `
        InterfaceAlias,
        AddressFamily,
        ServerAddresses
}

# Default gateway / possible router info
Save-Csv "17_Default_Gateway.csv" {
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object `
        InterfaceAlias,
        NextHop,
        RouteMetric,
        ifIndex
}

# ARP table - may reveal router MAC/vendor later
Save-Text "18_ARP_Table.txt" {
    arp -a
}

# Try to identify router web interface / brand clues
Save-Text "19_Router_Brand_Clues.txt" {
    $Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop

    "Default Gateway: $Gateway"
    ""
    "Trying HTTP title/header check..."
    ""

    if ($Gateway) {
        try {
            Invoke-WebRequest -Uri "http://$Gateway" -UseBasicParsing -TimeoutSec 5 |
            Select-Object StatusCode, StatusDescription, Headers, Content
        }
        catch {
            "HTTP check failed or blocked: $($_.Exception.Message)"
        }

        ""
        "Trying HTTPS title/header check..."
        ""

        try {
            Invoke-WebRequest -Uri "https://$Gateway" -UseBasicParsing -TimeoutSec 5 |
            Select-Object StatusCode, StatusDescription, Headers, Content
        }
        catch {
            "HTTPS check failed or blocked: $($_.Exception.Message)"
        }
    }
    else {
        "No default gateway found."
    }
}

# Windows 11 compatibility clues
Save-Csv "20_Windows11_Compatibility_Clues.csv" {
    $TPM = Get-Tpm
    $CPU = Get-CimInstance Win32_Processor | Select-Object -First 1
    $RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $Disk = Get-CimInstance Win32_DiskDrive | Select-Object -First 1
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CPU = $CPU.Name
        CPU_Cores = $CPU.NumberOfCores
        RAM_GB = $RAM
        Disk_Size_GB = [math]::Round($Disk.Size / 1GB, 2)
        TPM_Present = $TPM.TpmPresent
        TPM_Ready = $TPM.TpmReady
        TPM_Enabled = $TPM.TpmEnabled
        TPM_Activated = $TPM.TpmActivated
        SecureBoot_Enabled = $SecureBoot
        Firmware_Type = (Get-ComputerInfo).BiosFirmwareType
        OS_Architecture = (Get-ComputerInfo).OsArchitecture
    }
}

# Last boot time
Save-Csv "21_Last_Boot.csv" {
    Get-CimInstance Win32_OperatingSystem | Select-Object `
        CSName,
        LastBootUpTime,
        LocalDateTime
}

# Basic update status
Save-Text "22_Windows_Update_Status.txt" {
    "Windows Update Service:"
    Get-Service wuauserv

    ""
    "Recent Windows Updates:"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20

    ""
    "Update Policy Registry Clues:"
    Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
}

# SMB shares
Save-Csv "23_SMB_Shares.csv" {
    Get-SmbShare | Select-Object `
        Name,
        Path,
        Description,
        ShareState,
        FolderEnumerationMode
}

# Listening ports
Save-Csv "24_Listening_Ports.csv" {
    Get-NetTCPConnection -State Listen | Select-Object `
        LocalAddress,
        LocalPort,
        OwningProcess
}

# Processes tied to listening ports
Save-Csv "25_Listening_Port_Processes.csv" {
    Get-NetTCPConnection -State Listen |
    ForEach-Object {
        $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            ProcessId = $_.OwningProcess
            ProcessName = $Process.ProcessName
        }
    }
}

# Startup programs
Save-Csv "26_Startup_Programs.csv" {
    Get-CimInstance Win32_StartupCommand | Select-Object `
        Name,
        Command,
        Location,
        User
}

# Antivirus products registered in Security Center
Save-Csv "27_Security_Center_AV.csv" {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    Select-Object displayName, pathToSignedProductExe, productState
}

# Summary file
$SummaryPath = Join-Path $ReportFolder "00_READ_ME_Summary.txt"

@"
Client PC Audit Complete

Computer: $ComputerName
Date: $(Get-Date)
Report Folder: $ReportFolder

Useful files to review first:
1. 01_Computer_Info.csv
2. 07_Local_Users.csv
3. 08_Local_Admins.txt
4. 09_BitLocker_Status.txt
5. 10_Defender_Status.csv
6. 11_Firewall_Profiles.csv
7. 12_RDP_Status.csv
8. 13_Installed_Software.csv
9. 15_IP_DNS_Gateway.txt
10. 20_Windows11_Compatibility_Clues.csv
11. 22_Windows_Update_Status.txt
12. 24_Listening_Ports.csv

Router note:
PowerShell usually cannot perfectly identify router brand from a client PC.
This script checks the default gateway, ARP table, and gateway web headers.
For real router identification, physically inspect the router/firewall or log into the admin interface with permission.

This script is read-only and does not intentionally change system settings.
"@ | Out-File -FilePath $SummaryPath -Encoding UTF8

Write-Host ""
Write-Host "Audit complete." -ForegroundColor Green
Write-Host "Reports saved to:"
Write-Host $ReportFolder -ForegroundColor Cyan