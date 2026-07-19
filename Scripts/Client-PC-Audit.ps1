# Client-PC-Audit.ps1
# Read-only workstation assessment script
# Run as Administrator

[CmdletBinding()]
param(
    [switch]$InteractiveDiagnostics
)

$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ComputerName = $env:COMPUTERNAME

# All audit output is stored under this Office-free folder.
# This keeps the client computer clean and gives you one folder to copy, zip, upload to Google Drive, or import into AppSheet/Google Sheets.
$AuditRoot = Join-Path $env:USERPROFILE "Desktop\ArchesCyberAudit"
$ReportFolder = Join-Path $AuditRoot "$ComputerName`_$TimeStamp"

New-Item -ItemType Directory -Path $AuditRoot -Force | Out-Null
New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null

function Save-Text {
    param ([string]$FileName, [scriptblock]$Command)
    $Path = Join-Path $ReportFolder $FileName
    try { & $Command | Out-File -FilePath $Path -Encoding UTF8 }
    catch { "ERROR: $($_.Exception.Message)" | Out-File -FilePath $Path -Encoding UTF8 }
}

function Save-Csv {
    param ([string]$FileName, [scriptblock]$Command)
    $Path = Join-Path $ReportFolder $FileName
    try { & $Command | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
    catch {
        [PSCustomObject]@{ Error = $_.Exception.Message } |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

function Run-NetworkDiagnostics {
    Write-Host "`n=== Network Diagnostics ==="

    Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress
    Get-NetIPConfiguration

    Write-Host "`nTesting internet by IP..."
    Test-NetConnection 8.8.8.8

    Write-Host "`nTesting DNS/internet by hostname..."
    Test-NetConnection google.com
}

function Run-DnsDiagnostics {
    Write-Host "`n=== DNS Diagnostics ==="

    Get-DnsClientServerAddress
    Resolve-DnsName google.com -ErrorAction SilentlyContinue
    nslookup google.com

    $fix = Read-Host "Flush DNS cache? Y/N"
    if ($fix -eq "Y") {
        ipconfig /flushdns
        Restart-Service Dnscache -Force
    }
}

function Run-DhcpLeaseCheck {
    Write-Host "`n=== DHCP Lease Check ==="

    Get-CimInstance Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    Select-Object Description, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires
}

function Run-StaticIpDiagnostics {
    Write-Host "`n=== Static IP Diagnostics ==="

    Get-NetIPConfiguration
    Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" }
    Get-DnsClientServerAddress
    Get-NetRoute -DestinationPrefix "0.0.0.0/0"

    Write-Host "`nNOTE: This script will not switch static IP devices to DHCP."
    Write-Host "Review gateway, subnet, DNS, and duplicate IP risk manually before making changes."
}

function Run-VoipDiagnostics {
    Write-Host "`n=== VoIP Diagnostics ==="

    $SipHost = Read-Host "Enter SIP/PBX host, example sip.provider.com"
    if ([string]::IsNullOrWhiteSpace($SipHost)) {
        Write-Host "No SIP/PBX host entered. Returning to the diagnostics menu."
        return
    }

    $Ports = @(5060, 5061, 5080, 5090, 3478)

    Write-Host "`nResolving SIP host..."
    Resolve-DnsName $SipHost -ErrorAction SilentlyContinue

    foreach ($port in $Ports) {
        Write-Host "`nTesting TCP port $port..."
        Test-NetConnection $SipHost -Port $port
    }

    Write-Host "`nActive TCP connections:"
    Get-NetTCPConnection | Where-Object {
        $_.RemotePort -in $Ports -or $_.LocalPort -in $Ports
    }

    Write-Host "`nActive UDP endpoints:"
    Get-NetUDPEndpoint | Where-Object {
        $_.LocalPort -in @(5060,5061,5080,5090,3478) -or
        ($_.LocalPort -ge 10000 -and $_.LocalPort -le 20000)
    }

    Write-Host "`nTraceroute:"
    tracert $SipHost
}

function Run-AllowlistChecker {
    Write-Host "`n=== Connectivity Allowlist Checker ==="

    $Targets = @(
        @{Name="Microsoft 365"; Host="outlook.office365.com"; Ports=@(443)},
        @{Name="Google Accounts"; Host="accounts.google.com"; Ports=@(443)}
    )

    $CustomHost = Read-Host "Enter custom host to test, or press Enter to skip"
    if ($CustomHost) {
        $Targets += @{Name="Custom Target"; Host=$CustomHost; Ports=@(80,443,5060,5061)}
    }

    foreach ($target in $Targets) {
        foreach ($port in $target.Ports) {
            Write-Host "`nTesting $($target.Name): $($target.Host):$port"
            Test-NetConnection $target.Host -Port $port
        }
    }

    Write-Host "`nProxy Settings:"
    netsh winhttp show proxy

    Write-Host "`nHosts File:"
    Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
}

function Run-BlockPathTrace {
    Write-Host "`n=== Block Path Trace ==="

    $TargetHost = Read-Host "Enter target host"
    if ([string]::IsNullOrWhiteSpace($TargetHost)) {
        Write-Host "No target host entered. Returning to the diagnostics menu."
        return
    }

    $PortText = Read-Host "Enter target TCP port"
    $Port = 0
    if (-not [int]::TryParse($PortText, [ref]$Port) -or $Port -lt 1 -or $Port -gt 65535) {
        Write-Host "Enter a valid TCP port from 1 through 65535."
        return
    }

    Write-Host "`nDNS Resolution:"
    Resolve-DnsName $TargetHost -ErrorAction SilentlyContinue

    Write-Host "`nDefault Gateway:"
    Get-NetRoute -DestinationPrefix "0.0.0.0/0"

    Write-Host "`nTrace Route:"
    tracert $TargetHost

    Write-Host "`nTCP Port Test:"
    Test-NetConnection $TargetHost -Port $Port -InformationLevel Detailed

    Write-Host "`nWindows Firewall Allow Rules:"
    Get-NetFirewallRule -Enabled True -Action Allow |
    Select-Object DisplayName, Direction, Profile, Action |
    Format-Table -AutoSize

    Write-Host "`nProxy Settings:"
    netsh winhttp show proxy

    Write-Host "`nInterpretation:"
    Write-Host "- Gateway fail = local network, VLAN, switch, NIC, or IP issue"
    Write-Host "- DNS fail = DNS server/filter issue"
    Write-Host "- Traceroute dies at gateway = router/firewall issue"
    Write-Host "- Traceroute dies after ISP = ISP/upstream/provider issue"
    Write-Host "- Trace works but port fails = firewall, service, or provider block"
}

function Run-WindowsHealthDiagnostics {
    Write-Host "`n=== BSOD / Windows Health Diagnostics ==="

    Write-Host "`nRecent BugCheck Events:"
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message

    Write-Host "`nMinidump Folder:"
    if (Test-Path "C:\Windows\Minidump") {
        Get-ChildItem "C:\Windows\Minidump" | Select-Object Name, LastWriteTime, Length
    } else {
        Write-Host "No minidump folder found."
    }

    Write-Host "`nDisk Health:"
    Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size

    $repair = Read-Host "Run SFC scan? Y/N"
    if ($repair -eq "Y") {
        sfc /scannow
    }

    $dism = Read-Host "Run DISM ScanHealth? Y/N"
    if ($dism -eq "Y") {
        DISM /Online /Cleanup-Image /ScanHealth
    }
}

# 01 Basic computer info
Save-Csv "01_Computer_Info.csv" {
    Get-ComputerInfo | Select-Object `
        CsName, WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture,
        CsManufacturer, CsModel, CsDomain, CsWorkgroup, CsUserName,
        BiosFirmwareType, SecureBootState, CsTotalPhysicalMemory, OsLastBootUpTime
}

# 02 Serial / BIOS
Save-Csv "02_BIOS_Serial.csv" {
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate
}

# 03 CPU
Save-Csv "03_CPU.csv" {
    Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
}

# 04 RAM
Save-Csv "04_RAM.csv" {
    Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, PartNumber, Capacity, Speed, ConfiguredClockSpeed, DeviceLocator
}

# 05 Storage
Save-Csv "05_Storage_Disks.csv" {
    Get-CimInstance Win32_DiskDrive | Select-Object Model, SerialNumber, MediaType, InterfaceType, Size
}

Save-Csv "06_Storage_Volumes.csv" {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, Size, SizeRemaining
}

# 07 Users
Save-Csv "07_Local_Users.csv" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, UserMayChangePassword, PasswordExpires, Description
}

# 08 Admins
Save-Text "08_Local_Admins.txt" {
    Get-LocalGroupMember Administrators
}

Save-Csv "08A_Local_Admin_Count.csv" {
    $Admins = Get-LocalGroupMember Administrators
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        LocalAdminCount = $Admins.Count
        AdminNames = ($Admins.Name -join "; ")
    }
}

# 09 Password policy
Save-Text "09_Password_Policy.txt" {
    net accounts
}

# 10 BitLocker
Save-Text "10_BitLocker_Status.txt" {
    try {
        Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod, LockStatus
    }
    catch {
        "Get-BitLockerVolume failed: $($_.Exception.Message)"
        ""
        "Trying manage-bde fallback..."
        ""

        try {
            manage-bde -status
        }
        catch {
            "manage-bde also failed: $($_.Exception.Message)"
            ""
            "BitLocker status unavailable. Try running PowerShell as Administrator."
        }
    }
}

# 11 Defender
Save-Csv "11_Defender_Status.csv" {
    Get-MpComputerStatus | Select-Object `
        AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
        BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled,
        AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime
}

Save-Text "11A_Defender_Threats.txt" {
    Get-MpThreatDetection
}

# 12 Firewall
Save-Csv "12_Firewall_Profiles.csv" {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, NotifyOnListen
}

# 13 RDP
Save-Csv "13_RDP_Status.csv" {
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        RDP_Connections_Denied = $RDP.fDenyTSConnections
        RDP_Enabled = if ($RDP.fDenyTSConnections -eq 0) { "Yes" } else { "No" }
    }
}

# 14 Installed software
Save-Csv "14_Installed_Software.csv" {
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName
}

# 15 Network adapters
Save-Csv "15_Network_Adapters.csv" {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, MediaType
}

# 16 IP / DNS / gateway
Save-Text "16_IP_DNS_Gateway.txt" {
    Get-NetIPConfiguration
}

Save-Csv "17_DNS_Settings.csv" {
    Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses
}

Save-Csv "18_Default_Gateway.csv" {
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object InterfaceAlias, NextHop, RouteMetric, ifIndex
}

Save-Text "19_ARP_Table.txt" {
    arp -a
}

# 20 Router clues
Save-Text "20_Router_Brand_Clues.txt" {
    $Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    "Default Gateway: $Gateway"
    ""

    if ($Gateway) {
        "HTTP gateway check:"
        try {
            Invoke-WebRequest -Uri "http://$Gateway" -UseBasicParsing -TimeoutSec 5 |
            Select-Object StatusCode, StatusDescription, Headers, Content
        }
        catch { "HTTP check failed: $($_.Exception.Message)" }

        ""
        "HTTPS gateway check:"
        try {
            Invoke-WebRequest -Uri "https://$Gateway" -UseBasicParsing -TimeoutSec 5 |
            Select-Object StatusCode, StatusDescription, Headers, Content
        }
        catch { "HTTPS check failed: $($_.Exception.Message)" }
    }
}

# 21 Windows 11 compatibility clues
Save-Csv "21_Windows11_Compatibility_Clues.csv" {
try {
    $TPM = Get-Tpm -ErrorAction Stop
}
catch {
    $TPM = $null
}

    $CPU = Get-CimInstance Win32_Processor | Select-Object -First 1
    $RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $Disk = Get-CimInstance Win32_DiskDrive | Select-Object -First 1
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CPU = $CPU.Name
        CPU_Cores = $CPU.NumberOfCores
        RAM_GB = $RAM
        Disk_Size_GB = [math]::Round($Disk.Size / 1GB, 2)
       TPM_Present = if ($TPM) { $TPM.TpmPresent } else { "Unknown" }
TPM_Ready = if ($TPM) { $TPM.TpmReady } else { "Unknown" }
TPM_Enabled = if ($TPM) { $TPM.TpmEnabled } else { "Unknown" }
TPM_Activated = if ($TPM) { $TPM.TpmActivated } else { "Unknown" }
        SecureBoot_Enabled = $SecureBoot
        Firmware_Type = (Get-ComputerInfo).BiosFirmwareType
        OS_Architecture = (Get-ComputerInfo).OsArchitecture
        PartOfDomain = $ComputerSystem.PartOfDomain
        Domain = $ComputerSystem.Domain
    }
}

# 22 Last boot
Save-Csv "22_Last_Boot.csv" {
    Get-CimInstance Win32_OperatingSystem | Select-Object CSName, LastBootUpTime, LocalDateTime
}

# 23 Windows Update
Save-Text "23_Windows_Update_Status.txt" {
    "Windows Update Service:"
    Get-Service wuauserv

    ""
    "Recent Windows Updates:"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20

    ""
    "Update Policy Registry Clues:"
    Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
}

# 24 Activation status
Save-Csv "24_Windows_Activation_Status.csv" {
    Get-CimInstance SoftwareLicensingProduct |
    Where-Object { $_.PartialProductKey } |
    Select-Object Name, Description, LicenseStatus, PartialProductKey
}

# 25 SMB shares
Save-Csv "25_SMB_Shares.csv" {
    Get-SmbShare | Select-Object Name, Path, Description, ShareState, FolderEnumerationMode
}

# 26 Listening ports
Save-Csv "26_Listening_Ports.csv" {
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
}

Save-Csv "27_Listening_Port_Processes.csv" {
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

# 28 Startup programs
Save-Csv "28_Startup_Programs.csv" {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}

# 29 Security Center AV
Save-Csv "29_Security_Center_AV.csv" {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    Select-Object displayName, pathToSignedProductExe, productState
}

# 30 Mapped drives
Save-Csv "30_Mapped_Drives.csv" {
    Get-SmbMapping | Select-Object LocalPath, RemotePath, Status, UserName
}

# 31 Printers
Save-Csv "31_Printers.csv" {
    Get-Printer | Select-Object Name, DriverName, PortName, Shared, Published, PrinterStatus
}


# 32 Network / DNS / Static IP / VoIP Diagnostics
# These are read-only checks that get included in the generated report bundle.
# Interactive repair steps are intentionally not run during the audit.

Save-Text "32A_Network_Diagnostics.txt" {
    "Network Diagnostics"
    "==================="
    ""
    "Network Adapters:"
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, MediaType
    ""
    "IP Configuration:"
    Get-NetIPConfiguration
    ""
    "Internet test by IP, 8.8.8.8:"
    Test-NetConnection 8.8.8.8 -InformationLevel Detailed
    ""
    "Internet test by hostname, google.com:"
    Test-NetConnection google.com -InformationLevel Detailed
}

Save-Text "32B_DNS_Diagnostics.txt" {
    "DNS Diagnostics"
    "==============="
    ""
    "DNS Client Server Addresses:"
    Get-DnsClientServerAddress
    ""
    "Resolve-DnsName google.com:"
    Resolve-DnsName google.com -ErrorAction SilentlyContinue
    ""
    "nslookup google.com:"
    nslookup google.com
    ""
    "DNS Cache Sample:"
    ipconfig /displaydns | Select-Object -First 80
}

Save-Csv "32C_DHCP_Lease_Check.csv" {
    Get-CimInstance Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    Select-Object Description, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder
}

Save-Text "32D_Static_IP_Diagnostics.txt" {
    "Static IP Diagnostics"
    "====================="
    ""
    "NOTE: This audit does NOT change static devices to DHCP. It only reports static configuration risks."
    ""

    $Configs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($Config in $Configs) {
        "Adapter: $($Config.Description)"
        "DHCP Enabled: $($Config.DHCPEnabled)"
        "IP Address(es): $($Config.IPAddress -join ', ')"
        "Subnet(s): $($Config.IPSubnet -join ', ')"
        "Gateway(s): $($Config.DefaultIPGateway -join ', ')"
        "DNS Server(s): $($Config.DNSServerSearchOrder -join ', ')"

        if ($Config.DHCPEnabled -eq $false) {
            "Finding: STATIC IP detected. Review gateway, subnet, DNS, duplicate IP risk, and route metric before making changes."
            if (-not $Config.DefaultIPGateway) { "Warning: Static adapter has no default gateway." }
            if (-not $Config.DNSServerSearchOrder) { "Warning: Static adapter has no DNS servers configured." }
        }
        ""
    }

    "IPv4 Addresses:"
    Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState, PrefixOrigin, SuffixOrigin
    ""
    "Default Routes:"
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object InterfaceAlias, NextHop, RouteMetric, ifIndex
    ""
    "ARP Table:"
    arp -a
}

Save-Text "32E_VoIP_Diagnostics.txt" {
    "VoIP Diagnostics"
    "================"
    ""
    "This section checks common local VoIP clues. Provider-specific SIP/PBX host tests require setting `$VoipTargets below."
    ""

    $VoipTargets = @()
    # Optional: add client/provider hosts here before running, for example:
    # $VoipTargets = @("sip.provider.com", "pbx.clientdomain.com")

    $VoipPorts = @(5060,5061,5080,5090,3478)

    "Common VoIP Ports Checked: SIP 5060, SIP-TLS 5061, alternate SIP 5080/5090, STUN/TURN 3478, RTP UDP 10000-20000."
    ""
    "Local TCP connections using common VoIP ports:"
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $_.RemotePort -in $VoipPorts -or $_.LocalPort -in $VoipPorts
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    ""
    "Local UDP endpoints using common VoIP/RTP ports:"
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {
        $_.LocalPort -in $VoipPorts -or ($_.LocalPort -ge 10000 -and $_.LocalPort -le 20000)
    } | Select-Object LocalAddress, LocalPort, OwningProcess
    ""

    foreach ($Target in $VoipTargets) {
        "Target: $Target"
        "DNS:"
        Resolve-DnsName $Target -ErrorAction SilentlyContinue
        foreach ($Port in $VoipPorts) {
            "TCP Test $Target`:$Port"
            Test-NetConnection $Target -Port $Port -InformationLevel Detailed
        }
        "Traceroute:"
        tracert $Target
        ""
    }

    if ($VoipTargets.Count -eq 0) {
        "No provider-specific SIP/PBX host configured. Add client SIP/PBX hostnames to `$VoipTargets for deeper tests."
    }
}

Save-Text "32F_Connectivity_Allowlist_Checker.txt" {
    "Connectivity Allowlist Checker"
    "=============================="
    ""
    $Targets = @(
        @{Name="Microsoft 365 Outlook"; Host="outlook.office365.com"; Ports=@(443)},
        @{Name="Microsoft Login"; Host="login.microsoftonline.com"; Ports=@(443)},
        @{Name="Google Accounts"; Host="accounts.google.com"; Ports=@(443)},
        @{Name="Google DNS"; Host="dns.google"; Ports=@(443)}
    )

    foreach ($Target in $Targets) {
        foreach ($Port in $Target.Ports) {
            "Testing $($Target.Name): $($Target.Host):$Port"
            Test-NetConnection $Target.Host -Port $Port -InformationLevel Detailed
            ""
        }
    }

    "Proxy Settings:"
    netsh winhttp show proxy
    ""
    "Hosts File:"
    Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    ""
    "Enabled Windows Firewall Allow Rules, sample first 100:"
    Get-NetFirewallRule -Enabled True -Action Allow -ErrorAction SilentlyContinue |
    Select-Object -First 100 DisplayName, Direction, Profile, Action
}

Save-Text "32G_Block_Path_Trace.txt" {
    "Block Path Trace - General"
    "=========================="
    ""
    "This section traces general internet reachability. For a specific blocked app/service, run interactive option 7 or add that target to the script."
    ""
    $TraceTargets = @(
        @{Name="Public DNS"; Host="8.8.8.8"; Port=53},
        @{Name="Google HTTPS"; Host="google.com"; Port=443},
        @{Name="Microsoft 365 HTTPS"; Host="outlook.office365.com"; Port=443}
    )

    "Default Gateway / Routes:"
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object InterfaceAlias, NextHop, RouteMetric, ifIndex
    ""

    foreach ($Target in $TraceTargets) {
        "Target: $($Target.Name) - $($Target.Host):$($Target.Port)"
        "DNS:"
        Resolve-DnsName $Target.Host -ErrorAction SilentlyContinue
        "Trace Route:"
        Test-NetConnection $Target.Host -TraceRoute -InformationLevel Detailed
        "TCP Port Test:"
        Test-NetConnection $Target.Host -Port $Target.Port -InformationLevel Detailed
        ""
    }

    "Interpretation Guide:"
    "- Gateway fail = local network, VLAN, switch, NIC, or IP issue"
    "- DNS fail = DNS server/filter issue"
    "- Trace dies at gateway = router/firewall issue"
    "- Trace dies after ISP hop = ISP/upstream/provider path issue"
    "- Trace reaches target but port fails = firewall, target service, or provider block"
}

Save-Text "32H_BSOD_Windows_Health_Diagnostics.txt" {
    "BSOD / Windows Health Diagnostics"
    "================================="
    ""
    "Recent BugCheck Events:"
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message
    ""
    "Recent Critical System Events:"
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=1} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message
    ""
    "Minidump Folder:"
    if (Test-Path "C:\Windows\Minidump") {
        Get-ChildItem "C:\Windows\Minidump" | Select-Object Name, LastWriteTime, Length
    } else {
        "No minidump folder found."
    }
    ""
    "Disk Health:"
    Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size
    ""
    "Repair note: This audit does not automatically run SFC or DISM repairs. Use the interactive menu or run manually with client approval."
}

# 32 Quick risk summary
Save-Text "32_Quick_Risk_Summary.txt" {
    $Admins = Get-LocalGroupMember Administrators
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $Firewall = Get-NetFirewallProfile
    $Defender = Get-MpComputerStatus
    try { $TPM = Get-Tpm -ErrorAction Stop } catch { $TPM = $null }
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

    "Quick Risk Summary"
    "=================="
    ""
    "Computer Name: $env:COMPUTERNAME"
    "Local Admin Count: $($Admins.Count)"
    "RDP Enabled: $(if ($RDP.fDenyTSConnections -eq 0) { 'Yes' } else { 'No' })"
    "Defender Antivirus Enabled: $($Defender.AntivirusEnabled)"
    "Defender Real-Time Protection Enabled: $($Defender.RealTimeProtectionEnabled)"
    "TPM Present: $(if ($TPM) { $TPM.TpmPresent } else { 'Unknown' })"
    "TPM Ready: $(if ($TPM) { $TPM.TpmReady } else { 'Unknown' })"
    "Secure Boot Enabled: $SecureBoot"
    ""
    "Firewall Profiles:"
    $Firewall | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    ""
    "Password Policy:"
    net accounts
}
# 33 Executive Findings Generator
Save-Text "33_Executive_Findings.txt" {
    $Findings = @()

    # Password policy
    $NetAccounts = net accounts
    $MinPasswordLengthLine = $NetAccounts | Where-Object { $_ -match "Minimum password length" }
    $MinPasswordLength = 0
    if ($MinPasswordLengthLine -match "(\d+)") { $MinPasswordLength = [int]$Matches[1] }

    if ($MinPasswordLength -lt 12) {
        $Findings += [PSCustomObject]@{
            Severity = "HIGH"
            Finding = "Weak password policy"
            Evidence = "Minimum password length is $MinPasswordLength"
            Recommendation = "Set minimum password length to 12-14 characters."
        }
    }

    # Local admins
    $Admins = Get-LocalGroupMember Administrators
    if ($Admins.Count -gt 3) {
        $Findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Finding = "Too many local administrators"
            Evidence = "$($Admins.Count) local admin accounts found"
            Recommendation = "Limit local administrator access to required IT/admin accounts only."
        }
    }

    # RDP
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    if ($RDP.fDenyTSConnections -eq 0) {
        $Findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Finding = "Remote Desktop is enabled"
            Evidence = "RDP connections are allowed"
            Recommendation = "Disable RDP unless required. If required, restrict access and avoid exposing it to the internet."
        }
    }

    # Defender
    $Defender = Get-MpComputerStatus
    if ($Defender.AntivirusEnabled -ne $true -or $Defender.RealTimeProtectionEnabled -ne $true) {
        $Findings += [PSCustomObject]@{
            Severity = "HIGH"
            Finding = "Microsoft Defender protection issue"
            Evidence = "AntivirusEnabled=$($Defender.AntivirusEnabled), RealTimeProtectionEnabled=$($Defender.RealTimeProtectionEnabled)"
            Recommendation = "Enable antivirus and real-time protection."
        }
    }

    # Firewall
    $FirewallProfiles = Get-NetFirewallProfile
    foreach ($Profile in $FirewallProfiles) {
        if ($Profile.Enabled -ne $true) {
            $Findings += [PSCustomObject]@{
                Severity = "HIGH"
                Finding = "Windows Firewall disabled"
                Evidence = "$($Profile.Name) firewall profile is disabled"
                Recommendation = "Enable Windows Firewall on all profiles."
            }
        }
    }

    # BitLocker
    try {
        $BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($BitLocker.ProtectionStatus -ne "On") {
            $Findings += [PSCustomObject]@{
                Severity = "HIGH"
                Finding = "BitLocker protection is not enabled"
                Evidence = "C: ProtectionStatus=$($BitLocker.ProtectionStatus)"
                Recommendation = "Enable BitLocker on business workstations."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Finding = "BitLocker status could not be verified"
            Evidence = $_.Exception.Message
            Recommendation = "Manually verify drive encryption status."
        }
    }

    # Secure Boot
    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($SecureBoot -ne $true) {
            $Findings += [PSCustomObject]@{
                Severity = "MEDIUM"
                Finding = "Secure Boot is disabled"
                Evidence = "Confirm-SecureBootUEFI returned False"
                Recommendation = "Enable Secure Boot in BIOS/UEFI where supported."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity = "LOW"
            Finding = "Secure Boot status could not be verified"
            Evidence = $_.Exception.Message
            Recommendation = "Manually verify Secure Boot status in BIOS/UEFI."
        }
    }

    if ($Findings.Count -eq 0) {
        "No major automated findings detected."
    }
    else {
        "Executive Findings"
        "=================="
        ""
        foreach ($Finding in $Findings) {
            "Severity: $($Finding.Severity)"
            "Finding: $($Finding.Finding)"
            "Evidence: $($Finding.Evidence)"
            "Recommendation: $($Finding.Recommendation)"
            ""
        }
    }
}
# Summary file
$SummaryPath = Join-Path $ReportFolder "00_READ_ME_Summary.txt"

@"
Client PC Audit Complete

Computer: $ComputerName
Date: $(Get-Date)
Report Folder: $ReportFolder

Review these first:
1. 01_Computer_Info.csv
2. 07_Local_Users.csv
3. 08_Local_Admins.txt
4. 08A_Local_Admin_Count.csv
5. 09_Password_Policy.txt
6. 10_BitLocker_Status.txt
7. 11_Defender_Status.csv
8. 12_Firewall_Profiles.csv
9. 13_RDP_Status.csv
10. 14_Installed_Software.csv
11. 16_IP_DNS_Gateway.txt
12. 21_Windows11_Compatibility_Clues.csv
13. 23_Windows_Update_Status.txt
14. 24_Windows_Activation_Status.csv
15. 32_Quick_Risk_Summary.txt
16. 32A_Network_Diagnostics.txt
17. 32B_DNS_Diagnostics.txt
18. 32C_DHCP_Lease_Check.csv
19. 32D_Static_IP_Diagnostics.txt
20. 32E_VoIP_Diagnostics.txt
21. 32F_Connectivity_Allowlist_Checker.txt
22. 32G_Block_Path_Trace.txt
23. 32H_BSOD_Windows_Health_Diagnostics.txt
24. 33_Executive_Findings.txt

Router note:
PowerShell usually cannot perfectly identify router brand from a client PC.
This script checks default gateway, ARP table, and gateway web headers.
For real router identification, physically inspect the router/firewall or log into the admin interface with permission.

This script is read-only and does not intentionally change system settings.
"@ | Out-File -FilePath $SummaryPath -Encoding UTF8



# 34 Office-free report bundle: HTML, Google Sheets/AppSheet index, JSON, ZIP
# This section does NOT use Microsoft Excel/Office COM objects.
# Outputs:
# - 00_Audit_Report.html opens in any browser
# - 00_AppSheet_Upload_Index.csv can be imported to Google Sheets/AppSheet as a file manifest
# - Individual CSV files open in Microsoft Excel, Google Sheets, LibreOffice, etc.
# - 00_Raw_Report_Manifest.json is raw machine-readable metadata
# - A ZIP bundle is created for easy upload/copy if Compress-Archive exists

function Convert-FileToHtmlSection {
    param(
        [string]$Path,
        [string]$Title
    )

    $Extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $SafeTitle = [System.Net.WebUtility]::HtmlEncode($Title)
    $FileName = [System.IO.Path]::GetFileName($Path)
    $SafeFileName = [System.Net.WebUtility]::HtmlEncode($FileName)

    try {
        if ($Extension -eq ".csv") {
            $Rows = Import-Csv -Path $Path -ErrorAction Stop
            if ($Rows.Count -eq 0) {
                return "<section><h2>$SafeTitle</h2><p><a href='./$SafeFileName'>$SafeFileName</a></p><p>No rows found.</p></section>"
            }
            $Fragment = $Rows | ConvertTo-Html -Fragment
            return "<section><h2>$SafeTitle</h2><p><a href='./$SafeFileName'>$SafeFileName</a></p>$Fragment</section>"
        }
        else {
            $Text = Get-Content -Path $Path -Raw -ErrorAction Stop
            $SafeText = [System.Net.WebUtility]::HtmlEncode($Text)
            return "<section><h2>$SafeTitle</h2><p><a href='./$SafeFileName'>$SafeFileName</a></p><pre>$SafeText</pre></section>"
        }
    }
    catch {
        $Err = [System.Net.WebUtility]::HtmlEncode($_.Exception.Message)
        return "<section><h2>$SafeTitle</h2><p class='bad'>Could not render file: $Err</p></section>"
    }
}

$AllReportFiles = Get-ChildItem -Path $ReportFolder -File | Sort-Object Name

$Manifest = $AllReportFiles | ForEach-Object {
    [PSCustomObject]@{
        ComputerName = $ComputerName
        AuditTimestamp = $TimeStamp
        FileName = $_.Name
        FileType = $_.Extension.TrimStart('.').ToUpper()
        FullPath = $_.FullName
        RelativePath = $_.Name
        SizeKB = [math]::Round($_.Length / 1KB, 2)
        SuggestedUse = switch -Wildcard ($_.Name) {
            "00_READ_ME*" { "Start here"; break }
            "00_Audit_Report.html" { "Browser-readable complete report"; break }
            "01_Computer_Info.csv" { "Google Sheets / Excel import"; break }
            "07_Local_Users.csv" { "Google Sheets / Excel import"; break }
            "08A_Local_Admin_Count.csv" { "Google Sheets / Excel import"; break }
            "11_Defender_Status.csv" { "Google Sheets / Excel import"; break }
            "12_Firewall_Profiles.csv" { "Google Sheets / Excel import"; break }
            "13_RDP_Status.csv" { "Google Sheets / Excel import"; break }
            "21_Windows11_Compatibility_Clues.csv" { "Google Sheets / Excel import"; break }
            "33_Executive_Findings.txt" { "Client-facing findings draft"; break }
            "*.csv" { "Spreadsheet import"; break }
            "*.txt" { "Plain text evidence"; break }
            default { "Reference" }
        }
    }
}

$ManifestCsv = Join-Path $ReportFolder "00_AppSheet_Upload_Index.csv"
$Manifest | Export-Csv -Path $ManifestCsv -NoTypeInformation -Encoding UTF8

$ManifestJson = Join-Path $ReportFolder "00_Raw_Report_Manifest.json"
$Manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $ManifestJson -Encoding UTF8

$GoogleGuide = Join-Path $ReportFolder "00_Google_Sheets_AppSheet_Guide.txt"
@"
Google Sheets / AppSheet / Excel Use
====================================

This audit does NOT require Microsoft Office on the client computer. All output is saved under Desktop\ArchesCyberAudit.

Best files to open first:
1. 00_Audit_Report.html
   - Opens in any browser.
   - Best for quick review on any computer.

2. 00_AppSheet_Upload_Index.csv
   - Import this into Google Sheets as a file manifest.
   - Good for linking this audit folder/bundle to AppSheet.

3. Individual CSV files
   - Open in Microsoft Excel, Google Sheets, LibreOffice, or AppSheet.
   - Upload CSV files to Google Drive, then import into Google Sheets.

Suggested AppSheet workflow:
1. Upload the Desktop\ArchesCyberAudit report subfolder or ZIP to the client folder in Google Drive.
2. Upload/import 00_AppSheet_Upload_Index.csv into a Google Sheet table named AuditFiles.
3. Import important CSVs as separate tabs/tables, especially:
   - 01_Computer_Info.csv
   - 07_Local_Users.csv
   - 08A_Local_Admin_Count.csv
   - 11_Defender_Status.csv
   - 12_Firewall_Profiles.csv
   - 13_RDP_Status.csv
   - 14_Installed_Software.csv
   - 21_Windows11_Compatibility_Clues.csv
   - 24_Windows_Activation_Status.csv
4. In AppSheet, connect the Google Sheet as a data source.

Microsoft Office note:
- These CSV files can open in Excel if Excel is installed.
- Excel is NOT required to generate the report.
- HTML/TXT/JSON outputs are included so the report remains readable anywhere.
"@ | Out-File -FilePath $GoogleGuide -Encoding UTF8

# Refresh manifest after adding generated support files
$AllReportFiles = Get-ChildItem -Path $ReportFolder -File | Sort-Object Name

$ImportantFiles = @(
    "00_READ_ME_Summary.txt",
    "32_Quick_Risk_Summary.txt",
    "32A_Network_Diagnostics.txt",
    "32B_DNS_Diagnostics.txt",
    "32C_DHCP_Lease_Check.csv",
    "32D_Static_IP_Diagnostics.txt",
    "32E_VoIP_Diagnostics.txt",
    "32F_Connectivity_Allowlist_Checker.txt",
    "32G_Block_Path_Trace.txt",
    "32H_BSOD_Windows_Health_Diagnostics.txt",
    "33_Executive_Findings.txt",
    "01_Computer_Info.csv",
    "07_Local_Users.csv",
    "08A_Local_Admin_Count.csv",
    "11_Defender_Status.csv",
    "12_Firewall_Profiles.csv",
    "13_RDP_Status.csv",
    "14_Installed_Software.csv",
    "21_Windows11_Compatibility_Clues.csv",
    "24_Windows_Activation_Status.csv",
    "25_SMB_Shares.csv",
    "26_Listening_Ports.csv",
    "27_Listening_Port_Processes.csv"
)

$Sections = foreach ($FileName in $ImportantFiles) {
    $FilePath = Join-Path $ReportFolder $FileName
    if (Test-Path $FilePath) {
        Convert-FileToHtmlSection -Path $FilePath -Title $FileName
    }
}

$FileLinks = $AllReportFiles | ForEach-Object {
    $SafeName = [System.Net.WebUtility]::HtmlEncode($_.Name)
    "<li><a href='./$SafeName'>$SafeName</a> - $([math]::Round($_.Length / 1KB, 2)) KB</li>"
}

$HtmlPath = Join-Path $ReportFolder "00_Audit_Report.html"
$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Client PC Audit Report - $ComputerName</title>
<style>
body { font-family: Arial, sans-serif; margin: 30px; color: #111827; }
h1 { margin-bottom: 0; }
h2 { margin-top: 32px; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 24px 0; font-size: 13px; }
th, td { border: 1px solid #d1d5db; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f3f4f6; }
pre { background: #f9fafb; border: 1px solid #d1d5db; padding: 12px; overflow-x: auto; white-space: pre-wrap; }
.meta { color: #4b5563; }
.good { color: #047857; font-weight: bold; }
.bad { color: #b91c1c; font-weight: bold; }
.note { background: #fffbeb; border: 1px solid #f59e0b; padding: 10px; }
a { color: #1d4ed8; }
</style>
</head>
<body>
<h1>Client PC Audit Report</h1>
<p class="meta"><strong>Computer:</strong> $ComputerName<br>
<strong>Generated:</strong> $(Get-Date)<br>
<strong>Report Folder:</strong> $ReportFolder</p>

<div class="note">
<strong>Office-free:</strong> This report was generated without Microsoft Excel or Office. Open this HTML file in any browser. CSV files can be opened later in Microsoft Excel, Google Sheets, LibreOffice, or connected to AppSheet.
</div>

<h2>All Generated Files</h2>
<ul>
$($FileLinks -join "`n")
</ul>

$($Sections -join "`n")

</body>
</html>
"@
$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

# Try to create a ZIP bundle for easy upload to Google Drive/AppSheet workflow
try {
    $ZipPath = Join-Path $AuditRoot ("ArchesCyberAudit_" + $ComputerName + "_" + $TimeStamp + ".zip")
    if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
        Compress-Archive -Path (Join-Path $ReportFolder "*") -DestinationPath $ZipPath -Force
        "ZIP bundle created: $ZipPath" | Out-File -FilePath (Join-Path $ReportFolder "00_ZIP_Bundle_Path.txt") -Encoding UTF8
    }
}
catch {
    "ZIP bundle could not be created: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $ReportFolder "00_ZIP_Bundle_Path.txt") -Encoding UTF8
}

function Show-DiagnosticsMenu {
    Write-Host ""
    Write-Host "=== Arches Cyber Diagnostics ==="
    Write-Host "1. Run Network Diagnostics"
    Write-Host "2. Run DNS Diagnostics"
    Write-Host "3. Run Static IP Diagnostics"
    Write-Host "4. Run DHCP Lease Check"
    Write-Host "5. Run VoIP Diagnostics"
    Write-Host "6. Run Connectivity Allowlist Checker"
    Write-Host "7. Run Block Path Trace"
    Write-Host "8. Run BSOD / Windows Health Check"
    Write-Host "9. Exit"
}

# Copy finished report back to the launcher/USB folder when possible
try {
    $ScriptRoot = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
        $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    }

    # If the PS1 lives in a resources folder, copy reports to the parent folder.
    # Example: USB:\ArchesCyberAudit\resources\Client-PC-Audit-ArchesCyberAudit.ps1
    # Copy destination: USB:\ArchesCyberAudit\CollectedReports\...
    if ((Split-Path -Leaf $ScriptRoot) -ieq "resources") {
        $LauncherRoot = Split-Path -Parent $ScriptRoot
    }
    else {
        $LauncherRoot = $ScriptRoot
    }

    $CollectedRoot = Join-Path $LauncherRoot "CollectedReports"
    $UsbCopyFolder = Join-Path $CollectedRoot (Split-Path -Leaf $ReportFolder)

    New-Item -ItemType Directory -Path $CollectedRoot -Force | Out-Null

    if (Test-Path $UsbCopyFolder) {
        Remove-Item -Path $UsbCopyFolder -Recurse -Force
    }

    Copy-Item -Path $ReportFolder -Destination $UsbCopyFolder -Recurse -Force

    if ($ZipPath -and (Test-Path $ZipPath)) {
        Copy-Item -Path $ZipPath -Destination $CollectedRoot -Force
    }

    "Client desktop report: $ReportFolder`r`nLauncher/USB copy: $UsbCopyFolder`r`nCollected reports root: $CollectedRoot" |
        Out-File -FilePath (Join-Path $ReportFolder "00_Report_Copy_Locations.txt") -Encoding UTF8

    Write-Host "Report also copied to:" -ForegroundColor Green
    Write-Host $UsbCopyFolder -ForegroundColor Cyan
}
catch {
    $CopyError = "Report copy back to launcher/USB failed: $($_.Exception.Message)"
    $CopyError | Out-File -FilePath (Join-Path $ReportFolder "00_USB_Copy_Error.txt") -Encoding UTF8
    Write-Host $CopyError -ForegroundColor Yellow
}

if ($InteractiveDiagnostics) {
    do {
        Show-DiagnosticsMenu
        $choice = Read-Host "Choose an option"

        switch ($choice) {
            "1" { Run-NetworkDiagnostics }
            "2" { Run-DnsDiagnostics }
            "3" { Run-StaticIpDiagnostics }
            "4" { Run-DhcpLeaseCheck }
            "5" { Run-VoipDiagnostics }
            "6" { Run-AllowlistChecker }
            "7" { Run-BlockPathTrace }
            "8" { Run-WindowsHealthDiagnostics }
            "9" { Write-Host "Exiting diagnostics." }
            default { Write-Host "Invalid option." }
        }
    } while ($choice -ne "9")
}


Write-Host ""
Write-Host "Audit complete." -ForegroundColor Green
Write-Host "Reports saved to:"
Write-Host $ReportFolder -ForegroundColor Cyan
