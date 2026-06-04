# Client-PC-Audit-XLSX.ps1
# Read-only workstation assessment script
# Outputs one Excel workbook with one tab per audit section
# Run as Administrator
# Requires Microsoft Excel installed on the machine

$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ComputerName = $env:COMPUTERNAME

# Save output to the current directory where the script is run from
$OutputBase = (Get-Location).Path

$ReportFolder = Join-Path $OutputBase "ClientAudit_$ComputerName`_$TimeStamp"
$WorkbookPath = Join-Path $ReportFolder "Client_PC_Audit_$ComputerName`_$TimeStamp.xlsx"

New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null

# -----------------------------
# Excel setup
# -----------------------------

try {
    $Excel = New-Object -ComObject Excel.Application
}
catch {
    Write-Host "ERROR: Microsoft Excel does not appear to be installed, or Excel COM automation is unavailable." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

$Excel.Visible = $false
$Excel.DisplayAlerts = $false

$Workbook = $Excel.Workbooks.Add()
$UsedSheetNames = @{}

function Get-SafeSheetName {
    param ([string]$Name)

    # Excel sheet names max 31 chars and cannot contain: \ / ? * [ ] :
    $Safe = $Name -replace '[\\\/\?\*\[\]\:]', '_'

    if ($Safe.Length -gt 31) {
        $Safe = $Safe.Substring(0, 31)
    }

    $Base = $Safe
    $Counter = 1

    while ($UsedSheetNames.ContainsKey($Safe)) {
        $Suffix = "_$Counter"
        $MaxBaseLength = 31 - $Suffix.Length

        if ($Base.Length -gt $MaxBaseLength) {
            $Safe = $Base.Substring(0, $MaxBaseLength) + $Suffix
        }
        else {
            $Safe = $Base + $Suffix
        }

        $Counter++
    }

    $UsedSheetNames[$Safe] = $true
    return $Safe
}

function New-AuditSheet {
    param ([string]$Name)

    $Sheet = $Workbook.Worksheets.Add()
    $Sheet.Name = Get-SafeSheetName $Name
    return $Sheet
}

function Format-AuditSheet {
    param ($Sheet)

    try {
        $UsedRange = $Sheet.UsedRange

        if ($UsedRange -ne $null) {
            $UsedRange.Columns.AutoFit() | Out-Null
            $UsedRange.Rows.AutoFit() | Out-Null

            # Bold first row
            $Sheet.Rows.Item(1).Font.Bold = $true

            # Freeze top row
            $Sheet.Activate()
            $Excel.ActiveWindow.SplitRow = 1
            $Excel.ActiveWindow.FreezePanes = $true
        }
    }
    catch {
        # Formatting failure should not break audit
    }
}

function Add-ObjectSheet {
    param (
        [string]$SheetName,
        [scriptblock]$Command
    )

    $Sheet = New-AuditSheet $SheetName

    try {
        $Data = @(& $Command)

        if (-not $Data -or $Data.Count -eq 0) {
            $Sheet.Cells.Item(1, 1) = "Message"
            $Sheet.Cells.Item(2, 1) = "No data returned."
            Format-AuditSheet $Sheet
            return
        }

        # Collect all unique property names across all returned objects
        $Headers = New-Object System.Collections.Generic.List[string]

        foreach ($Item in $Data) {
            foreach ($Prop in $Item.PSObject.Properties) {
                if (-not $Headers.Contains($Prop.Name)) {
                    $Headers.Add($Prop.Name)
                }
            }
        }

        if ($Headers.Count -eq 0) {
            $Sheet.Cells.Item(1, 1) = "Output"
            $Row = 2

            foreach ($Item in $Data) {
                $Sheet.Cells.Item($Row, 1) = [string]$Item
                $Row++
            }

            Format-AuditSheet $Sheet
            return
        }

        # Write headers
        for ($Column = 0; $Column -lt $Headers.Count; $Column++) {
            $Sheet.Cells.Item(1, $Column + 1) = $Headers[$Column]
        }

        # Write data
        $Row = 2

        foreach ($Item in $Data) {
            for ($Column = 0; $Column -lt $Headers.Count; $Column++) {
                $Header = $Headers[$Column]
                $Value = $Item.PSObject.Properties[$Header].Value

                if ($null -eq $Value) {
                    $CellValue = ""
                }
                elseif ($Value -is [array]) {
                    $CellValue = ($Value -join "; ")
                }
                else {
                    $CellValue = [string]$Value
                }

                $Sheet.Cells.Item($Row, $Column + 1) = $CellValue
            }

            $Row++
        }
    }
    catch {
        $Sheet.Cells.Item(1, 1) = "ERROR"
        $Sheet.Cells.Item(2, 1) = $_.Exception.Message
    }

    Format-AuditSheet $Sheet
}

function Add-TextSheet {
    param (
        [string]$SheetName,
        [scriptblock]$Command
    )

    $Sheet = New-AuditSheet $SheetName

    try {
        $Output = @(& $Command)

        $Sheet.Cells.Item(1, 1) = "Output"

        if (-not $Output -or $Output.Count -eq 0) {
            $Sheet.Cells.Item(2, 1) = "No output returned."
        }
        else {
            $Row = 2

            foreach ($Line in $Output) {
                $Sheet.Cells.Item($Row, 1) = [string]$Line
                $Row++
            }
        }
    }
    catch {
        $Sheet.Cells.Item(1, 1) = "ERROR"
        $Sheet.Cells.Item(2, 1) = $_.Exception.Message
    }

    Format-AuditSheet $Sheet
}

# Remove default sheets after we create our own summary later
# But Excel needs at least one sheet, so we will reuse the first default sheet for the summary.

$SummarySheet = $Workbook.Worksheets.Item(1)
$SummarySheet.Name = Get-SafeSheetName "00_READ_ME_Summary"

$SummaryLines = @(
    "Client PC Audit Complete",
    "",
    "Computer: $ComputerName",
    "Date: $(Get-Date)",
    "Report Folder: $ReportFolder",
    "Workbook: $WorkbookPath",
    "",
    "Review these tabs first:",
    "01_Computer_Info",
    "07_Local_Users",
    "08_Local_Admins",
    "08A_Admin_Count",
    "09_Password_Policy",
    "10_BitLocker_Status",
    "11_Defender_Status",
    "12_Firewall_Profiles",
    "13_RDP_Status",
    "14_Installed_Software",
    "16_IP_DNS_Gateway",
    "21_Win11_Compatibility",
    "23_Windows_Update",
    "24_Activation_Status",
    "32_Quick_Risk_Summary",
    "33_Executive_Findings",
    "",
    "Router note:",
    "PowerShell usually cannot perfectly identify router brand from a client PC.",
    "This script checks default gateway, ARP table, and gateway web headers.",
    "For real router identification, physically inspect the router/firewall or log into the admin interface with permission.",
    "",
    "This script is read-only and does not intentionally change system settings."
)

$SummarySheet.Cells.Item(1, 1) = "Summary"

$Row = 2
foreach ($Line in $SummaryLines) {
    $SummarySheet.Cells.Item($Row, 1) = $Line
    $Row++
}

Format-AuditSheet $SummarySheet

# Delete extra default sheets
while ($Workbook.Worksheets.Count -gt 1) {
    $LastSheet = $Workbook.Worksheets.Item($Workbook.Worksheets.Count)

    if ($LastSheet.Name -ne $SummarySheet.Name) {
        $LastSheet.Delete()
    }
    else {
        break
    }
}

# -----------------------------
# Audit sections
# -----------------------------

# 01 Basic computer info
Add-ObjectSheet "01_Computer_Info" {
    $CI = Get-ComputerInfo
    $Reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $CurrentBuildNumber = [int]$Reg.CurrentBuild

    $FriendlyOS = if ($CurrentBuildNumber -ge 22000) {
        "Windows 11"
    }
    elseif ($CurrentBuildNumber -ge 10240) {
        "Windows 10"
    }
    else {
        "Older than Windows 10"
    }

    [PSCustomObject]@{
        CsName                = $CI.CsName

        FriendlyOS            = $FriendlyOS
        OsName                = $CI.OsName
        WindowsProductName    = $CI.WindowsProductName
        ProductName_Registry  = $Reg.ProductName
        EditionID             = $Reg.EditionID
        DisplayVersion        = $Reg.DisplayVersion
        ReleaseId             = $Reg.ReleaseId

        CurrentBuild          = $Reg.CurrentBuild
        UBR                   = $Reg.UBR
        FullBuild             = "$($Reg.CurrentBuild).$($Reg.UBR)"
        WindowsVersion        = $CI.WindowsVersion
        OsBuildNumber         = $CI.OsBuildNumber
        OsArchitecture        = $CI.OsArchitecture

        CsManufacturer        = $CI.CsManufacturer
        CsModel               = $CI.CsModel
        CsDomain              = $CI.CsDomain
        CsWorkgroup           = $CI.CsWorkgroup
        CsUserName            = $CI.CsUserName

        BiosFirmwareType      = $CI.BiosFirmwareType
        SecureBootState       = $CI.SecureBootState
        CsTotalPhysicalMemory = $CI.CsTotalPhysicalMemory
        OsLastBootUpTime      = $CI.OsLastBootUpTime
    }
}

# 02 Serial / BIOS
Add-ObjectSheet "02_BIOS_Serial" {
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate
}

# 03 CPU
Add-ObjectSheet "03_CPU" {
    Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
}

# 04 RAM
Add-ObjectSheet "04_RAM" {
    Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, PartNumber, Capacity, Speed, ConfiguredClockSpeed, DeviceLocator
}

# 05 Storage disks
Add-ObjectSheet "05_Storage_Disks" {
    Get-CimInstance Win32_DiskDrive | Select-Object Model, SerialNumber, MediaType, InterfaceType, Size
}

# 06 Storage volumes
Add-ObjectSheet "06_Storage_Volumes" {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, Size, SizeRemaining
}

# 07 Users
Add-ObjectSheet "07_Local_Users" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, UserMayChangePassword, PasswordExpires, Description
}

# 08 Admins
Add-ObjectSheet "08_Local_Admins" {
    Get-LocalGroupMember Administrators | Select-Object Name, ObjectClass, PrincipalSource, SID
}

# 08A Admin count
Add-ObjectSheet "08A_Admin_Count" {
    $Admins = Get-LocalGroupMember Administrators

    [PSCustomObject]@{
        ComputerName    = $env:COMPUTERNAME
        LocalAdminCount = $Admins.Count
        AdminNames      = ($Admins.Name -join "; ")
    }
}

# 09 Password policy
Add-TextSheet "09_Password_Policy" {
    net accounts
}

# 10 BitLocker
Add-ObjectSheet "10_BitLocker_Status" {
    try {
        Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod, LockStatus
    }
    catch {
        [PSCustomObject]@{
            Status  = "Get-BitLockerVolume failed"
            Message = $_.Exception.Message
        }

        try {
            manage-bde -status | ForEach-Object {
                [PSCustomObject]@{
                    Status  = "manage-bde fallback"
                    Message = $_
                }
            }
        }
        catch {
            [PSCustomObject]@{
                Status  = "manage-bde also failed"
                Message = $_.Exception.Message
            }
        }
    }
}

# 11 Defender
Add-ObjectSheet "11_Defender_Status" {
    Get-MpComputerStatus | Select-Object `
        AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
        BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled,
        AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime
}

# 11A Defender threats
Add-ObjectSheet "11A_Defender_Threats" {
    Get-MpThreatDetection
}

# 12 Firewall
Add-ObjectSheet "12_Firewall_Profiles" {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, NotifyOnListen
}

# 13 RDP
Add-ObjectSheet "13_RDP_Status" {
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'

    [PSCustomObject]@{
        ComputerName           = $env:COMPUTERNAME
        RDP_Connections_Denied = $RDP.fDenyTSConnections
        RDP_Enabled            = if ($RDP.fDenyTSConnections -eq 0) { "Yes" } else { "No" }
    }
}

# 14 Installed software
Add-ObjectSheet "14_Installed_Software" {
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName
}

# 15 Network adapters
Add-ObjectSheet "15_Network_Adapters" {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, MediaType
}

# 16 IP / DNS / gateway
Add-ObjectSheet "16_IP_DNS_Gateway" {
    Get-NetIPConfiguration | ForEach-Object {
        [PSCustomObject]@{
            InterfaceAlias = $_.InterfaceAlias
            InterfaceIndex = $_.InterfaceIndex
            IPv4Address    = ($_.IPv4Address.IPAddress -join "; ")
            IPv6Address    = ($_.IPv6Address.IPAddress -join "; ")
            IPv4Gateway    = ($_.IPv4DefaultGateway.NextHop -join "; ")
            IPv6Gateway    = ($_.IPv6DefaultGateway.NextHop -join "; ")
            DNSServers     = ($_.DNSServer.ServerAddresses -join "; ")
        }
    }
}

# 17 DNS settings
Add-ObjectSheet "17_DNS_Settings" {
    Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses
}

# 18 Default gateway
Add-ObjectSheet "18_Default_Gateway" {
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object InterfaceAlias, NextHop, RouteMetric, ifIndex
}

# 19 ARP table
Add-TextSheet "19_ARP_Table" {
    arp -a
}

# 20 Router clues
Add-ObjectSheet "20_Router_Clues" {
    $Results = @()
    $Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop

    $Results += [PSCustomObject]@{
        Check   = "Default Gateway"
        Result  = $Gateway
        Details = ""
    }

    if ($Gateway) {
        try {
            $HttpResult = Invoke-WebRequest -Uri "http://$Gateway" -UseBasicParsing -TimeoutSec 5

            $Results += [PSCustomObject]@{
                Check   = "HTTP gateway check"
                Result  = "$($HttpResult.StatusCode) $($HttpResult.StatusDescription)"
                Details = (($HttpResult.Headers.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "; ")
            }
        }
        catch {
            $Results += [PSCustomObject]@{
                Check   = "HTTP gateway check"
                Result  = "Failed"
                Details = $_.Exception.Message
            }
        }

        try {
            $HttpsResult = Invoke-WebRequest -Uri "https://$Gateway" -UseBasicParsing -TimeoutSec 5

            $Results += [PSCustomObject]@{
                Check   = "HTTPS gateway check"
                Result  = "$($HttpsResult.StatusCode) $($HttpsResult.StatusDescription)"
                Details = (($HttpsResult.Headers.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "; ")
            }
        }
        catch {
            $Results += [PSCustomObject]@{
                Check   = "HTTPS gateway check"
                Result  = "Failed"
                Details = $_.Exception.Message
            }
        }
    }

    $Results
}

# 21 Windows 11 compatibility clues
Add-ObjectSheet "21_Win11_Compatibility" {
    try {
        $TPM = Get-Tpm -ErrorAction Stop
        $TPM_Present = $TPM.TpmPresent
        $TPM_Ready = $TPM.TpmReady
        $TPM_Enabled = $TPM.TpmEnabled
        $TPM_Activated = $TPM.TpmActivated
        $TPM_Error = ""
    }
    catch {
        $TPM_Present = "Unknown"
        $TPM_Ready = "Unknown"
        $TPM_Enabled = "Unknown"
        $TPM_Activated = "Unknown"
        $TPM_Error = $_.Exception.Message
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        $SecureBoot_Error = ""
    }
    catch {
        $SecureBoot = "Unknown"
        $SecureBoot_Error = $_.Exception.Message
    }

    $CPU = Get-CimInstance Win32_Processor | Select-Object -First 1
    $RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $Disk = Get-CimInstance Win32_DiskDrive | Select-Object -First 1
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    $ComputerInfo = Get-ComputerInfo

    [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        CPU                = $CPU.Name
        CPU_Cores          = $CPU.NumberOfCores
        RAM_GB             = $RAM
        Disk_Size_GB       = [math]::Round($Disk.Size / 1GB, 2)
        TPM_Present        = $TPM_Present
        TPM_Ready          = $TPM_Ready
        TPM_Enabled        = $TPM_Enabled
        TPM_Activated      = $TPM_Activated
        TPM_Error          = $TPM_Error
        SecureBoot_Enabled = $SecureBoot
        SecureBoot_Error   = $SecureBoot_Error
        Firmware_Type      = $ComputerInfo.BiosFirmwareType
        OS_Architecture    = $ComputerInfo.OsArchitecture
        PartOfDomain       = $ComputerSystem.PartOfDomain
        Domain             = $ComputerSystem.Domain
    }
}

# 22 Last boot
Add-ObjectSheet "22_Last_Boot" {
    Get-CimInstance Win32_OperatingSystem | Select-Object CSName, LastBootUpTime, LocalDateTime
}

# 23 Windows Update
Add-ObjectSheet "23_Windows_Update" {
    $Results = @()

    try {
        $Service = Get-Service wuauserv

        $Results += [PSCustomObject]@{
            Section = "Windows Update Service"
            Name    = $Service.Name
            Status  = $Service.Status
            Details = $Service.DisplayName
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Section = "Windows Update Service"
            Name    = "ERROR"
            Status  = ""
            Details = $_.Exception.Message
        }
    }

    try {
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object {
            $Results += [PSCustomObject]@{
                Section = "Recent Windows Updates"
                Name    = $_.HotFixID
                Status  = $_.InstalledOn
                Details = $_.Description
            }
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Section = "Recent Windows Updates"
            Name    = "ERROR"
            Status  = ""
            Details = $_.Exception.Message
        }
    }

    try {
        $Policy = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue

        if ($Policy) {
            foreach ($Prop in $Policy.PSObject.Properties) {
                if ($Prop.Name -notmatch "^PS") {
                    $Results += [PSCustomObject]@{
                        Section = "Update Policy Registry Clues"
                        Name    = $Prop.Name
                        Status  = ""
                        Details = $Prop.Value
                    }
                }
            }
        }
        else {
            $Results += [PSCustomObject]@{
                Section = "Update Policy Registry Clues"
                Name    = "No policy key found"
                Status  = ""
                Details = ""
            }
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Section = "Update Policy Registry Clues"
            Name    = "ERROR"
            Status  = ""
            Details = $_.Exception.Message
        }
    }

    $Results
}

# 24 Activation status
Add-ObjectSheet "24_Activation_Status" {
    Get-CimInstance SoftwareLicensingProduct |
    Where-Object { $_.PartialProductKey } |
    Select-Object Name, Description, LicenseStatus, PartialProductKey
}

# 25 SMB shares
Add-ObjectSheet "25_SMB_Shares" {
    Get-SmbShare | Select-Object Name, Path, Description, ShareState, FolderEnumerationMode
}

# 26 Listening ports
Add-ObjectSheet "26_Listening_Ports" {
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
}

# 27 Listening port processes
Add-ObjectSheet "27_Port_Processes" {
    Get-NetTCPConnection -State Listen |
    ForEach-Object {
        $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            ProcessId    = $_.OwningProcess
            ProcessName  = $Process.ProcessName
        }
    }
}

# 28 Startup programs
Add-ObjectSheet "28_Startup_Programs" {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}

# 29 Security Center AV
Add-ObjectSheet "29_Security_Center_AV" {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    Select-Object displayName, pathToSignedProductExe, productState
}

# 30 Mapped drives
Add-ObjectSheet "30_Mapped_Drives" {
    Get-SmbMapping | Select-Object LocalPath, RemotePath, Status, UserName
}

# 31 Printers
Add-ObjectSheet "31_Printers" {
    Get-Printer | Select-Object Name, DriverName, PortName, Shared, Published, PrinterStatus
}

# 32 Quick risk summary
Add-ObjectSheet "32_Quick_Risk_Summary" {
    $Results = @()

    try {
        $Admins = Get-LocalGroupMember Administrators
        $AdminCount = $Admins.Count
    }
    catch {
        $AdminCount = "Error: $($_.Exception.Message)"
    }

    try {
        $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $RDPEnabled = if ($RDP.fDenyTSConnections -eq 0) { "Yes" } else { "No" }
    }
    catch {
        $RDPEnabled = "Error: $($_.Exception.Message)"
    }

    try {
        $Defender = Get-MpComputerStatus
        $DefenderAV = $Defender.AntivirusEnabled
        $DefenderRealtime = $Defender.RealTimeProtectionEnabled
    }
    catch {
        $DefenderAV = "Error: $($_.Exception.Message)"
        $DefenderRealtime = "Error: $($_.Exception.Message)"
    }

    try {
        $TPM = Get-Tpm -ErrorAction Stop
        $TPMPresent = $TPM.TpmPresent
        $TPMReady = $TPM.TpmReady
    }
    catch {
        $TPMPresent = "Unknown: $($_.Exception.Message)"
        $TPMReady = "Unknown: $($_.Exception.Message)"
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    }
    catch {
        $SecureBoot = "Unknown: $($_.Exception.Message)"
    }

    $Results += [PSCustomObject]@{ Item = "Computer Name"; Value = $env:COMPUTERNAME }
    $Results += [PSCustomObject]@{ Item = "Local Admin Count"; Value = $AdminCount }
    $Results += [PSCustomObject]@{ Item = "RDP Enabled"; Value = $RDPEnabled }
    $Results += [PSCustomObject]@{ Item = "Defender Antivirus Enabled"; Value = $DefenderAV }
    $Results += [PSCustomObject]@{ Item = "Defender Real-Time Protection Enabled"; Value = $DefenderRealtime }
    $Results += [PSCustomObject]@{ Item = "TPM Present"; Value = $TPMPresent }
    $Results += [PSCustomObject]@{ Item = "TPM Ready"; Value = $TPMReady }
    $Results += [PSCustomObject]@{ Item = "Secure Boot Enabled"; Value = $SecureBoot }

    try {
        $Firewall = Get-NetFirewallProfile

        foreach ($Profile in $Firewall) {
            $Results += [PSCustomObject]@{
                Item  = "Firewall Profile: $($Profile.Name)"
                Value = "Enabled=$($Profile.Enabled); Inbound=$($Profile.DefaultInboundAction); Outbound=$($Profile.DefaultOutboundAction)"
            }
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Item  = "Firewall Profiles"
            Value = "Error: $($_.Exception.Message)"
        }
    }

    try {
        $NetAccounts = net accounts

        foreach ($Line in $NetAccounts) {
            $Results += [PSCustomObject]@{
                Item  = "Password Policy"
                Value = $Line
            }
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Item  = "Password Policy"
            Value = "Error: $($_.Exception.Message)"
        }
    }

    $Results
}
# 33 Executive Findings
Add-ObjectSheet "33_Executive_Findings" {
    $Findings = @()

    # Password policy
    try {
        $NetAccounts = net accounts
        $MinPasswordLengthLine = $NetAccounts | Where-Object { $_ -match "Minimum password length" }
        $MinPasswordLength = ($MinPasswordLengthLine -replace "\D+", "")

        if ($MinPasswordLength -and [int]$MinPasswordLength -lt 12) {
            $Findings += [PSCustomObject]@{
                Severity       = "HIGH"
                Finding        = "Weak password policy"
                Evidence       = "Minimum password length is $MinPasswordLength"
                Recommendation = "Set minimum password length to 12-14 characters."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "LOW"
            Finding        = "Password policy could not be checked"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify local or domain password policy."
        }
    }

    # Local admins
    try {
        $Admins = Get-LocalGroupMember Administrators

        if ($Admins.Count -gt 3) {
            $Findings += [PSCustomObject]@{
                Severity       = "MEDIUM"
                Finding        = "Too many local administrators"
                Evidence       = "$($Admins.Count) local admin accounts found"
                Recommendation = "Limit local administrator access to required IT/admin accounts only."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "LOW"
            Finding        = "Local administrators could not be checked"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify local Administrators group membership."
        }
    }

    # RDP
    try {
        $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'

        if ($RDP.fDenyTSConnections -eq 0) {
            $Findings += [PSCustomObject]@{
                Severity       = "MEDIUM"
                Finding        = "Remote Desktop is enabled"
                Evidence       = "RDP connections are allowed"
                Recommendation = "Disable RDP unless required. If required, restrict access and avoid exposing it to the internet."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "LOW"
            Finding        = "RDP status could not be checked"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify Remote Desktop status."
        }
    }

    # Defender
    try {
        $Defender = Get-MpComputerStatus

        if ($Defender.AntivirusEnabled -ne $true -or $Defender.RealTimeProtectionEnabled -ne $true) {
            $Findings += [PSCustomObject]@{
                Severity       = "HIGH"
                Finding        = "Microsoft Defender protection issue"
                Evidence       = "AntivirusEnabled=$($Defender.AntivirusEnabled), RealTimeProtectionEnabled=$($Defender.RealTimeProtectionEnabled)"
                Recommendation = "Enable antivirus and real-time protection."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "MEDIUM"
            Finding        = "Microsoft Defender status could not be checked"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify antivirus and real-time protection status."
        }
    }

    # Firewall
    try {
        $FirewallProfiles = Get-NetFirewallProfile

        foreach ($Profile in $FirewallProfiles) {
            if ($Profile.Enabled -ne $true) {
                $Findings += [PSCustomObject]@{
                    Severity       = "HIGH"
                    Finding        = "Windows Firewall disabled"
                    Evidence       = "$($Profile.Name) firewall profile is disabled"
                    Recommendation = "Enable Windows Firewall on all profiles."
                }
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "MEDIUM"
            Finding        = "Windows Firewall status could not be checked"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify Windows Firewall status."
        }
    }

    # BitLocker
    try {
        $BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

        if ($BitLocker.ProtectionStatus -ne "On") {
            $Findings += [PSCustomObject]@{
                Severity       = "HIGH"
                Finding        = "BitLocker protection is not enabled"
                Evidence       = "C: ProtectionStatus=$($BitLocker.ProtectionStatus)"
                Recommendation = "Enable BitLocker on business workstations."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "MEDIUM"
            Finding        = "BitLocker status could not be verified"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify drive encryption status."
        }
    }

    # Secure Boot
    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

        if ($SecureBoot -ne $true) {
            $Findings += [PSCustomObject]@{
                Severity       = "MEDIUM"
                Finding        = "Secure Boot is disabled"
                Evidence       = "Confirm-SecureBootUEFI returned False"
                Recommendation = "Enable Secure Boot in BIOS/UEFI where supported."
            }
        }
    }
    catch {
        $Findings += [PSCustomObject]@{
            Severity       = "LOW"
            Finding        = "Secure Boot status could not be verified"
            Evidence       = $_.Exception.Message
            Recommendation = "Manually verify Secure Boot status in BIOS/UEFI."
        }
    }

    if ($Findings.Count -eq 0) {
        [PSCustomObject]@{
            Severity       = "INFO"
            Finding        = "No major automated findings detected"
            Evidence       = ""
            Recommendation = ""
        }
    }
    else {
        $Findings
    }
}

# -----------------------------
# Final workbook formatting/save
# -----------------------------

try {
    # Sort worksheets numerically by the number at the beginning of the sheet name
    # Example: 00_READ_ME_Summary, 01_Computer_Info, 02_BIOS_Serial, ... 33_Executive_Findings

    $SortedSheets = @()

    foreach ($Sheet in $Workbook.Worksheets) {
        $SheetName = $Sheet.Name

        if ($SheetName -match '^(\d+)') {
            $SortNumber = [int]$Matches[1]
        }
        else {
            # Put sheets without a leading number at the end
            $SortNumber = 9999
        }

        $SortedSheets += [PSCustomObject]@{
            Name       = $SheetName
            SortNumber = $SortNumber
        }
    }

    $SortedSheets = $SortedSheets | Sort-Object SortNumber, Name

    # Move in reverse sorted order to the front.
    # This creates final left-to-right order: 00, 01, 02, 03...
    for ($i = $SortedSheets.Count - 1; $i -ge 0; $i--) {
        $SheetName = $SortedSheets[$i].Name

        try {
            $Sheet = $Workbook.Worksheets.Item($SheetName)
            $Sheet.Move($Workbook.Worksheets.Item(1))
        }
        catch {
            Write-Host "Could not move sheet: $SheetName" -ForegroundColor Yellow
        }
    }

    # Save as .xlsx
    $Workbook.SaveAs($WorkbookPath, 51)

    Write-Host ""
    Write-Host "Audit complete." -ForegroundColor Green
    Write-Host "Excel workbook saved to:"
    Write-Host $WorkbookPath -ForegroundColor Cyan
}
catch {
    Write-Host "ERROR: Failed to save workbook." -ForegroundColor Red
    Write-Host $_.Exception.Message
}
finally {
    if ($Workbook) {
        $Workbook.Close($true)
    }

    if ($Excel) {
        $Excel.Quit()
    }

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($SummarySheet) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Workbook) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Excel) | Out-Null

    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}