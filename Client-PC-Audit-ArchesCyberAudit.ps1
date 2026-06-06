# Client-PC-Audit.ps1
# Read-only workstation assessment script
# Run as Administrator

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

# 32 Quick risk summary
Save-Text "32_Quick_Risk_Summary.txt" {
    $Admins = Get-LocalGroupMember Administrators
    $RDP = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $Firewall = Get-NetFirewallProfile
    $Defender = Get-MpComputerStatus
    $TPM = Get-Tpm
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

    "Quick Risk Summary"
    "=================="
    ""
    "Computer Name: $env:COMPUTERNAME"
    "Local Admin Count: $($Admins.Count)"
    "RDP Enabled: $(if ($RDP.fDenyTSConnections -eq 0) { 'Yes' } else { 'No' })"
    "Defender Antivirus Enabled: $($Defender.AntivirusEnabled)"
    "Defender Real-Time Protection Enabled: $($Defender.RealTimeProtectionEnabled)"
    "TPM Present: $($TPM.TpmPresent)"
    "TPM Ready: $($TPM.TpmReady)"
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
    $MinPasswordLength = ($MinPasswordLengthLine -replace "\D+", "")

    if ([int]$MinPasswordLength -lt 12) {
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


Write-Host ""
Write-Host "Audit complete." -ForegroundColor Green
Write-Host "Reports saved to:"
Write-Host $ReportFolder -ForegroundColor Cyan