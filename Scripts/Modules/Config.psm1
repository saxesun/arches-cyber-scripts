Set-StrictMode -Version 2.0

function Test-ArchesProperty {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    $null -ne $InputObject -and $Name -in @($InputObject.PSObject.Properties.Name)
}

function Assert-ArchesRequiredProperty {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Location
    )
    if (-not (Test-ArchesProperty -InputObject $InputObject -Name $Name)) {
        throw "Invalid Phase 1 configuration: required property '$Location.$Name' is missing."
    }
}

function Assert-ArchesNumber {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][double]$Minimum,
        [Parameter(Mandatory)][double]$Maximum,
        [switch]$Integer
    )
    $numericTypes = @(
        [byte], [sbyte], [int16], [uint16], [int32], [uint32],
        [int64], [uint64], [single], [double], [decimal]
    )
    if ($null -eq $Value -or $Value.GetType() -notin $numericTypes) {
        throw "Invalid Phase 1 configuration: '$Name' must be a number."
    }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt $Minimum -or $number -gt $Maximum) {
        throw "Invalid Phase 1 configuration: '$Name' must be between $Minimum and $Maximum."
    }
    if ($Integer -and $number -ne [math]::Truncate($number)) {
        throw "Invalid Phase 1 configuration: '$Name' must be a whole number."
    }
}

function Get-ArchesConfiguration {
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Phase1.json')
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("Phase 1 configuration file not found: $Path", $Path)
    }

    try {
        $configuration = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Phase 1 configuration contains malformed JSON: $($_.Exception.Message)"
    }

    foreach ($property in @('SchemaVersion', 'ReportRetentionDays', 'RollbackRetentionDays', 'Thresholds', 'Safety')) {
        Assert-ArchesRequiredProperty -InputObject $configuration -Name $property -Location 'root'
    }
    if ($null -eq $configuration.Thresholds) {
        throw "Invalid Phase 1 configuration: required section 'Thresholds' cannot be null."
    }
    if ($null -eq $configuration.Safety) {
        throw "Invalid Phase 1 configuration: required section 'Safety' cannot be null."
    }

    Assert-ArchesNumber -Value $configuration.SchemaVersion -Name 'SchemaVersion' -Minimum 1 -Maximum 1 -Integer
    Assert-ArchesNumber -Value $configuration.ReportRetentionDays -Name 'ReportRetentionDays' -Minimum 1 -Maximum 3650 -Integer
    Assert-ArchesNumber -Value $configuration.RollbackRetentionDays -Name 'RollbackRetentionDays' -Minimum 1 -Maximum 3650 -Integer

    $thresholdRanges = [ordered]@{
        DiskFreeWarningPercent = @(1, 100)
        DiskFreeCriticalPercent = @(0, 99)
        MemoryAvailableWarningPercent = @(1, 100)
        MemoryAvailableCriticalPercent = @(0, 99)
        CpuWarningPercent = @(1, 100)
        RestartAgeWarningDays = @(1, 3650)
        LatencyWarningMs = @(1, 60000)
        PacketLossWarningPercent = @(0, 100)
    }
    foreach ($name in $thresholdRanges.Keys) {
        Assert-ArchesRequiredProperty -InputObject $configuration.Thresholds -Name $name -Location 'Thresholds'
        $range = $thresholdRanges[$name]
        Assert-ArchesNumber -Value $configuration.Thresholds.$name -Name "Thresholds.$name" -Minimum $range[0] -Maximum $range[1]
    }

    if ($configuration.Thresholds.DiskFreeCriticalPercent -ge $configuration.Thresholds.DiskFreeWarningPercent) {
        throw "Invalid Phase 1 configuration: 'Thresholds.DiskFreeCriticalPercent' must be less than 'Thresholds.DiskFreeWarningPercent'."
    }
    if ($configuration.Thresholds.MemoryAvailableCriticalPercent -ge $configuration.Thresholds.MemoryAvailableWarningPercent) {
        throw "Invalid Phase 1 configuration: 'Thresholds.MemoryAvailableCriticalPercent' must be less than 'Thresholds.MemoryAvailableWarningPercent'."
    }

    foreach ($name in @('RequireExplicitFixApproval', 'CreateRollbackBeforeChange', 'AllowNetworkReset', 'AllowStaticToDhcpChange')) {
        Assert-ArchesRequiredProperty -InputObject $configuration.Safety -Name $name -Location 'Safety'
        if ($configuration.Safety.$name -isnot [bool]) {
            throw "Invalid Phase 1 configuration: 'Safety.$name' must be true or false."
        }
    }

    $configuration
}

Export-ModuleMember -Function Get-ArchesConfiguration
