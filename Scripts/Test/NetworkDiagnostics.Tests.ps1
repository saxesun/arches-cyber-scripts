$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Diagnostics.psm1') -Force

Describe 'Bounded multi-signal gateway diagnosis' {
    BeforeAll {
        function Get-TestGatewayResult {
            Get-ArchesNetworkDiagnostics -Configuration $configuration |
                Where-Object Id -eq 'NET-GW-001'
        }
    }

    BeforeEach {
        $configuration = [PSCustomObject]@{ Thresholds = [PSCustomObject]@{} }
        $script:routePresent = $true
        $script:neighborPresent = $true
        $script:icmpStatuses = @('Success', 'Success', 'Success')
        $script:tcpStatus = 'Success'

        Mock Get-ArchesDefaultRoute -ModuleName Diagnostics {
            if ($script:routePresent) {
                [PSCustomObject]@{ NextHop='192.0.2.1'; InterfaceAlias='Ethernet'; RouteMetric=10 }
            }
        }
        Mock Get-ArchesGatewayNeighbor -ModuleName Diagnostics {
            if ($script:neighborPresent) {
                [PSCustomObject]@{ IPAddress=$IPAddress; State='Reachable' }
            }
        }
        Mock Invoke-ArchesIcmpSamples -ModuleName Diagnostics {
            @($script:icmpStatuses | ForEach-Object {
                [PSCustomObject]@{ Status=$_; RoundtripTimeMs=$null }
            })
        }
        Mock Test-ArchesTcpReachability -ModuleName Diagnostics {
            [PSCustomObject]@{ Status=$script:tcpStatus; Target=$Target; Port=$Port }
        }
        Mock Resolve-ArchesDnsBounded -ModuleName Diagnostics {
            [PSCustomObject]@{ Status='Success'; Name=$Name; Addresses=@('192.0.2.10') }
        }
    }

    It 'passes healthy multi-signal evidence' {
        (Get-TestGatewayResult).Status | Should -Be 'Pass'
    }

    It 'fails a confirmed missing route' {
        $script:routePresent = $false
        (Get-TestGatewayResult).Status | Should -Be 'Fail'
    }

    It 'warns when ICMP is blocked but TCP works' {
        $script:icmpStatuses = @('TimedOut', 'TimedOut', 'TimedOut')
        (Get-TestGatewayResult).Status | Should -Be 'Warning'
    }

    It 'fails when neighbor ICMP and TCP all indicate outage' {
        $script:neighborPresent = $false
        $script:icmpStatuses = @('TimedOut', 'TimedOut', 'TimedOut')
        $script:tcpStatus = 'Error'
        (Get-TestGatewayResult).Status | Should -Be 'Fail'
    }

    It 'reports Unknown when bounded operations time out with partial local evidence' {
        $script:icmpStatuses = @('TimedOut', 'TimedOut', 'TimedOut')
        $script:tcpStatus = 'Timeout'
        (Get-TestGatewayResult).Status | Should -Be 'Unknown'
    }

    It 'reports Unknown for partial or conflicting evidence' {
        $script:icmpStatuses = @('Success', 'TimedOut', 'TimedOut')
        $script:tcpStatus = 'Error'
        (Get-TestGatewayResult).Status | Should -Be 'Unknown'
    }

    It 'uses explicit retry and timeout limits' {
        Get-TestGatewayResult | Out-Null
        Should -Invoke -CommandName Invoke-ArchesIcmpSamples -ModuleName Diagnostics `
            -Times 1 -Exactly -ParameterFilter { $Attempts -eq 3 -and $TimeoutMilliseconds -eq 1000 }
        Should -Invoke -CommandName Test-ArchesTcpReachability -ModuleName Diagnostics `
            -ParameterFilter { $Port -eq 443 -and $TimeoutMilliseconds -eq 3000 }
    }
}
