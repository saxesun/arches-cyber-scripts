$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules\Results.psm1') -Force
Import-Module (Join-Path $root 'Modules\Diagnostics.psm1') -Force

Describe 'Configuration-driven diagnostic thresholds' {
    BeforeEach {
        $configuration = [PSCustomObject]@{
            Thresholds = [PSCustomObject]@{
                DiskFreeWarningPercent = 20
                DiskFreeCriticalPercent = 10
                MemoryAvailableWarningPercent = 20
                MemoryAvailableCriticalPercent = 10
                CpuWarningPercent = 90
                RestartAgeWarningDays = 30
            }
        }
        $script:diskFreePercent = 50
        $script:memoryAvailablePercent = 50
        $script:cpuPercent = 20
        $script:restartDays = 1

        Mock Get-CimInstance -ModuleName Diagnostics {
            switch ($ClassName) {
                'Win32_LogicalDisk' {
                    [PSCustomObject]@{ Size = 100000; FreeSpace = $script:diskFreePercent * 1000 }
                }
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        LastBootUpTime = (Get-Date).AddDays(-$script:restartDays).AddMinutes(-1)
                        FreePhysicalMemory = $script:memoryAvailablePercent * 1000
                        TotalVisibleMemorySize = 100000
                        OSArchitecture = '64-bit'
                    }
                }
                'Win32_ComputerSystem' {
                    [PSCustomObject]@{ TotalPhysicalMemory = 8GB }
                }
                'Win32_Processor' {
                    [PSCustomObject]@{ Name = 'Test CPU'; NumberOfCores = 4; LoadPercentage = $script:cpuPercent }
                }
            }
        }
        Mock Get-Service -ModuleName Diagnostics {
            [PSCustomObject]@{ StartType = 'Automatic'; Status = 'Running' }
        }
        Mock Get-Tpm -ModuleName Diagnostics {
            [PSCustomObject]@{ TpmPresent = $true; TpmReady = $true }
        }
    }

    It 'fails disk space at the critical boundary' {
        $script:diskFreePercent = 10
        $result = Get-ArchesSystemDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'SYS-DISK-001'
        $result.Status | Should -Be 'Fail'
    }

    It 'warns below the disk warning boundary' {
        $script:diskFreePercent = 19
        $result = Get-ArchesSystemDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'SYS-DISK-001'
        $result.Status | Should -Be 'Warning'
    }

    It 'passes disk space at the warning boundary' {
        $script:diskFreePercent = 20
        $result = Get-ArchesSystemDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'SYS-DISK-001'
        $result.Status | Should -Be 'Pass'
    }

    It 'fails available memory at the critical boundary' {
        $script:memoryAvailablePercent = 10
        $result = Get-ArchesPerformanceDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'PERF-MEM-001'
        $result.Status | Should -Be 'Fail'
    }

    It 'warns below the memory warning boundary' {
        $script:memoryAvailablePercent = 19
        $result = Get-ArchesPerformanceDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'PERF-MEM-001'
        $result.Status | Should -Be 'Warning'
    }

    It 'passes available memory at the warning boundary' {
        $script:memoryAvailablePercent = 20
        $result = Get-ArchesPerformanceDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'PERF-MEM-001'
        $result.Status | Should -Be 'Pass'
    }

    It 'warns for CPU load at the configured boundary' {
        $script:cpuPercent = 90
        $result = Get-ArchesPerformanceDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'PERF-CPU-001'
        $result.Status | Should -Be 'Warning'
    }

    It 'passes CPU load below the configured boundary' {
        $script:cpuPercent = 89
        $result = Get-ArchesPerformanceDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'PERF-CPU-001'
        $result.Status | Should -Be 'Pass'
    }

    It 'warns for restart age at the configured boundary' {
        $script:restartDays = 30
        $result = Get-ArchesSystemDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'SYS-BOOT-001'
        $result.Status | Should -Be 'Warning'
    }

    It 'passes restart age below the configured boundary' {
        $script:restartDays = 29
        $result = Get-ArchesSystemDiagnostics -Configuration $configuration |
            Where-Object Id -eq 'SYS-BOOT-001'
        $result.Status | Should -Be 'Pass'
    }
}
