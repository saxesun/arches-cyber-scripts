# Arches Cyber Scripts

PowerShell 5.1-compatible workstation diagnostics for the Arches Cyber Phase 1 MVP.

## Run

Open Windows PowerShell as Administrator and run:

```powershell
.\Scripts\Start-ArchesCyber.ps1
```

Focused scans are available with `-Scan Security`, `Network`, `System`, `Devices`, or `Performance`. Use `-ProblemsOnly` for the simplified console view and `-NoOpenReport` for unattended execution. On Windows, `Run-ArchesCyber.bat` provides an elevated double-click launcher.

Reports are written to `Desktop\ArchesCyberAudit` as HTML, JSON, and CSV. Diagnostic operations are read-only. Guided remediation and rollback remain under development and are not enabled by this entry point.

## Guided fixes

Fixes are separate from scanning and require explicit approval. Preview a fix with `-WhatIf`, then run it deliberately:

```powershell
.\Scripts\Invoke-ArchesFix.ps1 -Id FIX-FW-001 -Approved -WhatIf
.\Scripts\Invoke-ArchesFix.ps1 -Id FIX-FW-001 -Approved
```

Firewall changes create a JSON rollback record before changing state. The project intentionally does not offer static-IP-to-DHCP conversion or broad network resets in Phase 1.

## Tests

With Pester 5 installed:

```powershell
Invoke-Pester .\Scripts\Test
```

GitHub Actions runs parser validation and the Pester suite on a Windows runner for every pull request targeting `main`.
