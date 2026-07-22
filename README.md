# Arches Cyber Scripts

PowerShell 5.1-compatible workstation diagnostics for the Arches Cyber Phase 1 MVP.

## Run

Open Windows PowerShell as Administrator and run:

```powershell
.\Scripts\Start-ArchesCyber.ps1
```

Focused scans are available with `-Scan Security`, `Network`, `System`, `Devices`, or `Performance`. Use `-ProblemsOnly` for the simplified console view and `-NoOpenReport` for unattended execution. On Windows, `Run-ArchesCyber.bat` provides an elevated double-click launcher.

Each run creates a timestamped folder under `Desktop\ArchesCyberAudit` with an offline HTML dashboard plus JSON and CSV exports. The HTML dashboard opens in Client Summary mode and includes a Technical Details tab with approved IP configuration, observed IPv4/MAC neighbors, firewall-rule inventory, user/admin totals, malware health, diagnostic evidence, and validated change history. Diagnostic operations are read-only.

The large legacy audit scripts and USB launcher are disabled as Phase 1 entry points because their historical multi-file HTML/JSON/CSV/ZIP bundles are not fully covered by the Phase 1 evidence allowlist. Use the repository-level `Run-ArchesCyber.bat` or `Scripts\Start-ArchesCyber.ps1`. Legacy source remains only for controlled migration work and does not collect or export when invoked.

The Windows 11 readiness check reports hardware clues only. Microsoft PC Health Check remains the authoritative compatibility check because CPU model support cannot be determined reliably from core count and architecture alone.

## Malware diagnostics and scans

Security and full scans report registered antivirus ownership, Defender mode, signature age and update time, last completed quick/full scan, and count-only detected, quarantined, resolved, and unresolved threat history. A registered active third-party antivirus product is treated as authoritative; inactive or passive Defender state is not incorrectly reported as a protection failure.

Threat evidence intentionally excludes affected file paths, usernames, process paths, and raw Defender records. Run `Run-ArchesMalwareScan.bat` to open the elevated Malware Scan Center. Quick and full scans each require a fresh confirmation. Full scan approval includes a warning that it can run for hours and materially increase CPU and disk use. The scan center refuses Defender scans when Defender is unavailable, passive, non-authoritative, or superseded by an active third-party product.

## Guided fixes

Fixes are separate from scanning. The launcher can open `Scripts\Start-ArchesGuidedFixes.ps1`, a built-in Windows dialog that creates a read-only plan, displays the exact before/after change, and requires both a checked approval and a final confirmation. The HTML report cannot execute PowerShell; its fix buttons direct the operator to this trusted local dialog.

The command-line path also displays the plan before asking for terminal approval. Preview with `-WhatIf`, then run deliberately:

```powershell
.\Scripts\Invoke-ArchesFix.ps1 -Id FIX-FW-001 -WhatIf
.\Scripts\Invoke-ArchesFix.ps1 -Id FIX-FW-001 -ManagementOwnershipAttested -Approved
```

`-Approved` is not required for `-WhatIf`. On an execution run, the operator must type `APPROVE` only after the exact plan is displayed. Firewall execution also requires `-ManagementOwnershipAttested` after the technician confirms no unsupported management product owns firewall policy. Attestation cannot override detected or unknown management. Execution rechecks the planned baseline and refuses stale plans.

Firewall changes create a JSON rollback record before changing state. The project intentionally does not offer static-IP-to-DHCP conversion or broad network resets in Phase 1.

## Tests

With Pester 5 installed:

```powershell
Invoke-Pester .\Scripts\Test
```

GitHub Actions runs parser validation and the Pester suite on a Windows runner for every pull request targeting `main`.
