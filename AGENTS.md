# Arches Cyber Engineering Rules

These rules apply to the entire repository. Arches Cyber Phase 1 is a Windows PowerShell 5.1 script project, not an installed application.

## Source of truth

- `Docs/PHASE1-SPEC.md` defines Phase 1 requirements and acceptance criteria.
- `Docs/SAFETY-POLICY.md` defines mandatory diagnostic, remediation, and rollback safeguards.
- `Docs/ROADMAP.md` defines Phase 1 boundaries and deferred work.
- When code and these documents disagree, treat the disagreement as a gap. Do not silently weaken the documented requirement to match existing code.

## Repository workflow

- Work only on `diagnostics-module` unless the user explicitly authorizes another branch.
- Never modify `main`, merge PR #2, or force-push without explicit user approval.
- Never discard unrelated changes. Stage only files belonging to the current task.
- Use focused commits and push them to `origin/diagnostics-module`.
- After every push, watch Windows GitHub Actions and fix genuine failures until CI is green.
- Preserve legacy scripts until their useful behavior has been migrated and validated. Clearly distinguish legacy entry points from the Phase 1 launcher.

## Platform and compatibility

- Production code must run in built-in Windows PowerShell 5.1 on Windows 11.
- Do not require PowerShell 7, Python, Microsoft Office, or third-party software at runtime.
- Paths must work from a copied folder or USB drive and must not depend on a username, drive letter, or installation directory.
- `Run-ArchesCyber.bat` is the primary Phase 1 launcher.
- Do not introduce PowerShell syntax or APIs unavailable in Windows PowerShell 5.1.

## Diagnostic safety

- Scans are read-only and must never invoke remediation automatically.
- Isolate checks so one failed or unsupported check does not terminate the scan.
- Report unsupported, unavailable, policy-managed, or inconclusive checks as `Unknown`, `Error`, or a separately approved not-applicable state. A failed check is not automatically a security failure.
- Never infer an ISP boundary or upstream device identity beyond what a Windows endpoint can reliably observe.
- Network operations must have bounded timeouts. Blocked ICMP alone must not prove gateway or internet failure.
- Do not collect passwords, tokens, recovery keys, browser data, message content, credentials in command lines, or unnecessary personal information.

## Remediation safety

- Diagnostics and fixes remain separate.
- Every fix requires explicit approval, supports `WhatIf` where technically possible, and declares risk, privileges, disruption, affected components, protection tier, reversibility, and verification.
- Recheck the exact condition after applying a fix.
- Detect domain policy, MDM, RMM, third-party antivirus, and other management conflicts before changing controlled settings. Refuse the fix when safety cannot be established.
- Never silently convert static addressing to DHCP or run broad network resets.
- Avoid changes that may disrupt VoIP, VPNs, allowlists, business applications, or managed security controls.
- Do not add firmware changes, encryption enable/disable, mass software removal, destructive cleanup, exploit behavior, persistence, or credential collection.
- Stop and request explicit direction before introducing a high-impact remediation or weakening a protection requirement.

## Rollback safety

- Rollback records contain structured data only—never executable commands, command text, or script blocks.
- Never use `Invoke-Expression`, `ScriptBlock.Create`, or execute content obtained from JSON.
- Dispatch restoration only through predefined trusted handlers for validated remediation IDs and target types.
- Unknown, modified, wrong-computer, wrong-status, or unsupported records fail closed.
- Mark rollback successful only after the restored state is verified.
- Keep failed rollback records for investigation.
- `ConfigOnly` is for narrow reversible settings.
- `RestorePoint` is for broader Windows changes and does not protect personal files.
- `ExternalSnapshotRequired` blocks high-impact work until an external backup, system image, or VM snapshot is explicitly confirmed.
- Phase 1 does not create full-machine images.

## Testing and release claims

- Run `git diff --check`, PowerShell parser validation, and the complete Pester suite for implementation changes.
- Mock Windows configuration-changing commands in automated tests. Tests must not alter a runner's real firewall, network, Defender, BitLocker, services, or operating-system configuration.
- Keep Windows GitHub Actions green.
- CI is not a substitute for the required Windows 11 VM validation in `Docs/PHASE1-SPEC.md`.
- Never claim client readiness until real-machine validation passes. Before that gate, call the project an MVP candidate or development build.
