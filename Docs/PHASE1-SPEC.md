# Phase 1 Product Specification

## Product definition

Arches Cyber Phase 1 is a portable Windows PowerShell 5.1 script for small-business and MSP workstation diagnostics and guided remediation. It is not an installed application, remote-management platform, cloud service, or client-ready product.

The Phase 1 objective is a safe, one-click Windows workstation scan with focused technical scans, understandable findings, useful reports, and a deliberately limited catalog of thoroughly tested low-risk fixes.

## Primary experience

The primary launcher is `Run-ArchesCyber.bat`. It must:

- run from a copied folder or USB drive without fixed usernames, drive letters, or installation paths;
- request elevation when needed and explain launch failures;
- start a full scan without further interactive input;
- return an exit code defined in the release contract;
- keep interactive targeted diagnostics behind an explicit operator choice.

The default human-facing view is problems-only. An operator may intentionally request the complete technical view. Findings must explain the condition, technical evidence, business impact, recommended action, and whether guided remediation is available.

Health ratings are `Great`, `Good`, `Not Good`, `Bad`, and `Not Scanned`. `Not Scanned` is never presented as healthy.

## Runtime and compatibility requirements

- Windows 11 with built-in Windows PowerShell 5.1 is the runtime target.
- Microsoft Office, PowerShell 7, Python, and third-party runtime dependencies are not required.
- A normal full scan has no prompts and targets a runtime below two minutes, excluding optional malware scans and interactive diagnostics.
- Every network operation has a bounded timeout and cannot hang indefinitely.
- Exit codes distinguish success, completed-with-findings, partial-check failure, and fatal failure.
- The script records whether execution was elevated.

The exact numeric exit-code mapping is an open decision listed below and must be settled before release behavior is implemented.

## Result contract

Every finding has:

- a stable unique ID;
- status: `Pass`, `Warning`, `Fail`, `Unknown`, or `Error` (plus a not-applicable representation only after the open decision below is resolved);
- severity;
- category and title;
- consumer-friendly summary;
- serializable technical evidence;
- business impact;
- recommendation;
- remediation availability and remediation ID where applicable;
- check time.

Duplicate finding IDs are rejected. Individual diagnostic failures are isolated. Missing Windows features, unsupported hardware, third-party controls, and management policy do not become security failures merely because a local command failed or a local setting differs.

`Unknown` and `Error` describe confidence or execution state and do not incur score penalties. A category containing only `Unknown` or `Error` results is rated `Not Scanned`; when confirmed checks are also present, uncertain results are counted separately without altering the confirmed-condition score.

## Diagnostic scope

### Security and identity

- Microsoft Defender and third-party antivirus awareness
- Windows Firewall
- local users and administrators
- password policy
- RDP
- BitLocker status without collecting recovery keys
- TPM and Secure Boot
- managed-control awareness for domain, MDM, RMM, and third-party security

Antivirus diagnosis correlates Windows Security Center registrations with Defender state and policy clues. Active registered third-party antivirus with Defender passive or inactive is not a failure. Unavailable Security Center, managed ambiguity, unavailable Defender state, and conflicting product signals are `Unknown`. A confirmed `Fail` requires available, consistent evidence that no registered product is active.

### Windows and hardware

- Windows Update health and update age
- Windows 11 readiness clues, without claiming authoritative compatibility
- CPU, memory, storage, and restart health
- startup programs
- service failures
- listening ports and associated processes, without retaining credential-bearing command lines

### Network and connected devices

- adapter state
- DHCP/static addressing state, with no automatic static-to-DHCP conversion
- gateway and DNS
- latency and packet loss
- internet reachability using multiple signals where practical
- connected-device visibility
- targeted router, access point, printer, VoIP, NIC, internet, and storage diagnostics where reliably observable from a Windows endpoint

Blocked ICMP alone does not prove a gateway or internet outage. Trace results describe observable hops only and do not claim to locate an ISP boundary perfectly.

The modular gateway check uses one default-route lookup, neighbor resolution, exactly three ICMP samples bounded to one second each, and an independent TCP 443 attempt bounded to three seconds. DNS and standalone internet checks are also bounded to three seconds. Missing route or failure across independent local and external signals may be a confirmed failure; ICMP failure with working TCP is a warning, and partial, conflicting, or timed-out evidence is `Unknown`.

## Configuration

`Scripts/Config/Phase1.json` is versioned and controls supported thresholds, retention, and safety options. The loader:

- rejects missing or malformed files;
- validates required sections, property types, numeric ranges, and related threshold ordering;
- does not silently substitute defaults after validation fails;
- returns a validated object that is passed explicitly to consumers rather than stored as unvalidated global state.

Current safe defaults:

| Setting | Default | Accepted range or rule |
|---|---:|---|
| Report retention | 30 days | 1–3650 whole days |
| Rollback retention | 30 days | 1–3650 whole days |
| Disk free warning | 20% | 1–100 |
| Disk free critical | 10% | 0–99 and below warning |
| Available memory warning | 20% | 1–100 |
| Available memory critical | 10% | 0–99 and below warning |
| CPU warning | 90% | 1–100 |
| Restart age warning | 30 days | 1–3650 |
| Latency warning | 100 ms | 1–60000 |
| Packet-loss warning | 2% | 0–100 |

Safety defaults require approval and rollback-before-change, and prohibit broad network reset and static-to-DHCP conversion.

## Reporting

Every run creates a unique timestamped report directory and produces:

- a simple client-facing HTML summary;
- detailed technical HTML content or a clearly separated technical section;
- JSON with complete structured results;
- CSV with useful flattened fields.

Reports identify computer, scan time, scan type, script version, and elevation state. Findings are separated from raw evidence. All untrusted system values are HTML-encoded.

The client summary lists validated apply and rollback events that occurred on the report date, with the affected setting and before/after state. The technical view shows the complete retained, validated record lifecycle: creation, application, rollback attempt, final status, exact structured changes, protection tier, verification result, and undo availability. Pending records are not represented as completed changes, and invalid records expose no untrusted change contents.

Reports must not expose passwords, tokens, BitLocker recovery keys, browser data, message content, credential-bearing command lines, or unnecessary personal data. Retention cleanup is limited to known Arches Cyber report and rollback directories.

Phase 1 evidence is deny-by-default. `Privacy.psm1` maps each approved finding ID to its permitted evidence fields; unknown IDs export no evidence. Diagnostics construct only those fields, and report export reapplies the allowlist as defense in depth. Identity evidence is limited to counts, BitLocker evidence excludes key protectors and recovery material, and technical network inventory contains bounded IP/MAC/interface observations without usernames or discovered hostnames. Firewall inventory excludes program paths, service identity, users, and unbounded rule output. Legacy DNS-cache collection is disabled. This allowlist does not make free-form future summaries safe automatically; new findings and fields require privacy review and deterministic tests before approval.

Console, HTML, JSON metadata, CSV rows, and completion logs distinguish confirmed `Warning`/`Fail` findings from `Unknown` and `Error` checks. Unknown or failed execution is never included in the confirmed-finding count.

## Guided remediation

Diagnostics never apply fixes. Every remediation follows `Docs/SAFETY-POLICY.md` and:

- requires explicit approval;
- supports `WhatIf` where technically possible;
- declares risk, privileges, estimated disruption, affected components, protection tier, reversibility, and verification;
- detects management conflicts before changing controlled settings;
- refuses when safety cannot be established;
- rechecks the condition after applying the change;
- preserves rollback data and reports both application and rollback failures.

Phase 1 targets approximately 10–15 thoroughly tested low-risk fixes. Reliability is more important than meeting a count. Candidate fixes require individual safety review:

- enable disabled firewall profiles after management-policy checks;
- flush DNS cache, explicitly non-reversible;
- restart a selected safe service after dependency/disruption checks;
- remove stale temporary files only from an Arches-owned directory;
- correct selected Windows Update service states when not policy-managed;
- enable selected Defender protections only when Defender is active and policy permits.

Do not invent fixes to meet a numeric target.

## Acceptance criteria

Phase 1 is complete enough for user testing only when all of the following are proven:

1. The primary launcher and all production modules run in Windows PowerShell 5.1 on Windows 11.
2. Full and focused scans satisfy the execution, result, diagnostic, privacy, and timeout requirements above.
3. Problems-only is the default; complete technical output is opt-in.
4. Findings include business impact and remediation metadata, with stable IDs and no duplicates.
5. Deterministic scoring tests cover every rating and ensure `Unknown`, `Error`, and `Not Scanned` are not misrepresented.
6. Reports satisfy all format, metadata, encoding, separation, privacy, uniqueness, and retention requirements.
7. Approximately 10–15 individually reviewed low-risk remediations meet the safety policy; no automatic remediation exists.
8. Structured rollback meets every validation, dispatch, state, approval, verification, and retention requirement.
9. Parser validation and all Pester tests pass, and Windows GitHub Actions is green.
10. The Windows 11 VM checklist below has been completed with evidence.

Until item 10 passes, the product is an MVP candidate—not client-ready.

## Required Windows 11 VM validation

- Test elevated and non-elevated launch.
- Test full and every focused scan.
- Measure runtime, CPU use, and memory use.
- Test healthy, intentionally misconfigured, and unsupported-feature conditions.
- Test disconnected network, DNS failure, and blocked-ICMP conditions.
- Test third-party antivirus and managed-control behavior.
- Verify report accuracy, HTML safety, and privacy.
- Exercise every remediation with `WhatIf`.
- Apply and undo every reversible remediation.
- Confirm failed, tampered, wrong-computer, and wrong-status rollback records fail safely.
- Verify DPAPI key creation and reload, corrupted and inaccessible key failure, elevated/current-user behavior, concurrent first-use creation, and the documented inability to undo under a different Windows user.
- Reboot and verify changes where applicable.
- Confirm no unrelated configuration changed.

Record the Windows build, PowerShell version, device/VM configuration, test time, expected result, observed result, report path, and operator for each case.

## Current repository comparison

Baseline reviewed on 2026-07-19 at `diagnostics-module` commit `e552450`.

### Implemented foundations

- PowerShell 5.1-oriented modular code and a double-click launcher exist.
- Full and focused scan entry points exist.
- Stable IDs and isolated diagnostic exception handling exist.
- The normalized result model includes static business-impact text, and client and technical reports separate the observed condition from why it matters.
- Configuration loading and threshold validation exist.
- Health rating names and basic deterministic scoring tests exist.
- HTML, JSON, and CSV export exists with HTML encoding for current finding fields.
- Firewall and DNS remediations are separated from diagnostics and require approval.
- Version 3 data-only firewall rollback, HMAC integrity validation, trusted restore handlers, approval, `WhatIf`, and verification exist.
- Parser/Pester validation runs in Windows GitHub Actions.

### Contradictions and incomplete requirements

- Complete console output is currently the default; problems-only requires `-ProblemsOnly`.
- Explicit remediation availability remains derived from the remediation ID rather than stored as a first-class result field.
- Current diagnostics cover only part of the stated scope; update age, users, password policy, adapter addressing, latency/packet loss, listening processes, startup/service failures, and targeted device diagnostics remain incomplete in the modular Phase 1 path.
- Reports now use a unique directory per run, record scan type, script version and elevation state, separate client and technical views, render readable approved evidence, and include date-scoped client changes plus complete validated retained change lifecycles.
- Report/rollback retention settings are validated but automated scoped retention behavior is incomplete.
- The launcher reports only a generic PowerShell exit code; the required exit-code contract is not implemented.
- The remediation catalog has two entries, not the target 10–15; supported firewall-management signals and explicit technician attestation are implemented, but the detection catalog still requires managed-environment validation.
- Legacy audit scripts and launchers remain present without a complete operator-facing legacy label/migration map.
- The README does not yet contain the complete exact run, test, report, fix, undo, and troubleshooting instructions required by the release gate.
- Real Windows 11 VM validation has not been completed. Client readiness must not be claimed.

### Missing decisions

Resolve and document these before implementing the affected behavior:

1. Exact numeric exit codes for clean success, findings, partial-check failure, and fatal failure.
2. Whether to add a distinct `NotApplicable` result status or represent it as `Unknown` with a reason.
3. The deterministic scoring treatment for `Unknown`, `Error`, managed, and not-applicable checks.
4. The authoritative script version source and versioning/release convention.
5. Per-operation network timeout values and the maximum retry budget consistent with the two-minute target.
6. Expansion criteria for the implemented deny-by-default privacy allowlist when new identity, software, process, or network evidence is proposed.
7. The exact management-conflict signals required before firewall, Defender, service, and Windows Update changes.
8. The individually approved initial remediation catalog beyond `FIX-FW-001` and non-reversible `FIX-DNS-001`.
9. Whether focused scans require elevation or may return partial results in a non-elevated mode.
10. The migration/retirement criteria for each legacy script and launcher.
