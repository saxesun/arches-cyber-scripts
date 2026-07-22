# Arches Cyber Roadmap

## Product boundary

Arches Cyber is currently a portable Windows PowerShell 5.1 script project. The immediate goal is a safe Phase 1 diagnostic and guided-remediation MVP candidate. It is not yet an installed application, remote-management agent, cloud dashboard, or client-ready service.

## Phase 1 — Workstation diagnostic MVP candidate

Phase 1 includes:

- one-click full scan through `Run-ArchesCyber.bat`;
- focused Security, Network, System/Hardware, Connected Devices, and Performance scans;
- privacy-bounded antivirus, Defender signature/scan-history, and malware threat diagnostics;
- separately approved Defender quick/full scan controls with a full-scan runtime warning;
- problems-only default presentation with opt-in technical detail;
- stable structured findings with plain-language summary, business impact, evidence, recommendation, and remediation metadata;
- deterministic Great/Good/Not Good/Bad/Not Scanned ratings;
- client and technical HTML reporting plus JSON and CSV;
- strict versioned configuration;
- the diagnostic scope in `Docs/PHASE1-SPEC.md`;
- approximately 10–15 individually reviewed, thoroughly tested low-risk guided fixes;
- tiered protection and version 3 integrity-protected, data-only rollback;
- parser and Pester validation with green Windows GitHub Actions;
- a completed Windows 11 VM validation record.

### Phase 1 delivery sequence

1. **Documentation and contracts**
   - Maintain the specification, safety policy, roadmap, result contract, exit-code contract, privacy allowlist, and versioning decision.
2. **Core execution and result model**
   - Problems-only default, exit codes, elevation metadata, duplicate prevention, business impact, not-applicable decision, and partial-failure behavior.
3. **Diagnostic coverage and reliability**
   - Complete the documented security, hardware, update, process, network, and device checks with bounded timeouts and managed-control awareness.
4. **Reporting and retention**
   - Unique run directories, client/technical separation, metadata, privacy controls, scoped retention, and deterministic report tests.
5. **Guided remediation catalog**
   - Review and add only individually safe candidates; implement policy conflict detection, disruption messaging, `WhatIf`, verification, and rollback where applicable.
6. **Release validation**
   - Keep CI green, complete the Windows 11 VM checklist, record limitations, and prepare the handoff inventory.

Phase 1 code completion is not client readiness. Real Windows VM evidence is a mandatory release gate.

## Later Phase 1.x candidates

These may follow the initial 10–15 reliable fixes without changing the Phase 1 architecture:

- additional low-risk diagnostics;
- additional individually reviewed low-risk remediations toward a longer-term 25–40 catalog;
- improved report explanations and device-specific guidance;
- compatibility expansion based on field and VM evidence.

Each candidate remains subject to the Phase 1 safety and release gates.

## Deferred beyond Phase 1

The following are explicitly out of Phase 1:

- searchable historical reports;
- severity filtering across historical scans;
- scan/fix change timelines;
- long-term system-health dashboards;
- backend or cloud dashboards;
- remote access and centralized management;
- an optional Wazuh export adapter that emits privacy-reviewed structured JSON findings and validated change events for agent collection, custom rules, and dashboards;
- automatic report email;
- full-machine imaging or backup service.

These features require separate product, privacy, authentication, authorization, retention, deployment, and threat-model decisions. They must not be smuggled into the Phase 1 script as convenience features.

## Legacy migration

Legacy scripts remain in the repository until useful behavior is migrated into the modular Phase 1 path and validated. They must be labeled clearly so operators do not mistake them for the current launcher.

Retirement requires:

1. an inventory of the legacy behavior;
2. mapping to replacement diagnostics/reports;
3. automated coverage where practical;
4. Windows 11 VM comparison;
5. explicit approval to remove or archive the legacy entry point.

## Handoff deliverables

When code-level Phase 1 work is complete, stop and provide:

- feature inventory;
- remediation catalog;
- test inventory and GitHub Actions links;
- known limitations and deferred items;
- completed Windows VM validation checklist;
- exact run, test, report, fix, undo, and troubleshooting commands;
- a clear statement that the product is an MVP candidate, not client-ready, until Windows VM validation passes.
