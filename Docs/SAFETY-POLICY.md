# Safety, Remediation, and Rollback Policy

## Safety posture

Diagnostics are read-only. Remediation is a separate, opt-in workflow. When safety, ownership, management policy, scope, or reversibility is uncertain, Arches Cyber fails closed and explains why.

No Phase 1 workflow may:

- silently change static addressing to DHCP;
- perform a broad network reset by default;
- change firmware;
- enable or disable encryption without a separately approved design;
- perform mass software removal or destructive cleanup;
- create persistence, collect credentials, exploit systems, or execute arbitrary commands;
- attempt full-machine imaging;
- claim that a restore point protects personal files.

## Required remediation declaration

Every catalog entry declares:

- stable remediation ID and title;
- affected service, setting, or device;
- risk;
- required privileges;
- expected disruption and estimated duration;
- management-policy conflict checks;
- protection tier;
- whether the action is reversible;
- exact intended changes;
- post-change verification;
- rollback verification where reversible.

Every execution requires explicit approval and supports `WhatIf` where technically possible. Approval applies only to the displayed change; it is not blanket authorization for adjacent changes.

Before approval, Arches Cyber performs read-only preflight and builds a structured plan containing exact targets and before/after values, risk, privileges, disruption, estimated duration, protection tier, reversibility, ownership signals, and verification. `WhatIf` displays and returns this exact plan without executing a change handler. Approval is requested only after the plan is available. Immediately before execution, relevant state is re-read; if it differs from the plan baseline, execution fails closed and requires a new plan.

## Preflight sequence

Before changing anything:

1. Validate configuration.
2. Resolve the remediation from a trusted catalog.
3. Confirm approval and required privileges.
4. Detect domain, Group Policy, MDM, RMM, third-party security, VPN, VoIP, allowlist, and business-application conflicts relevant to the target.
5. Refuse the action if ownership or safety cannot be established.
6. Establish the declared protection tier.
7. For reversible settings, create a validated `Pending` data-only record containing only the exact affected values.
8. Display the intended change and disruption.

After changing:

1. Apply only the intended settings.
2. Re-read and verify the target state.
3. Mark a rollback record `Applied` only after verification succeeds.
4. If application or verification fails, attempt only the trusted targeted recovery handler.
5. Report both the original failure and recovery result.
6. Preserve failed records for investigation.

## Protection tiers

### Tier 1 — ConfigOnly

Use for narrow, independently reversible settings such as approved firewall profiles, DNS server settings, safe service settings, and startup entries.

- Record only exact affected targets, properties, before values, and intended after values.
- Restore only through predefined handlers.
- Verify each restored value.
- A safe but non-reversible action such as flushing DNS cache may be classified low risk, but it must set `Reversible = false` and must not create a fake rollback record.

### Tier 2 — RestorePoint

Use for broader Windows system changes only after an individual design review.

- Save structured setting data as in Tier 1.
- Attempt a Windows System Restore point before the change.
- If protection cannot be created, stop unless the catalog contains an explicitly reviewed policy permitting continuation.
- The operator-facing explanation must say that Windows System Restore does not protect personal files.
- A restore point supplements targeted undo; it does not replace post-change or rollback verification.

No current Phase 1 remediation is approved for this tier.

### Tier 3 — ExternalSnapshotRequired

Use for high-impact changes only after explicit design approval.

- Require operator confirmation of an external backup, system image, or VM snapshot.
- Refuse to run without confirmation.
- Do not create a full-machine image in Phase 1.
- Stop for user direction before adding any Tier 3 remediation.

No current Phase 1 remediation is approved for this tier.

## Rollback record requirements

Rollback schema version 3 contains data only. Version 3 adds an `Integrity` object containing an HMAC-SHA256 key identifier and signature:

```json
{
  "SchemaVersion": 3,
  "RecordId": "GUID",
  "RemediationId": "FIX-FW-001",
  "ProtectionTier": "ConfigOnly",
  "ComputerName": "PC-NAME",
  "CreatedAt": "ISO-8601",
  "Status": "Pending",
  "Changes": [
    {
      "TargetType": "FirewallProfile",
      "Target": "Public",
      "Property": "Enabled",
      "Before": false,
      "After": true
    }
  ],
  "AppliedAt": null,
  "RolledBackAt": null,
  "Verification": null,
  "Integrity": {
    "Algorithm": "HMAC-SHA256",
    "KeyId": "SHA-256 key identifier",
    "Value": "Base64 HMAC"
  }
}
```

The HMAC covers every security-relevant record field, including identity, computer binding, remediation and protection tier, timestamps, status, changes, and verification. Its random 256-bit key is stored outside the rollback directory and protected by Windows DPAPI for the current Windows user. Records are verified before status evaluation or trusted handler dispatch. Offline edits, copied records, use under another Windows account, and records signed by another installation therefore fail closed.

This integrity mechanism does not protect against an attacker who can execute code as the same Windows user, read that user's DPAPI-protected data, or modify the trusted Arches Cyber scripts themselves. It is tamper detection for data at rest, not a substitute for Windows account security, filesystem permissions, code signing, or an enterprise key-management system.

Allowed states are `Pending`, `Applied`, `RolledBack`, and `RollbackFailed`. State updates use atomic file replacement where practical.

Validation rejects:

- unknown schema versions, root fields, or change fields;
- unknown remediation IDs or handler combinations;
- unknown target types, targets, properties, or value types;
- unsupported status transitions;
- empty or non-changing change sets;
- records belonging to another computer;
- malformed timestamps, identifiers, or verification data.

There is no general cross-computer override. Any future override requires a separately approved threat model and design.

Rollback requires explicit approval for execution and supports `WhatIf`. Normal undo accepts only `Applied` records. A trusted remediation failure-recovery path may process its own `Pending` record. `RolledBack` and `RollbackFailed` records are retained and cannot be replayed by the normal path.

## Trusted dispatch

JSON never selects a command. Validated remediation ID and target type select a predefined code path. Handlers accept typed, allowlisted values and invoke fixed PowerShell cmdlets.

Prohibited in rollback and remediation code:

- `Invoke-Expression`;
- `ScriptBlock.Create`;
- command or script-block fields in JSON;
- invoking a command name, path, or arguments read from rollback data;
- arbitrary registry paths, service names, profiles, or properties not allowlisted by the handler.

## Current catalog policy

| ID | Action | Tier | Reversible | Required safety gap before broader use |
|---|---|---|---:|---|
| `FIX-FW-001` | Enable disabled Domain, Private, or Public firewall profiles | ConfigOnly | Yes | Refuse detected domain, Group Policy, MDM/Entra, approved RMM, or third-party security ownership; require technician attestation when supported signals are clear because unknown vendors cannot be excluded |
| `FIX-DNS-001` | Flush DNS resolver cache | ConfigOnly | No | Explain that previous cache contents cannot be restored |

Additional candidates remain unapproved until individually reviewed against this policy. Reliability takes precedence over catalog size.

## Validation gate

Automated tests must mock configuration-changing Windows commands and cover approval, `WhatIf`, validation rejection, exact restoration, verification failure, state transitions, and combined failure reporting.

Real Windows 11 VM testing must exercise every approved remediation and undo path, management-policy conflicts, tampered records, reboot behavior where relevant, and verification that unrelated settings remain unchanged.

Firewall ownership detection is deliberately described as `Managed`, `SupportedSignalsClear`, or `Unknown`; it never claims that a computer is definitively unmanaged. Supported signals include domain membership, firewall Group Policy, MDM/OMADM and Entra join registry state, an approved list of common RMM service patterns, and Security Center third-party antivirus registration. A clear supported-signal scan still requires explicit technician attestation that no unsupported management owner controls the setting. Attestation cannot override a detected or unknown state.
