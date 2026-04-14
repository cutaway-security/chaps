# RESUME.md

## Current State

**Last Session**: 2026-04-14
**Branch**: claude-dev
**Status**: Clean -- Phase 10 second batch complete; awaiting review before release prep

## What Was Accomplished

### Phases 1-9: Complete (see earlier sessions)

### Phase 10 First Batch (Complete)

Shipped `tools/chaps-analyze.ps1` with an 18-entry JSON knowledge base, user docs, and README/INTERPRETING_REPORTS.md cross-references. Tool accepted by user after review of three analysis outputs (PSv3/PSv2/CMD on Win10).

### Phase 10 Second Batch (Complete this session)

Expanded the knowledge base from 18 to 59 entries. Added patterns for 40+ additional negative findings that appear in real CHAPS reports.

**Coverage improvement:**

| Report | First batch | Second batch |
|---|:---:|:---:|
| Win10Pro-Dev-psv3.md | 10/65 (15%) | 65/65 (100%) |
| Win10Pro-Dev-psv2.md | 10/64 (16%) | 64/64 (100%) |
| Win10Pro-Dev-cmd.md | 4/17 (24%) | 16/17 (94%) |
| WinServer2019-Dev-psv3.md | ~11/68 (16%) | 68/68 (100%) |
| Win7Pro-Dev-psv2.md | ~10/69 (14%) | 65/69 (94%) |

**New entries added (41 total):**

System Info: missing_critical_patches, autoupdate_not_scheduled, bitlocker_not_encrypted, exploit_protection_off, laps_not_installed, applocker_not_configured, netsessionenum_open, device_guard_not_configured, account_policy_weak, secure_boot_off, risky_service_running

Security: smb_encryption_off, smbv1_audit_off, anonymous_enumeration, untrusted_fonts_off, asr_not_configured, smb_client_signing_off, audit_policy_missing

Authentication: localadmin_group_crowded, cached_logons_high, wdigest_unset, restrictremoteclients_unset, rdp_encryption_low, rdp_nla_not_required, rdp_allowed_when_not_needed

Network: llmnr_enabled, netbios_enabled, computer_browser_running, wpad_not_hardened, wins_lmhosts_enabled, ipv6_enabled_unused, icmp_redirect_enabled, tcpip_source_routing_on

PowerShell: psv2_enabled, ps_language_not_constrained, ps_transcription_off, ps_protected_event_logging_off, winrm_running_without_hardening

Logging: event_log_size_small, wsh_enabled, kb_security_patch_missing

**Severity distribution of all 59 entries:**

- Critical: 1 (AlwaysInstallElevated both keys)
- High: 9 (credential theft + SMBv1 + UAC + patches + exploit protection)
- Medium: 28 (majority; AppLocker, ASR, LLMNR/NBT-NS, WPAD, RDP, account policy, etc.)
- Low: 21 (logging gaps, minor hardening, legacy-protocol cleanup)

**MITRE ATT&CK coverage:**

Primary techniques referenced: T1003.001 (LSASS), T1003.002 (SAM), T1003.008, T1014, T1018, T1021.001-006, T1027.004, T1040, T1055, T1059 (.001, .005, .007), T1068, T1070.001, T1078.003, T1087 (.001, .002), T1110 (.001, .002, .003), T1135, T1190, T1204.002, T1210, T1218, T1542.003, T1548.002, T1550.002, T1552.004, T1556, T1557 (and .001), T1562.002, T1562.010, T1566.001, T1574 (.005, .009, .010), T1588.001, T1588.003, T1135, T1558.003

## In Progress

- Nothing active. Awaiting user review of expanded knowledge base and regenerated review reports in `claude-dev/review.local/analysis-*.md`.

## Blockers

- None.

## Next Steps

1. User reviews analysis output with 59-entry KB applied
2. If approved, commit Phase 10 second batch
3. Resume Phase 8 release prep:
   - Close Issue #2 (features implemented in Phase 3)
   - Close PR #5 (thank-you comment, features integrated via rewrite)
   - Clean up `claude-dev/review.local/` once review is done
   - Delete stale remote branches
   - Pre-release checklist
   - Tag and release (`dev-v2` -> `release-v2` strip -> main force-push -> `v2` tag -> GitHub release)

## Open Questions

1. Any entries where the severity feels wrong? Current distribution: 1 Critical / 9 High / 28 Medium / 21 Low / 0 Info.
2. Any wording in the risk / recommendation fields that reads too technical or too alarming?
3. Any MITRE mappings that look off?

## Files Modified This Session

| File | Change |
|------|---|
| tools/knowledge/findings.json | Expanded 18 -> 59 entries; added patterns and new checks |
| claude-dev/PLAN.md | Phase 10 second batch marked complete |
| claude-dev/RESUME.md | This file |
| claude-dev/review.local/analysis-Win10Pro-Dev-*.md | Regenerated review outputs (gitignored) |
