# RESUME.md

## Current State

**Last Session**: 2026-04-13
**Branch**: claude-dev
**Status**: Clean -- Phase 3a complete, 23 commits ahead of origin/claude-dev

## What Was Accomplished

### Phases 1-3: Complete (see previous sessions)

### Phase 3a: Additional Hardening Checks and Check Parity Planning (Complete)

Added 10 new hardening check functions to PSv3 for CIS/STIG alignment:
- Get-UACConfig: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, FilterAdministratorToken
- Get-AccountPolicy: password policy (net accounts), lockout threshold, guest account, admin rename
- Get-SecureBoot: Confirm-SecureBootUEFI with registry fallback
- Get-LSAProtection: RunAsPPL credential theft prevention
- Get-ServiceHardening: Print Spooler, RemoteRegistry, SNMP, Telnet, RemoteAccess, NetTcpPortSharing, SharedAccess
- Get-SMBClientConfig: client-side signing (RequireSecuritySignature, EnableSecuritySignature)
- Get-TLSConfig: SCHANNEL protocols (SSL 2.0/3.0 flagged, TLS 1.2/1.3 positive)
- Get-AuditPolicy: auditpol for Logon, Security Group Mgmt, User Account Mgmt, Process Creation, etc.
- Get-RDPNLAConfig: NLA requirement and minimum encryption level
- Get-TCPIPHardening: source routing, ICMP redirect, router discovery

Check parity planning:
- Full 3-script comparison completed (PSv3: 59 checks, PSv2: 33 matching, CMD: 16 matching)
- Created CANONICAL_CHECKS.md with all 59 checks in order, CMD feasibility noted
- Added parity requirements to Phases 6 (PSv2) and 7 (CMD)
- 2 checks truly N/A for CMD (PSVersions, PSLanguage), 5 info-only (require PS cmdlets)
- Decision: parity enforced during port phases, not as separate retrofit

Script: 1,974 -> 2,409 lines. 67 functions. 764/764 braces balanced. Zero TODOs.

## In Progress

- Nothing active -- awaiting confirmation to start Phase 4

## Blockers

- None

## Next Steps

1. Phase 4: Replace text output with markdown format in PSv3
2. Phase 5: Testing infrastructure (Proxmox VMs)
3. Phase 6: PSv2 implementation with check parity
4. Phase 7: CMD implementation with check parity

## Open Questions

- None currently

## Files Modified This Session

| File | Change |
|------|--------|
| PowerShellv3/chaps_PSv3.ps1 | All phases: bug fixes + stubs + new checks + hardening checks (+983 lines total) |
| CMD/chaps.bat | Merged from cmd-bat-refactor (2,343 lines) |
| PowerShellv2/chaps_PSv2.ps1 | Extracted from report_format_update (1,483 lines) |
| CLAUDE.md | Created and updated |
| claude-dev/ARCHITECTURE.md | Created and updated |
| claude-dev/PLAN.md | Created, Phases 1-3a marked complete |
| claude-dev/RESUME.md | This file |
| claude-dev/CANONICAL_CHECKS.md | Created -- canonical check order for all scripts |
| claude-dev/GIT_RELEASE_STEPS.md | Created |
| claude-dev/code-standards/powershell.md | Copied from templates |
| claude-dev/code-standards/batch.md | Copied from templates |
