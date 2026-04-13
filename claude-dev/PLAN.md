# PLAN.md

## Project Goal

Consolidate branch work into claude-dev, fix broken checks in PSv3, add new checks from open issues, replace text output with markdown report format across all three scripts (CMD, PSv2, PSv3+), implement PSv2 and CMD scripts, and validate all scripts against Windows VMs on Proxmox.

## Current Phase

**Phase**: Phase 8 - Documentation and Release Prep
**Status**: Not Started
**Focus**: Update README, close issues/PRs, final validation, release

## Phases

### Phase 1: Branch Consolidation and Baseline

**Status**: Complete

- [x] Review and merge cmd-bat-refactor branch (2,344-line CMD/chaps.bat -- merged cleanly, 13 commits)
- [x] Review report_format_update branch (extracted PSv2 1,483-line baseline; PSv3 portion superseded by master)
- [x] Review PR #5 (Issue #2 features) -- code targets old chaps.ps1 architecture, cmdlet references noted for Phase 3 rewrite
- [x] Resolve conflicts -- no conflicts; cmd-bat-refactor was clean merge, PSv2 extracted via checkout
- [x] Verify merged code follows project coding standards -- PSv2 and CMD are baselines, will be reworked in Phases 6-7
- [x] Intern-Dev branch -- ignored per decision (too divergent, targets old architecture)
- [x] Stale branches identified: ai-test, port-to-PSv2, smbv1-check, typos-and-grammar, update-output-directory (all already in master)
- [x] PR #14 (cmd-bat-refactor) -- content merged into claude-dev

Branches to delete remotely (pending user confirmation):
- origin/Intern-Dev (ignored)
- origin/ai-test (identical to master)
- origin/port-to-PSv2 (merged)
- origin/smbv1-check-returns-a-false-positive-error (merged via PR #9)
- origin/typos-and-grammar (merged via PR #13)
- origin/update-output-directory (merged via PR #12)
- origin/cmd-bat-refactor (merged into claude-dev)
- origin/report_format_update (PSv2 extracted, PSv3 superseded)

### Phase 2: PSv3 Bug Fixes and Check Audit

**Status**: Complete

Fix confirmed bugs:
- [x] Fix Get-UntrustedFonts(): `$ressh` -> `$resuf` (wrong variable reference)
- [x] Fix date format `yyyyddMM` -> `yyyyMMdd` (day/month reversed)
- [x] Fix Get-WPAD(): registry path `HKEY_CURRENT_USER\` -> `HKCU:\`
- [x] Fix Get-WPAD(): wrong variable `$resllmnr` -> `$reswpad` in hosts check (found during full read)
- [x] Fix Get-NetBIOS(): WMI class typo `Win32_NetWorkAdapterConfiguration` -> `Win32_NetworkAdapterConfiguration`
- [x] Fix Get-WinRM(): typo "WimRM" -> "WinRM"
- [x] Fix Get-CredDeviceGuard and Get-UntrustedFonts: version checks `-eq 10` -> `-ge 10`
- [x] Fix Get-LocalAdmin(): Catch block outside Try (structural syntax error, found during full read)
- [x] Fix Get-LocalAdmin(): wrong variable `$content.length` -> `$numadmin.length` (found during full read)

Complete stubbed functions:
- [x] Implement Get-NetSessionEnum (SrvsvcSessionInfo + RestrictRemoteSAM checks)
- [x] Implement Get-MSOffice (VBAWarnings, BlockContentExecutionFromInternet, GPO policy detection)
- [x] Enable both checks (changed from `$false` to `$true`)

Address TODOs in code:
- [x] Get-CredDeviceGuard: version check now covers Win11+ via `-ge 10`
- [x] Get-SMBv1: added SMBv3 EncryptData and RejectUnencryptedAccess checks
- [x] Get-PSModule: added wildcard module check (verifies '*' in ModuleNames)
- [x] Get-PSTranscript: added transcript OutputDirectory location output

Update outdated checks:
- [x] Get-EMET: detects Windows Exploit Protection (DEP, ASLR, CFG) on Win10+; falls back to EMET service on older
- [x] Get-LAPS: detects Windows LAPS (registry policy + state) and legacy LAPS (AdmPwd.dll)
- [x] Get-WinRM: netsh fallback when Get-NetFirewallRule unavailable
- [x] Get-PSVersions: Get-WindowsFeature fallback for Server editions

Script grew from 1,426 to 1,641 lines. Zero TODOs remaining. All curly braces balanced (504/504).

### Phase 3: PSv3 New Checks

**Status**: Complete

- [x] Add check: USB/PnP device enumeration (Get-PnpDevice with WMI fallback)
- [x] Add check: Antivirus/EDR detection (SecurityCenter2 with Get-MpComputerStatus fallback for Server)
- [x] Add check: Software inventory (registry Uninstall keys -- avoids slow Win32_Product per user decision)
- [x] Add check: Network connections (Get-NetTCPConnection with netstat fallback, shows process names)
- [x] Add check: SYSMON detection (service + driver presence)
- [x] Add check: Windows Firewall profile status (Domain/Private/Public enabled/disabled, default actions, no rule enumeration per user decision)
- [x] Add check: ASR rules (Get-MpPreference, reports rule IDs and actions)
- [x] Event log size recommendations reviewed -- current thresholds (1-4 GB) align with guidance, no changes needed

Script: 1,641 -> 1,974 lines. 60 functions (up from 53). 622/622 braces balanced.

### Phase 3a: Additional Hardening Checks and Check Parity Planning

**Status**: Complete

New checks added to PSv3 (10 functions, CIS/STIG alignment):
- [x] Get-UACConfig: UAC settings (EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, FilterAdministratorToken)
- [x] Get-AccountPolicy: password policy, lockout threshold, guest account status, administrator rename check
- [x] Get-SecureBoot: UEFI Secure Boot status
- [x] Get-LSAProtection: RunAsPPL credential theft prevention
- [x] Get-ServiceHardening: risky services (Print Spooler, RemoteRegistry, SNMP, Telnet, etc.)
- [x] Get-SMBClientConfig: client-side signing (RequireSecuritySignature, EnableSecuritySignature)
- [x] Get-TLSConfig: SCHANNEL protocol versions (SSL 2.0/3.0 bad, TLS 1.2/1.3 good)
- [x] Get-AuditPolicy: audit policy via auditpol for critical subcategories
- [x] Get-RDPNLAConfig: NLA requirement and RDP encryption level
- [x] Get-TCPIPHardening: source routing, ICMP redirects, router discovery

Check parity planning complete:
- [x] Full comparison of PSv3 vs PSv2 vs CMD check coverage
- [x] Canonical check order defined (see claude-dev/CANONICAL_CHECKS.md)
- [x] Parity requirements added to Phases 6 and 7
- [x] 2 checks identified as truly N/A for CMD (PSVersions, PSLanguage -- runtime-only)
- [x] 4 PS checks identified as registry-based and implementable in CMD (PSModule, PSScript, PSTranscript, PSProtectedEvent)

Script: 1,974 -> 2,409 lines. 67 functions. 764/764 braces balanced.

### Phase 4: Markdown Output Format

**Status**: Complete

- [x] Replace all 403 Tee-Object calls with plain Write-Output
- [x] Remove Set-Output function, output directory/file creation, Set-Location
- [x] Remove $out_dir, $out_file, $sysinfo_file variables
- [x] Remove Prt-SectionHeader function
- [x] Single output stream: markdown to stdout (redirect-friendly)
- [x] Rewrite Prt-ReportHeader as markdown table (hostname, time, PS version, OS, admin status, company, site)
- [x] Rewrite Prt-ReportFooter and Prt-CutSec-ReportFooter as markdown
- [x] Add markdown section headers (## System Info Checks, ## Security Checks, etc.)
- [x] Rewrite Get-AdminState to output markdown table row
- [x] Rewrite Get-SystemInfo to output directly (no separate sysinfo file)
- [x] Fix 373 collapsed lines from bulk Tee-Object removal
- [x] Bump version to 2.0.0
- [x] Status prefixes [+] [-] [*] [x] preserved in markdown output

Markdown format specification for PSv2 and CMD:
- Report starts with `# CHAPS Report: <name> <version>` heading
- Metadata table: | Field | Value | format
- Section headers: `## <Category> Checks`
- Findings: status prefix + text, one per line
- Footer: `---` separator, bold completion line, italic Cutaway Security line

Script: 2,409 -> 2,374 lines (removed infrastructure code). 65 functions. 759/759 braces balanced.

### Phase 5: Testing Infrastructure

**Status**: Complete

- [x] Create REMOTE_TESTING.md (topology, SSH access, deploy/execute/retrieve pattern, snapshots, known quirks)
- [x] Create TESTING_STANDARD.md (test matrices for PSv3/PSv2/CMD x 6 OS versions, pass criteria, output validation commands, parity testing procedure)
- [x] Create remote-testing.example.conf (VM connection template, local copy gitignored)
- [x] Document shared Proxmox VM fleet: Win7, Win10, Win11, Server 2016/2019/2022
- [x] Document SSH-based test pattern: scp deploy -> ssh execute -> capture stdout -> validate markdown
- [x] Define pass criteria: clean exit, valid markdown, all sections present, no unexpected [x] errors, graceful non-admin handling
- [x] Document known per-OS quirks (Win7 PSv2 limitations, Server no SecurityCenter2, Server 2016 32-bit)
- [x] Update .gitignore for local config and results directory
- [x] Update ARCHITECTURE.md and GIT_RELEASE_STEPS.md with new files

Actual VM testing deferred to after PSv2/CMD implementation (Phases 6-7) so all three scripts can be tested together. PSv3 can be tested on VMs independently at any time using the documented procedure.

### Phase 6: PSv2 Script Implementation

**Status**: Complete

- [x] Built from PSv3 as base, adapted for PSv2 compatibility
- [x] All 65 functions ported with same canonical check order
- [x] Get-CimInstance replaced with Get-WmiObject (CredDeviceGuard, AntiVirus)
- [x] Get-SmbServerConfiguration replaced with registry queries (LanmanServer\Parameters)
- [x] Get-AppLockerPolicy replaced with registry check (SrpV2 path)
- [x] Get-WinEvent -ListLog replaced with wevtutil gl
- [x] Get-LocalUser replaced with net user + WMI Win32_UserAccount
- [x] Get-NetIPAddress removed, uses WMI gwmi directly for IPv4
- [x] Get-WindowsOptionalFeature replaced with registry PS engine version check
- [x] Ternary-like if expressions replaced with standard if/else
- [x] Markdown output format matching PSv3 (same headers, same prefixes)
- [x] PSv3+ cmdlets behind Test-CommandExists gates fall through to fallbacks

Script: 2,384 lines. 65 functions. 754/754 braces balanced. Zero PSv3+ cmdlets in direct use.
VM testing deferred to after Phase 7 (CMD) for full fleet testing of all scripts.

### Phase 7: CMD Batch Script Implementation

**Status**: Complete

- [x] Complete rewrite of chaps.bat (1,367 lines) implementing all 59 canonical checks
- [x] All checks in canonical order per CANONICAL_CHECKS.md
- [x] reg query for registry checks, wmic for WMI, sc query for services
- [x] netsh for firewall, net accounts/localgroup for account/admin checks
- [x] auditpol for audit policy, wevtutil for event log sizes
- [x] 4 PS logging checks via reg query (PSModule, PSScript, PSTranscript, PSProtectedEvent)
- [x] 4 N/A checks with info messages (AppLocker, ASR, PSVersions, PSLanguage)
- [x] Markdown output via echo to stdout (header table, ## sections, ### checks, status prefixes)
- [x] Helper functions: GetRegVal, GetRegValTokens3, CheckSvcState, PrintRegCheck
- [x] SETLOCAL ENABLEDELAYEDEXPANSION, proper quoting, exit /b 0
- [x] No file writing -- users redirect: `chaps.bat > report.md`

Script: 1,367 lines. 236 status output lines. 59 check references.
VM testing deferred to Phase 8 for full fleet testing of all three scripts.

### Phase 8: Documentation and Release Prep

**Status**: Not Started

- [ ] Update README.md with all new checks and features
- [ ] Update usage instructions for all three scripts
- [ ] Document markdown report format and how to use it for reports and AI analysis
- [ ] Update references and hardening guide links
- [ ] Remove completed TODO items from README
- [ ] Close Issue #2 after feature implementation
- [ ] Close PR #5 after integrating changes
- [ ] Final cross-script output comparison test on all VMs
- [ ] Pre-release checklist per GIT_RELEASE_STEPS.md
- [ ] Tag and release per GIT_RELEASE_STEPS.md

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-13 | Consolidate branches into claude-dev before modernizing | Multiple branches have divergent work that needs unified baseline |
| 2026-04-13 | PSv3 is the reference implementation; PSv2 and CMD are ports | PSv3 has the most complete codebase (1,426 lines vs stubs) |
| 2026-04-13 | Ignore Intern-Dev branch | Intern refactor targets old chaps.ps1 architecture, too divergent to cherry-pick |
| 2026-04-13 | Single markdown output to stdout | Users redirect to file or copy from console; no dual output or Tee-Object; keeps all scripts simple and consistent |
| 2026-04-13 | Reuse ICSWatchDog Proxmox VM fleet | Same VMs (Win7/10/11, Server 2016/2019/2022), same SSH infrastructure |
| 2026-04-13 | CMD markdown: most effective method, keep simple | Use whatever works best in batch; no over-engineering |
| 2026-04-13 | PR #5 code not merged directly | Targets old chaps.ps1 architecture; cmdlet references used for Phase 3 rewrite as proper functions |
| 2026-04-13 | Software inventory via registry, not Win32_Product | Win32_Product triggers MSI reconfiguration and is slow; registry Uninstall keys are fast and reliable |
| 2026-04-13 | Firewall check: profile status only, no rule enumeration | Keeps output focused; per-rule detail would be overwhelming and not actionable in assessment context |
| 2026-04-13 | Check parity enforced during PSv2/CMD port phases, not as separate retrofit | PSv3 is the finished reference; porting phases build from it naturally; avoids rewriting in old format then again in markdown |
| 2026-04-13 | Unavailable checks output info line with reason | All scripts produce same check list; N/A checks say why instead of being silently skipped |
| 2026-04-13 | Add 10 hardening checks to PSv3 before output conversion | UAC, account policy, Secure Boot, LSA, risky services, SMB client signing, TLS, audit policy, RDP NLA, TCP/IP hardening -- standard CIS/STIG expectations |
| 2026-04-13 | No Windows version targeting per script | Admins pick the script matching their system; each script handles its own compatibility |
| 2026-04-13 | References are for understanding, not specific benchmark targeting | Check recommendations cite sources but don't target specific CIS/STIG versions |
| 2026-04-13 | Phase work sequentially: consolidate -> fix bugs -> new checks -> markdown -> test -> port | Changes flow from reference PSv3 outward; testing validates before porting |
| 2026-04-13 | Adapt ICSWatchDog Proxmox VM testing infrastructure | Existing VM fleet and SSH-based testing methodology proven in sister project |

## Out of Scope

- Remediation scripts or configuration changes
- Network-based or remote scanning capabilities
- GUI or interactive interface
- Integration with specific SIEM or GRC platforms
- Automated scoring or compliance percentage calculations
- Support for non-Windows operating systems
- Windows version gating within scripts (admins choose the right script)
