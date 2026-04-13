# PLAN.md

## Project Goal

Consolidate branch work into claude-dev, fix broken checks in PSv3, add new checks from open issues, replace text output with markdown report format across all three scripts (CMD, PSv2, PSv3+), implement PSv2 and CMD scripts, and validate all scripts against Windows VMs on Proxmox.

## Current Phase

**Phase**: Phase 2 - PSv3 Bug Fixes and Check Audit
**Status**: Not Started
**Focus**: Fix confirmed bugs, complete stubs, update outdated checks in PSv3

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

**Status**: Not Started

Fix confirmed bugs:
- [ ] Fix line 595 Get-UntrustedFonts(): uses `$ressh` instead of `$resuf` (wrong variable reference)
- [ ] Fix line 107: date format `"yyyyddMM_HHmmss"` should be `"yyyyMMdd_HHmmss"` (day/month reversed)
- [ ] Fix line 903 Get-WPAD(): registry path uses `HKEY_CURRENT_USER\` instead of `HKCU:\` (invalid for Get-ItemProperty)
- [ ] Fix line 1007 Get-NetBIOS(): WMI class typo `Win32_NetWorkAdapterConfiguration` (missing 'e' in Network)
- [ ] Fix line 1250 Get-WinRM(): typo "WimRM" in error message should be "WinRM"
- [ ] Fix lines 480, 589: Windows version checks use `-eq 10` instead of `-ge 10` (excludes Win11+)

Complete stubbed functions:
- [ ] Implement Get-NetSessionEnum() (lines 445-451, currently empty)
- [ ] Implement Get-MSOffice() (lines 505-507, currently empty -- macro security checks)

Address TODOs in code:
- [ ] Line 479 Get-CredDeviceGuard(): add Windows 11 support
- [ ] Line 517 Get-SMBv1(): add SMBv3 encryption and signing checks
- [ ] Line 1100 Get-PSModule(): add check for which modules are logged (should be '*')
- [ ] Line 1165 Get-PSTranscript(): add check for transcript log location

Update outdated checks:
- [ ] Line 395 Get-EMET(): EMET is deprecated, update check to detect modern alternatives (Exploit Protection)
- [ ] Line 413 Get-LAPS(): update from legacy DLL path to modern Windows LAPS detection
- [ ] Add fallbacks where Get-NetFirewallRule (line 1255) or Get-WindowsOptionalFeature (line 1050) may not be available

### Phase 3: PSv3 New Checks

**Status**: Not Started

- [ ] Add check: USB/PnP device enumeration (Issue #2: `Get-PnpDevice -Class 'USB'`)
- [ ] Add check: Antivirus/EDR software detection (Issue #2: `Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct`)
- [ ] Add check: Software inventory (Issue #2: `Get-WmiObject -Class Win32_Product` or registry-based alternative)
- [ ] Add check: Network connections (Issue #2: `netstat -anob` or `Get-NetTCPConnection`)
- [ ] Add check: SYSMON detection (README TODO -- check service and driver presence)
- [ ] Add check: Windows Firewall profile assessment (inbound/outbound rules, profile status)
- [ ] Add check: ASR rules / Exploit Protection (modern Win10/11 hardening)
- [ ] Update existing check thresholds and recommendations to current standards
- [ ] Review and update event log size recommendations

### Phase 4: Markdown Output Format

**Status**: Not Started

- [ ] Design markdown report format consistent across all three scripts (CMD, PSv2, PSv3)
- [ ] Define report structure: metadata header, summary table, categorized findings, recommendations
- [ ] Replace text output with markdown in PSv3 script
- [ ] Single output stream: markdown to stdout (user redirects to file or copies from console)
- [ ] No dual output / Tee-Object -- simple Write-Output only, redirect-friendly
- [ ] Include summary table at top of report (pass/fail/info/error counts per category)
- [ ] Include per-check detail sections with finding, status, and recommendation
- [ ] Add machine-readable metadata block (hostname, timestamp, OS version, admin status, script version)
- [ ] Test markdown renders correctly in GitHub, VS Code, and common markdown viewers
- [ ] Validate markdown is parseable by AI analysis tools
- [ ] Document the markdown report format specification for PSv2 and CMD to follow

### Phase 5: Testing Infrastructure

**Status**: Not Started

Adapt Proxmox VM testing from ICSWatchDog project:
- [ ] Create REMOTE_TESTING.md documenting VM testing procedures for CHAPS
- [ ] Create TESTING_STANDARD.md with test matrix and pass criteria
- [ ] Create remote-testing.example.conf template (gitignored local copy with real values)
- [ ] Use same Proxmox VM fleet as ICSWatchDog:
  - Win7 (PSv2 + CMD testing)
  - Win10 (PSv3 + PSv2 + CMD testing)
  - Win11 (PSv3 + PSv2 + CMD testing)
  - Server 2016, 2019, 2022 (all scripts)
- [ ] Document SSH-based deployment procedure: scp script to VM, ssh execute, scp results back
- [ ] Define test procedure per script:
  1. Copy script to VM via scp
  2. Execute remotely via ssh
  3. Verify script completes without errors
  4. Retrieve output file via scp
  5. Validate markdown output renders correctly
  6. Compare check results across script variants for same VM
- [ ] Test PSv3 script on all target VMs, record results
- [ ] Fix any VM-specific failures discovered during testing
- [ ] Document known per-OS quirks (Server Core differences, missing features, etc.)

### Phase 6: PSv2 Script Implementation

**Status**: Not Started

- [ ] Baseline from report_format_update branch PSv2 work (1,483 lines)
- [ ] Port modernized PSv3 checks to PSv2-compatible syntax
- [ ] Replace CIM cmdlets with WMI equivalents
- [ ] Replace PSv3+ features (ordered hashtables, etc.) with v2 alternatives
- [ ] Implement markdown output format (matching PSv3 report structure)
- [ ] Test on Win7 VM (PSv2 environment) via Proxmox
- [ ] Test on modern VMs to verify backward-compatible behavior
- [ ] Validate output parity with PSv3 script

### Phase 7: CMD Batch Script Implementation

**Status**: Not Started

- [ ] Baseline from cmd-bat-refactor branch work (2,344 lines)
- [ ] Port remaining checks not yet in batch script
- [ ] Implement markdown output using most effective method for batch (echo with markdown syntax, keep simple)
- [ ] Single output stream to stdout, same as PowerShell scripts -- redirect-friendly
- [ ] Follow batch.md coding standards (delayed expansion, redirect safety, etc.)
- [ ] Test on all target VMs via Proxmox
- [ ] Validate output parity with PowerShell scripts

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
