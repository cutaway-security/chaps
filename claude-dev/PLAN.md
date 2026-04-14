# PLAN.md

## Project Goal

Consolidate branch work into claude-dev, fix broken checks in PSv3, add new checks from open issues, replace text output with markdown report format across all three scripts (CMD, PSv2, PSv3+), implement PSv2 and CMD scripts, and validate all scripts against Windows VMs on Proxmox.

## Current Phase

**Phase**: Released
**Status**: v2 shipped 2026-04-14
**Focus**: CHAPS v2 released to master. Tags `dev-v2` and `v2` pushed. GitHub release published at https://github.com/cutaway-security/chaps/releases/tag/v2. Working tree clean on claude-dev. Next session: post-release feedback / hardening backlog.

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

**Status**: Complete (reset to ICSWatchDog standard)

Initial setup (superseded):
- [x] Create REMOTE_TESTING.md, TESTING_STANDARD.md, remote-testing.example.conf (first draft, later reset)

Reset to ICSWatchDog testing standard:
- [x] Rewrite REMOTE_TESTING.md to follow ICSWatchDog Proxmox VE + SSH + VMID-comment standard (strips Sysmon content, uses ~/.ssh/config as single source of truth, no local conf file)
- [x] Rewrite TESTING_STANDARD.md with Available Systems table (SSH Alias, VMID, Proxmox, OS, PS Version, Scripts Supported, Notes), test matrices, parity testing, per-OS quirks
- [x] Delete remote-testing.example.conf (redundant with ~/.ssh/config per new standard)
- [x] Replace specific .gitignore entry with defensive `claude-dev/*.local.*` catch-all
- [x] Add claude-dev/vm-lookup bash helper (parses VMID/Proxmox alias from ~/.ssh/config structured comments)
- [x] Update ARCHITECTURE.md and GIT_RELEASE_STEPS.md to reflect the reset
- [x] Connection-test each VM and the Proxmox host

Actual script testing deferred to Phase 8 (Documentation and Release Prep) so all three scripts can be tested together against live VMs.

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

**Status**: In Progress

Documentation (complete):
- [x] Simplified README.md: overview, script table, quick start, links to docs/, collaborators, license (~75 lines)
- [x] docs/USAGE.md: prerequisites, per-script invocation, output patterns, non-admin behavior, troubleshooting, removal
- [x] docs/CHECKS.md: all 59 checks in canonical order, organized by section, with brief descriptions and CMD capability matrix
- [x] docs/INTERPRETING_REPORTS.md: status prefixes, triage workflow, common findings, cross-script comparison, report-to-writeup workflow
- [x] docs/REMEDIATION.md: per-check remediation guidance (28 remediable checks detailed), Group Policy paths, registry keys, commands, priority order

VM testing (complete):
- [x] Full test run: all three scripts on all six VMs, 2026-04-13 (results in claude-dev/review.local/)
- [x] Runtime bugs fixed: Get-SystemInfo fallback chain, CMD LF->CRLF, Get-BitLocker manage-bde probe, PSv2 Get-WmiObject parameters
- [x] Review observations fixed: blank [*] lines, AllowRemoteRPC typo
- [x] Test matrices populated in TESTING_STANDARD.md

Release prep (items 1-4 complete 2026-04-14; items 5-8 BLOCKED on Phase 11 + 12):
- [x] Close Issue #2 -- all four requested features (USB, AV, software inventory, netstat) implemented; closing comment cites the corresponding v2.0 check numbers
- [x] Close PR #5 -- thank-you comment to @0xKaushik; features integrated via v2.0 rewrite with proper framework conventions
- [x] Close PR #14 (prerequisite for deleting cmd-bat-refactor branch) -- thank-you comment to @workentin; content merged into claude-dev
- [x] Clean up claude-dev/review.local/ -- 21 local analysis files removed
- [x] Delete 8 stale remote branches: ai-test, port-to-PSv2, smbv1-check-returns-a-false-positive-error, typos-and-grammar, update-output-directory, cmd-bat-refactor, report_format_update, Intern-Dev
- [x] Tagged `dev-v2` on claude-dev, pushed (2026-04-14)
- [x] Created `release-v2` branch, stripped `claude-dev/` and `CLAUDE.md`, committed `1bb098d` "Remove dev files for release v2"
- [x] Force-pushed `release-v2` to `master`, tagged `v2` on master, pushed tag
- [x] Created GitHub release `v2` from `claude-dev/RELEASE_NOTES_v2.md` -- https://github.com/cutaway-security/chaps/releases/tag/v2
- [x] Deleted local `release-v2` branch
- [x] Post-release: renormalized `CMD/chaps.bat` line endings per `.gitattributes` (commit `35df259`); pushed

### Phase 9: Additional Privilege Escalation and Exposure Checks

**Status**: Complete

Four new checks to add to the canonical set (total goes from 59 to 63):

- [x] **Check 24: Unquoted Service Paths** -- enumerate service ImagePath values, flag any with spaces not enclosed in quotes (classic local privilege escalation vector)
- [x] **Check 25: Weak Program Directory Permissions** -- inspect NTFS ACLs on Program Files, Program Files (x86), and non-standard top-level C:\ folders for write/modify permissions granted to Users, Authenticated Users, or Everyone
- [x] **Check 26: Installed Compilers** -- detect GCC/MinGW, clang, MSVC cl.exe, assemblers, Strawberry Perl, make, cmake. Searches PATH plus common install roots (C:\Strawberry, C:\MinGW, C:\msys64)
- [x] **Check 53: Network Shares** -- enumerate non-default SMB shares (excludes ADMIN$, C$, D$, IPC$)

Canonical numbering updates (propagates through all three scripts and docs):
- System Info: was 1-23, now 1-26 (adds 24, 25, 26)
- Security: was 24-30, now 27-33
- Authentication: was 31-39, now 34-42
- Network: was 40-49, now 43-52 + new 53 (Network Shares)
- PowerShell: was 50-56, now 54-60
- Logging: was 57-59, now 61-63

Implementation tasks:
- [x] Added Get-UnquotedServicePaths, Get-WeakProgramPermissions, Get-InstalledCompilers, Get-NetworkShares to PSv3
- [x] Ported all four functions to PSv2 (Get-WmiObject, Get-Acl, Win32_Share equivalents)
- [x] Added four new check blocks to CMD with renumbered subheadings for all downstream checks
- [x] Updated CANONICAL_CHECKS.md with new numbering and three new System Info rows plus Network Shares row
- [x] Updated docs/CHECKS.md with new entries and renumbered existing entries
- [x] Added REMEDIATION.md entries for each new check; renumbered and reordered existing entries
- [x] Full VM retest 2026-04-14 (all scripts on all 6 VMs): all pass, 0 stderr, 63 checks per CMD report
- [x] Test matrix counts confirmed updated

### Phase 10: Analysis Tooling

**Status**: In Progress

Post-processing tool that analyzes a CHAPS markdown report and emits a structured findings report with per-finding recommendations, MITRE ATT&CK mappings, and references. The output is suitable for direct human review, ingestion into AI reporting tools (executive summaries, ticket backlogs), and ingestion into AI attack-planning tools (pentest teams reframe into attack plans).

Decision: single PowerShell tool (not two separate defender/attacker tools). Rationale: in an AI-assisted environment, pre-opinionated output for a specific audience is less valuable than richly-structured neutral facts; AI tooling on either side reframes the output. Also cheaper to maintain one knowledge base.

First batch (complete):

- [x] Create `tools/chaps-analyze.ps1` -- PowerShell 3.0+, no external dependencies
- [x] Create `tools/knowledge/findings.json` -- editable knowledge base, 18 Phase 1 entries
- [x] Support `-InputReport <path>` (required) and `-KnowledgeOverride <path>` (optional)
- [x] Parse CHAPS metadata block, six category sections, and status prefixes
- [x] Match `[-]` findings against knowledge-base patterns; emit structured Markdown
- [x] Emit unmatched `[-]` findings succinctly
- [x] Emit incomplete-check ([x]) appendix and informational-evidence summary appendix
- [x] Include single OT/ICS advisory paragraph near the top
- [x] Severity scheme: Critical/High/Medium/Low/Info
- [x] Exit non-zero on invalid input
- [x] No logging, no telemetry, no external network calls
- [x] Create `docs/ANALYSIS.md`
- [x] Update `README.md` and `docs/INTERPRETING_REPORTS.md`

Second batch (complete):

- [x] Expanded knowledge base from 18 to 59 entries
- [x] Added common findings: AutoUpdate, BitLocker, Exploit Protection, LAPS, AppLocker, NetSessionEnum, Device Guard, Secure Boot, account policy, risky services, SMB encryption/auditing, anonymous enum, untrusted fonts, ASR, SMB client signing, audit policy, local admins, cached logons, WDigest unset, RestrictRemoteClients, RDP encryption, RDP NLA, LLMNR, NetBIOS, Computer Browser, WPAD, WINS/LMHOSTS, IPv6, ICMP redirects, source routing, PS v2, ConstrainedLanguage, transcription, Protected Event Logging, WinRM, event log sizes, WSH, legacy KB hotfixes, missing patches
- [x] Coverage on test reports: 94-100% (was ~15% after first batch)
- [x] Retested three review reports, output reviewed

Later batches (not yet scoped):

- [ ] Role-aware severity adjustments (DC vs. workstation vs. HMI)
- [ ] Optional: batch mode (directory of reports -> rollup analysis)
- [ ] Cover remaining edge cases surfaced during real-world use

### Phase 11: Licensing and Header Standardization

**Status**: Complete

Goal: adopt a license posture that allows consulting teams, organizations, and students to use CHAPS freely while preventing other vendors from bundling CHAPS into proprietary products without permission. Decision: keep GPL v3 (already the project license) and add an explicit commercial-license offer for parties that cannot comply with GPL v3. Match the dual-license pattern used in the sibling ICSWatchDog project, but with GPL v3 as the open-source half (CHAPS is software; ICSWatchDog uses CC BY-SA because its content is XML/docs).

Key clarifications baked into NOTICE and README:

- Running CHAPS to produce a report is *use*, not *distribution*; the resulting report is not a derivative work of CHAPS.
- Internal organizational use does not trigger GPL v3 redistribution obligations.
- Consultants delivering reports to clients owe nothing under GPL.
- Vendors bundling CHAPS (modified or unmodified) into closed-source products must either GPL-license that product or obtain a commercial license from Cutaway Security, LLC.

Tasks:

- [x] Added root `LICENSE` file containing the full GPL v3 text (canonical FSF text from /usr/share/common-licenses/GPL-3, 674 lines)
- [x] Added root `NOTICE` file documenting dual-license terms, copyright, contact for commercial license, permitted-use clarifications (consulting, internal, academic, report-not-derivative), and when a commercial license is required
- [x] Standardized per-file headers in PSv3, PSv2, CMD, and `tools/chaps-analyze.ps1`: replaced ~16-line inline GPL boilerplate with a short block citing LICENSE + NOTICE
- [x] Updated copyright across all files to `Copyright (c) 2019-2026 Cutaway Security, LLC`
- [x] Updated `README.md` "License" section: replaced one-line GPL statement with full Project License section mirroring NOTICE; links to LICENSE and NOTICE
- [x] No leftover license language in dev docs that contradicts the new posture (verified)

Out of scope for Phase 11:
- No website, no Jekyll docs site (deferred indefinitely; user has not requested one)
- No third-party content inventory in NOTICE -- CHAPS has none

### Phase 12: Release Tooling and Deployment Process

**Status**: Complete (in working tree, awaiting commit and review)

Goal: bring CHAPS release process up to ICSWatchDog standard so future releases are repeatable, low-risk, and partially automated. The current `claude-dev/GIT_RELEASE_STEPS.md` documents the manual procedure; this phase adds a defensive safety net and a preflight automation script.

Tasks:

- [x] Added `.gitattributes` with `export-ignore` for `claude-dev/` and `CLAUDE.md`. Also added `*.bat text eol=crlf` to enforce CRLF on the CMD script (Windows CMD silently skips lines on LF-terminated batch files -- previous bug recurrence prevention).
- [x] Added `claude-dev/release.sh` adapted from ICSWatchDog -- automates Steps 1-5 of GIT_RELEASE_STEPS.md (preflight, manual-checklist confirmation, header/TBD checks, dev-tag, release-branch, dev-file strip, verify) and prints the manual Step 6-9 commands. Force-push to main is never automated. Bash syntax-checked.
- [x] Updated `GIT_RELEASE_STEPS.md`: added "Automated vs. Manual" preamble pointing at `release.sh`, added LICENSE/NOTICE/README-license-section to the pre-release checklist, added `chaps-analyze.ps1` smoke-test item, added LICENSE/NOTICE/.gitattributes to the "DO ship" list, added "Defensive Safety Net" section explaining `.gitattributes`.
- [x] "Files Removed During Release" table left untouched -- it never listed LICENSE/NOTICE; verified.
- Deferred: `claude-dev/test-fleet.sh` -- nice-to-have, not blocking.

Phase 12 commit pending -- await user review.

Out of scope for Phase 12:
- No `deploy-site.sh` (no website)
- No GitHub Actions / CI -- not requested
- No signed releases / Sigstore -- not requested

### Phase 8 (resumed): Release Tagging

**Status**: Complete (2026-04-14)

CHAPS v2 shipped. Release executed manually following GIT_RELEASE_STEPS.md (the `release.sh` script is interactive and reserved for human-driven runs). All steps verified:

- `dev-v2` tag on claude-dev (commit 7c3983d)
- `v2` tag on master (commit 1bb098d)
- master tree contains only ship-list files (15 paths total)
- No `claude-dev/`, `CLAUDE.md`, or other dev paths in the master tree
- GitHub release published with full v2 release notes
- Local `release-v2` branch cleaned up

Post-release housekeeping: `CMD/chaps.bat` was renormalized in claude-dev to match the new `.gitattributes` `*.bat text eol=crlf` rule. Pure line-ending change, no content drift. Master is unaffected.

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
| 2026-04-14 | One analysis tool, not two (defender+pentest) | AI tooling reframes neutral facts into audience-specific output; pre-opinionated separate tools duplicate work and create distribution complexity; single knowledge base is cheaper to maintain |
| 2026-04-14 | Analysis tool in PowerShell (not Python) | OT admins already use PowerShell; avoids second runtime install; same ecosystem as the collection scripts. Pentest teams with Linux workstations can run via PowerShell Core |
| 2026-04-14 | Knowledge base in JSON with optional user override file | JSON is stdlib-parseable, editable, diffable; -KnowledgeOverride flag lets organizations add custom entries without touching bundled file |
| 2026-04-14 | Include MITRE ATT&CK mappings in analysis output | Standard vocabulary useful to both defender and attacker audiences; supports threat-model mapping and AI attack-planning |
| 2026-04-14 | Single OT/ICS advisory at top of analysis output | Admins know what can break; per-check warnings would be noise |
| 2026-04-14 | Phased knowledge base | Ship ~12-15 entries for most common negative findings first; expand based on real use |
| 2026-04-14 | Emit unmatched findings succinctly | Silent gaps are misleading; succinct flagging gives users a backlog and keeps the report honest |
| 2026-04-14 | Dual-license CHAPS as GPL v3 + Commercial; do not switch to CC, MIT, Elastic, or BUSL | GPL v3 already covers the consulting/student/internal-org use cases (use is not distribution; reports are not derivative works), and its copyleft is the lever that forces proprietary bundlers to either open-source their product or buy a commercial license. CC BY-SA is wrong for software. MIT/Apache permit unrestricted bundling. Elastic/BUSL are not OSI-approved and create friction with universities and consulting shops. |
| 2026-04-14 | Copyright line standardized to `Copyright (c) 2019-2026, Cutaway Security, LLC` | 2019 preserves PSv2 original authorship; 2026 marks the v2 rewrite. LLC matches Cutaway Security's current legal entity and the ICSWatchDog convention; PSv3/CMD's "Inc." is a stale copy-paste. |
| 2026-04-14 | Per-file headers shrink to a 3-line block citing LICENSE + NOTICE | Long inline GPL boilerplate in every file is noise; concentrating the license text in LICENSE and the dual-license terms in NOTICE keeps script headers focused on author/date/purpose and matches the ICSWatchDog cross-project convention. |
| 2026-04-14 | Add `.gitattributes` export-ignore + `release.sh` automation; defer website | Adopt the ICSWatchDog release safety net (defensive strip on `git archive`) and the preflight script (Steps 1-5 automated, force-push manual). Skip Jekyll/CNAME/deploy-site -- no website is in scope for CHAPS. |

## Out of Scope

- Remediation scripts or configuration changes
- Network-based or remote scanning capabilities
- GUI or interactive interface
- Integration with specific SIEM or GRC platforms
- Automated scoring or compliance percentage calculations
- Support for non-Windows operating systems
- Windows version gating within scripts (admins choose the right script)
